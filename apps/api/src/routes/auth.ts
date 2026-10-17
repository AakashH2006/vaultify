/**
 * The auth-key login flow, plus the second factor and the audit log.
 *
 * What the server is doing here, in one line: checking that whoever is calling
 * can produce a value derived from the master password, and handing back the
 * wrapped vault key if so. At no point does it hold anything that could open a
 * vault -- not during registration, not during login, not during a password
 * change, and not when enforcing 2FA.
 *
 * On the ordering of checks in `/login`, which is the part worth reading
 * carefully: the auth key is verified **before** 2FA is even mentioned. A
 * caller who does not know the master password gets exactly the same
 * `invalid_credentials` they always did, and learns nothing about whether the
 * account exists or whether it has a second factor configured. `totp_required`
 * is only reachable by someone who already passed the first factor.
 */

import { Router, type Request } from "express";
import {
  generateRecoveryCodes,
  generateSecret,
  normaliseRecoveryCode,
  otpauthUri,
  verifyTotp,
} from "@vaultify/totp";

import { ApiError } from "../errors.ts";
import type { Config } from "../config.ts";
import type { AccountRecord, Store } from "../store/types.ts";
import type { TokenService } from "../auth/tokens.ts";
import { fakeVerify, hashAuthKey, verifyAuthKey } from "../auth/authKeyHash.ts";
import { audit } from "../auth/audit.ts";
import { isLockedOut, lockoutUntil, secondsRemaining } from "../auth/lockout.ts";
import { authenticate, requireAuth, type AuthenticatedRequest } from "../middleware/authenticate.ts";
import { ipAndAccount, rateLimit } from "../middleware/rateLimit.ts";
import {
  changePasswordBody,
  loginBody,
  parseBody,
  preloginBody,
  registerBody,
  totpDisableBody,
  totpEnableBody,
} from "../validation.ts";

/** KDF parameters handed to clients asking about an account that does not
 *  exist. Must match what registration would choose, or prelogin becomes an
 *  account-enumeration oracle. */
const DEFAULT_KDF = { algorithm: "PBKDF2", iterations: 600_000 } as const;

/** How many audit rows the activity view returns. */
const ACTIVITY_LIMIT = 50;

export interface AuthDeps {
  store: Store;
  tokens: TokenService;
  config: Config;
}

export function authRoutes({ store, tokens }: AuthDeps): Router {
  const router = Router();

  const credentialLimit = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    keyBy: ipAndAccount,
  });

  const registrationLimit = rateLimit({ windowMs: 60 * 60 * 1000, max: 5 });

  // Keyed on the authenticated account rather than the body, which carries no
  // accountId here. Runs after `authenticate`, so `req.auth` is populated.
  const byAccount = (max: number) =>
    rateLimit({
      windowMs: 15 * 60 * 1000,
      max,
      keyBy: (req) => (req as AuthenticatedRequest).auth?.accountId ?? req.ip ?? "unknown",
    });

  // -------------------------------------------------------------------------
  // POST /api/auth/register
  // -------------------------------------------------------------------------
  router.post("/register", registrationLimit, async (req, res) => {
    const body = parseBody(registerBody, req);

    const account = await store.createAccount({
      accountId: body.accountId,
      authKeyHash: await hashAuthKey(body.authKey),
      kdf: body.kdf,
      protectedVaultKey: body.protectedVaultKey,
    });

    if (!account) {
      // Registration genuinely cannot hide that an address is taken -- the
      // alternative is letting someone overwrite an existing account. The
      // mitigation is the rate limit above, not a vague error.
      throw new ApiError(409, "account_exists", "An account with that email already exists.");
    }

    audit(store, req, account.accountId, "register", true);

    const token = await tokens.issue(account.accountId);
    await store.createSession({
      sessionId: token.sessionId,
      accountId: account.accountId,
      expiresAt: token.expiresAt,
    });

    res.status(201).json({
      accountId: account.accountId,
      ...tokenResponse(token),
      keyRecord: keyRecordOf(account),
      vault: null,
      vaultRevision: 0,
      twoFactor: { enabled: false, recoveryCodesRemaining: 0 },
    });
  });

  // -------------------------------------------------------------------------
  // POST /api/auth/prelogin
  //
  // The client needs the account's KDF parameters before it can derive an auth
  // key, and it has no session yet. Unknown accounts get the defaults rather
  // than a 404, so this cannot be used to test which emails are registered.
  //
  // Note what is deliberately NOT here: whether the account has 2FA. That
  // would turn this into an oracle for "which accounts are worth attacking",
  // and would leak it to anyone who can guess an email address.
  // -------------------------------------------------------------------------
  router.post("/prelogin", credentialLimit, async (req, res) => {
    const body = parseBody(preloginBody, req);
    const account = await store.findAccount(body.accountId);
    res.json({ kdf: account?.kdf ?? DEFAULT_KDF });
  });

  // -------------------------------------------------------------------------
  // POST /api/auth/login
  // -------------------------------------------------------------------------
  router.post("/login", credentialLimit, async (req, res) => {
    const body = parseBody(loginBody, req);
    const account = await store.findAccount(body.accountId);

    // A locked account still spends the scrypt work before answering, so the
    // lockout itself does not become a fast "this account exists" signal.
    if (account && isLockedOut(account)) {
      await fakeVerify();
      audit(store, req, account.accountId, "login.locked_out", false);
      throw ApiError.locked(secondsRemaining(account.lockedUntil));
    }

    // Spend the same scrypt work whether or not the account exists, so the
    // response time does not distinguish the two.
    const ok = account ? await verifyAuthKey(body.authKey, account.authKeyHash) : await fakeVerify();

    if (!ok || !account) {
      if (account) await registerFailure(account);
      throw ApiError.invalidCredentials();
    }

    // --- first factor passed; only now does 2FA enter the picture ----------
    if (account.totpEnabled) {
      const passed = await checkSecondFactor(account, body, req);
      if (!passed) {
        await registerFailure(account);
        // Distinguishing "no code sent" from "wrong code" is safe here and
        // genuinely useful: the caller already proved they know the master
        // password, so there is nothing left to leak, and the client needs to
        // know whether to show the code field or an error on it.
        if (!body.totpCode && !body.recoveryCode) {
          audit(store, req, account.accountId, "login.totp_failed", false);
          throw new ApiError(401, "totp_required", "Enter the code from your authenticator app.");
        }
        audit(store, req, account.accountId, "login.totp_failed", false);
        throw new ApiError(401, "totp_invalid", "That code is not valid. Try the next one.");
      }
    }

    await store.clearFailedAttempts(account.accountId);
    audit(store, req, account.accountId, "login", true);

    const token = await tokens.issue(account.accountId);
    await store.createSession({
      sessionId: token.sessionId,
      accountId: account.accountId,
      expiresAt: token.expiresAt,
    });

    res.json({
      accountId: account.accountId,
      ...tokenResponse(token),
      // The client needs this to unwrap its vault key. It is useless without
      // the master password.
      keyRecord: keyRecordOf(account),
      vaultRevision: account.vaultRevision,
      twoFactor: await twoFactorStatus(account),
    });
  });

  // -------------------------------------------------------------------------
  // POST /api/auth/logout
  // -------------------------------------------------------------------------
  router.post("/logout", authenticate(tokens, store), async (req: AuthenticatedRequest, res) => {
    const { sessionId, accountId } = requireAuth(req);
    await store.revokeSession(sessionId);
    audit(store, req, accountId, "logout", true);
    res.status(204).end();
  });

  // -------------------------------------------------------------------------
  // POST /api/auth/2fa/setup
  //
  // Mints a secret and hands back the otpauth URI. Nothing is switched on:
  // 2FA is only enabled once the user proves, in `/2fa/enable`, that their
  // authenticator actually holds the secret. Enabling on the strength of
  // "the user saw a QR code" is how people lock themselves out.
  // -------------------------------------------------------------------------
  router.post(
    "/2fa/setup",
    authenticate(tokens, store),
    byAccount(10),
    async (req: AuthenticatedRequest, res) => {
      const { accountId } = requireAuth(req);
      const account = await store.findAccount(accountId);
      if (!account) throw ApiError.unauthorized();

      if (account.totpEnabled) {
        throw ApiError.conflict(
          "Two-factor authentication is already on. Turn it off before enrolling again.",
        );
      }

      const secret = generateSecret();
      await store.startTotpEnrolment(accountId, secret);

      res.json({
        secret,
        uri: otpauthUri({ secret, account: accountId, issuer: "Vaultify" }),
      });
    },
  );

  // -------------------------------------------------------------------------
  // POST /api/auth/2fa/enable
  // -------------------------------------------------------------------------
  router.post(
    "/2fa/enable",
    authenticate(tokens, store),
    byAccount(10),
    async (req: AuthenticatedRequest, res) => {
      const { accountId } = requireAuth(req);
      const body = parseBody(totpEnableBody, req);

      const account = await store.findAccount(accountId);
      if (!account) throw ApiError.unauthorized();
      if (account.totpEnabled) {
        throw ApiError.conflict("Two-factor authentication is already on.");
      }
      if (!account.totpSecret) {
        throw new ApiError(
          409,
          "totp_not_enrolled",
          "Start setup first — there is no pending secret for this account.",
        );
      }

      const result = await verifyTotp(account.totpSecret, body.code, {
        lastUsedStep: account.totpLastStep,
      });
      if (!result.ok) {
        throw new ApiError(
          401,
          "totp_invalid",
          "That code is not valid. Check your phone's clock, then try the next one.",
        );
      }

      // Recovery codes are generated here and returned exactly once. The
      // server keeps only scrypt hashes, so this response is the single
      // opportunity the user has to save them.
      const codes = generateRecoveryCodes();
      const recoveryCodeHashes = await Promise.all(
        codes.map((code) => hashAuthKey(normaliseRecoveryCode(code))),
      );

      const enabled = await store.enableTotp(accountId, {
        secret: account.totpSecret,
        recoveryCodeHashes,
      });
      if (!enabled) throw ApiError.unauthorized();

      if (result.step !== null) await store.recordTotpStep(accountId, result.step);
      audit(store, req, accountId, "totp_enabled", true);

      res.json({ enabled: true, recoveryCodes: codes });
    },
  );

  // -------------------------------------------------------------------------
  // POST /api/auth/2fa/disable
  //
  // Requires the auth key *and* a current code. Removing a second factor is
  // exactly what an attacker holding a stolen session token would want to do
  // first, so a live session alone is not enough.
  // -------------------------------------------------------------------------
  router.post(
    "/2fa/disable",
    authenticate(tokens, store),
    byAccount(5),
    async (req: AuthenticatedRequest, res) => {
      const { accountId } = requireAuth(req);
      const body = parseBody(totpDisableBody, req);

      const account = await store.findAccount(accountId);
      if (!account) throw ApiError.unauthorized();
      if (!account.totpEnabled || !account.totpSecret) {
        throw new ApiError(409, "totp_not_enrolled", "Two-factor authentication is not on.");
      }

      if (!(await verifyAuthKey(body.authKey, account.authKeyHash))) {
        throw ApiError.invalidCredentials();
      }

      const result = await verifyTotp(account.totpSecret, body.code, {
        lastUsedStep: account.totpLastStep,
      });
      if (!result.ok) {
        throw new ApiError(401, "totp_invalid", "That code is not valid.");
      }

      await store.disableTotp(accountId);
      audit(store, req, accountId, "totp_disabled", true);

      res.status(204).end();
    },
  );

  // -------------------------------------------------------------------------
  // GET /api/auth/activity
  //
  // The audit log, for the account reading it. Both the IP prefix and the
  // client label are deliberately coarse -- see auth/audit.ts.
  // -------------------------------------------------------------------------
  router.get("/activity", authenticate(tokens, store), async (req: AuthenticatedRequest, res) => {
    const { accountId } = requireAuth(req);
    const events = await store.listAuditEvents(accountId, ACTIVITY_LIMIT);
    res.json({ events });
  });

  // -------------------------------------------------------------------------
  // GET /api/auth/2fa
  // -------------------------------------------------------------------------
  router.get("/2fa", authenticate(tokens, store), async (req: AuthenticatedRequest, res) => {
    const { accountId } = requireAuth(req);
    const account = await store.findAccount(accountId);
    if (!account) throw ApiError.unauthorized();
    res.json(await twoFactorStatus(account));
  });

  // -------------------------------------------------------------------------
  // POST /api/auth/change-password
  //
  // The vault ciphertext is deliberately untouched: the client rewraps the
  // vault key and sends only that. See docs/architecture.md section 2.
  // -------------------------------------------------------------------------
  router.post(
    "/change-password",
    authenticate(tokens, store),
    byAccount(5),
    async (req: AuthenticatedRequest, res) => {
      const { accountId } = requireAuth(req);
      const body = parseBody(changePasswordBody, req);

      const account = await store.findAccount(accountId);
      if (!account) throw ApiError.unauthorized();

      // A live session is not enough to change the password -- a borrowed
      // token must not be upgradeable into account takeover.
      if (!(await verifyAuthKey(body.currentAuthKey, account.authKeyHash))) {
        throw ApiError.invalidCredentials();
      }

      const rotated = await store.rotateCredentials(accountId, {
        authKeyHash: await hashAuthKey(body.newAuthKey),
        kdf: body.kdf,
        protectedVaultKey: body.protectedVaultKey,
      });
      if (!rotated) throw ApiError.unauthorized();

      audit(store, req, accountId, "password_changed", true);

      // Every device, including this one, re-authenticates with the new
      // password. If the change was prompted by a suspected compromise, leaving
      // old sessions alive would defeat the point.
      await store.revokeAllSessions(accountId);

      res.status(204).end();
    },
  );

  return router;

  // -------------------------------------------------------------------------
  // Helpers
  // -------------------------------------------------------------------------

  /**
   * Check a TOTP code or a recovery code. Returns whether the second factor
   * was satisfied; the caller handles the failure bookkeeping.
   */
  async function checkSecondFactor(
    account: AccountRecord,
    body: { totpCode?: string; recoveryCode?: string },
    req: Request,
  ): Promise<boolean> {
    if (body.totpCode && account.totpSecret) {
      const result = await verifyTotp(account.totpSecret, body.totpCode, {
        lastUsedStep: account.totpLastStep,
      });
      if (result.ok && result.step !== null) {
        // Record the spent step before issuing the session, so a code cannot
        // be replayed inside the 90 seconds it stays arithmetically valid.
        await store.recordTotpStep(account.accountId, result.step);
        return true;
      }
      return false;
    }

    if (body.recoveryCode) {
      const candidate = normaliseRecoveryCode(body.recoveryCode);
      const stored = await store.listRecoveryCodeHashes(account.accountId);

      for (const { id, hash } of stored) {
        if (!(await verifyAuthKey(candidate, hash))) continue;
        // consume() is the compare-and-set: if another request spent this code
        // first, we lose and the login fails rather than both succeeding.
        if (!(await store.consumeRecoveryCode(account.accountId, id))) return false;
        audit(store, req, account.accountId, "recovery_code_used", true);
        return true;
      }
      return false;
    }

    return false;
  }

  /**
   * Bump the failure counter and apply the progressive backoff, in one write.
   *
   * The deadline is computed from the count we are about to reach rather than
   * from the count the store reports back, so this stays a single statement.
   * Two failures racing can therefore agree on the same deadline instead of
   * one overwriting the other's -- and the counter itself still increments
   * atomically, so the backoff keeps lengthening correctly either way.
   */
  async function registerFailure(account: AccountRecord): Promise<void> {
    await store.recordFailedAttempt(account.accountId, lockoutUntil(account.failedAttempts + 1));
  }

  async function twoFactorStatus(account: AccountRecord) {
    if (!account.totpEnabled) {
      return { enabled: false, recoveryCodesRemaining: 0 };
    }
    const codes = await store.listRecoveryCodeHashes(account.accountId);
    return { enabled: true, recoveryCodesRemaining: codes.length };
  }

  function tokenResponse(token: { accessToken: string; expiresInSeconds: number }) {
    return {
      accessToken: token.accessToken,
      tokenType: "Bearer",
      expiresIn: token.expiresInSeconds,
    };
  }
}

/** The public half of an account: everything the client needs to derive and
 *  unwrap its keys, and nothing that helps anyone else. */
function keyRecordOf(account: {
  accountId: string;
  kdf: { algorithm: "PBKDF2"; iterations: number };
  protectedVaultKey: string;
}) {
  return {
    accountId: account.accountId,
    kdf: account.kdf,
    protectedVaultKey: account.protectedVaultKey,
  };
}
