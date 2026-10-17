/**
 * An in-memory stand-in for the Vaultify API, wired in as a `fetch`
 * implementation so the tests drive the *real* `ApiClient` -- its headers, its
 * status-code handling and its error mapping -- rather than a mock of it.
 *
 * It implements the contract in `docs/api.md` as literally as a test double
 * can: the same status codes, the same error bodies, and crucially the same
 * compare-and-set on `vault_revision`, because that is the behaviour the
 * client's conflict handling is written against.
 *
 * What it does not do is hash the auth key or sign a real JWT. Those are the
 * server's responsibility and `apps/api` has its own tests for them; repeating
 * them here would test the double instead of the client.
 */

import type { KdfParams } from "@vaultify/crypto";

export interface StoredAccount {
  accountId: string;
  authKey: string;
  kdf: KdfParams;
  protectedVaultKey: string;
  vault: string | null;
  vaultRevision: number;
  vaultUpdatedAt: string | null;
}

export interface FakeServerOptions {
  /** Force the next N vault writes to lose the race, as if another device had
   *  written first. Used to drive the conflict path deterministically. */
  tokenTtlSeconds?: number;
}

const DEFAULT_KDF: KdfParams = { algorithm: "PBKDF2", iterations: 600_000 };

export class FakeServer {
  readonly accounts = new Map<string, StoredAccount>();
  readonly sessions = new Map<string, string>();
  /** Every request the client made, for assertions about what crossed the wire. */
  readonly requests: Array<{ method: string; path: string; body: unknown }> = [];
  /** Set to run a callback immediately before a PUT /api/vault is applied --
   *  the hook a test uses to simulate another device writing first. */
  beforeVaultWrite: (() => void | Promise<void>) | null = null;

  #tokenTtl: number;
  #nextSession = 1;

  constructor(options: FakeServerOptions = {}) {
    this.#tokenTtl = options.tokenTtlSeconds ?? 900;
  }

  /** Simulate another device writing a vault, bumping the revision. */
  writeAsOtherDevice(accountId: string, ciphertext: string): number {
    const account = this.#require(accountId);
    account.vault = ciphertext;
    account.vaultRevision += 1;
    account.vaultUpdatedAt = new Date().toISOString();
    return account.vaultRevision;
  }

  currentVault(accountId: string): string | null {
    return this.#require(accountId).vault;
  }

  revision(accountId: string): number {
    return this.#require(accountId).vaultRevision;
  }

  #require(accountId: string): StoredAccount {
    const account = this.accounts.get(accountId);
    if (!account) throw new Error(`No such account in the fake server: ${accountId}`);
    return account;
  }

  /** Drop-in replacement for `fetch`. */
  fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input.toString());
    const path = url.pathname;
    const method = init?.method ?? "GET";
    const body = init?.body ? JSON.parse(String(init.body)) : undefined;
    this.requests.push({ method, path, body });

    const token = (init?.headers as Record<string, string> | undefined)?.["Authorization"]
      ?.replace(/^Bearer /, "");

    switch (`${method} ${path}`) {
      case "POST /api/auth/register":
        return this.#register(body);
      case "POST /api/auth/prelogin":
        return this.#prelogin(body);
      case "POST /api/auth/login":
        return this.#login(body);
      case "POST /api/auth/logout":
        return this.#logout(token);
      case "POST /api/auth/change-password":
        return this.#changePassword(token, body);
      case "GET /api/vault":
        return this.#getVault(token);
      case "PUT /api/vault":
        return this.#putVault(token, body);
      default:
        return fail(404, "not_found", "Not found");
    }
  };

  // -------------------------------------------------------------------------

  #register(body: {
    accountId: string;
    authKey: string;
    kdf: KdfParams;
    protectedVaultKey: string;
  }): Response {
    const accountId = body.accountId.trim().toLowerCase();
    if (this.accounts.has(accountId)) {
      return fail(409, "account_exists", "That email is already registered.");
    }
    this.accounts.set(accountId, {
      accountId,
      authKey: body.authKey,
      kdf: body.kdf,
      protectedVaultKey: body.protectedVaultKey,
      vault: null,
      vaultRevision: 0,
      vaultUpdatedAt: null,
    });
    return ok(201, { ...this.#sessionFor(accountId), vault: null, vaultRevision: 0 });
  }

  #prelogin(body: { accountId: string }): Response {
    // Defaults for an unknown account -- the anti-enumeration behaviour the
    // real API has, reproduced so the client cannot accidentally depend on a
    // 404 that will never come.
    const account = this.accounts.get(body.accountId.trim().toLowerCase());
    return ok(200, { kdf: account?.kdf ?? DEFAULT_KDF });
  }

  #login(body: { accountId: string; authKey: string }): Response {
    const account = this.accounts.get(body.accountId.trim().toLowerCase());
    if (!account || account.authKey !== body.authKey) {
      return fail(401, "invalid_credentials", "Invalid credentials");
    }
    return ok(200, { ...this.#sessionFor(account.accountId), vaultRevision: account.vaultRevision });
  }

  #logout(token: string | undefined): Response {
    if (!token || !this.sessions.has(token)) return fail(401, "unauthorized", "Unauthorized");
    this.sessions.delete(token);
    return new Response(null, { status: 204 });
  }

  #changePassword(
    token: string | undefined,
    body: {
      currentAuthKey: string;
      newAuthKey: string;
      kdf: KdfParams;
      protectedVaultKey: string;
    },
  ): Response {
    const accountId = token ? this.sessions.get(token) : undefined;
    if (!accountId) return fail(401, "unauthorized", "Unauthorized");

    const account = this.#require(accountId);
    if (account.authKey !== body.currentAuthKey) {
      return fail(401, "invalid_credentials", "Invalid credentials");
    }

    account.authKey = body.newAuthKey;
    account.kdf = body.kdf;
    account.protectedVaultKey = body.protectedVaultKey;
    // Every session dies, including the caller's.
    for (const [existing, owner] of this.sessions) {
      if (owner === accountId) this.sessions.delete(existing);
    }
    return new Response(null, { status: 204 });
  }

  #getVault(token: string | undefined): Response {
    const accountId = token ? this.sessions.get(token) : undefined;
    if (!accountId) return fail(401, "unauthorized", "Unauthorized");

    const account = this.#require(accountId);
    return ok(200, {
      vault: account.vault,
      vaultRevision: account.vaultRevision,
      vaultUpdatedAt: account.vaultUpdatedAt,
      keyRecord: keyRecordOf(account),
    });
  }

  async #putVault(
    token: string | undefined,
    body: { vault: string; expectedRevision: number },
  ): Promise<Response> {
    const accountId = token ? this.sessions.get(token) : undefined;
    if (!accountId) return fail(401, "unauthorized", "Unauthorized");

    await this.beforeVaultWrite?.();

    const account = this.#require(accountId);
    if (account.vaultRevision !== body.expectedRevision) {
      return new Response(
        JSON.stringify({
          error: {
            code: "conflict",
            message: "The vault changed since you last loaded it.",
          },
          currentRevision: account.vaultRevision,
        }),
        { status: 409, headers: { "Content-Type": "application/json" } },
      );
    }

    account.vault = body.vault;
    account.vaultRevision += 1;
    account.vaultUpdatedAt = new Date().toISOString();
    return ok(200, {
      vaultRevision: account.vaultRevision,
      vaultUpdatedAt: account.vaultUpdatedAt,
    });
  }

  #sessionFor(accountId: string): {
    accountId: string;
    accessToken: string;
    tokenType: string;
    expiresIn: number;
    keyRecord: ReturnType<typeof keyRecordOf>;
  } {
    const accessToken = `token-${this.#nextSession++}`;
    this.sessions.set(accessToken, accountId);
    return {
      accountId,
      accessToken,
      tokenType: "Bearer",
      expiresIn: this.#tokenTtl,
      keyRecord: keyRecordOf(this.#require(accountId)),
    };
  }
}

function keyRecordOf(account: StoredAccount): {
  accountId: string;
  kdf: KdfParams;
  protectedVaultKey: string;
} {
  return {
    accountId: account.accountId,
    kdf: account.kdf,
    protectedVaultKey: account.protectedVaultKey,
  };
}

function ok(status: number, payload: unknown): Response {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function fail(status: number, code: string, message: string): Response {
  return new Response(JSON.stringify({ error: { code, message } }), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
