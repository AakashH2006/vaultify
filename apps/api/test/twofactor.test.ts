/**
 * Two-factor authentication, end to end against the real routes.
 *
 * The property these tests exist to protect is subtle and easy to break with
 * a well-meaning refactor: **2FA must not become an account-enumeration or
 * account-fingerprinting oracle.** Nothing reachable without the master
 * password may differ between an account with 2FA, an account without it, and
 * an account that does not exist. Several tests below assert exactly that,
 * and they matter more than the happy path.
 */

import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";

import { generateRecoveryCodes, stepFor, totp } from "../../../packages/totp/src/index.ts";

import {
  makeUser,
  register,
  registrationBody,
  startApi,
  TEST_KDF,
  type TestApi,
  type TestUser,
} from "./harness.ts";

let api: TestApi;

beforeEach(async () => {
  api = await startApi();
});

afterEach(async () => {
  await api.close();
});

/**
 * The code for the *next* step.
 *
 * Needed because every code this system accepts is spent on use, enrolment
 * included -- so the code that switched 2FA on cannot also buy a session 10
 * seconds later. That is the replay protection working, not a quirk of the
 * tests, and the client tells the user to wait for the next code.
 */
function nextCode(secret: string): Promise<string> {
  return totp(secret, { now: Date.now() + 30_000 });
}

/** Walks the full enrolment: setup, read the secret, confirm with a real code. */
async function enable2fa(token: string): Promise<{ secret: string; recoveryCodes: string[] }> {
  const setup = await api.post("/api/auth/2fa/setup", {}, token);
  assert.equal(setup.status, 200, JSON.stringify(setup.body));

  const secret = setup.body.secret as string;
  const code = await totp(secret);

  const enabled = await api.post("/api/auth/2fa/enable", { code }, token);
  assert.equal(enabled.status, 200, JSON.stringify(enabled.body));

  return { secret, recoveryCodes: enabled.body.recoveryCodes };
}

function login(user: TestUser, extra: Record<string, unknown> = {}) {
  return api.post("/api/auth/login", {
    accountId: user.accountId,
    authKey: user.authKey,
    ...extra,
  });
}

describe("2FA enrolment", () => {
  it("hands back a secret and an otpauth URI, without switching anything on", async () => {
    const { token } = await register(api);

    const setup = await api.post("/api/auth/2fa/setup", {}, token);

    assert.equal(setup.status, 200);
    assert.match(setup.body.secret, /^[A-Z2-7]{32}$/);
    assert.match(setup.body.uri, /^otpauth:\/\/totp\//);
    assert.ok(setup.body.uri.includes(`secret=${setup.body.secret}`));

    // Crucially: still off. A user who closes the tab mid-setup is not locked
    // out of an account whose second factor they never configured.
    const status = await api.get("/api/auth/2fa", token);
    assert.equal(status.body.enabled, false);
  });

  it("refuses to enable without a correct code", async () => {
    const { token } = await register(api);
    await api.post("/api/auth/2fa/setup", {}, token);

    const response = await api.post("/api/auth/2fa/enable", { code: "000000" }, token);

    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, "totp_invalid");
    assert.equal((await api.get("/api/auth/2fa", token)).body.enabled, false);
  });

  it("refuses to enable before setup has run", async () => {
    const { token } = await register(api);

    const response = await api.post("/api/auth/2fa/enable", { code: "000000" }, token);

    assert.equal(response.status, 409);
    assert.equal(response.body.error.code, "totp_not_enrolled");
  });

  it("issues ten single-use recovery codes, exactly once", async () => {
    const { token } = await register(api);
    const { recoveryCodes } = await enable2fa(token);

    assert.equal(recoveryCodes.length, 10);
    assert.equal(new Set(recoveryCodes).size, 10);
    for (const code of recoveryCodes) assert.match(code, /^[A-Z2-7]{5}-[A-Z2-7]{5}$/);

    // The status endpoint reports the count but never the codes themselves --
    // the server only has hashes.
    const status = await api.get("/api/auth/2fa", token);
    assert.deepEqual(status.body, { enabled: true, recoveryCodesRemaining: 10 });
    assert.ok(!JSON.stringify(status.body).includes(recoveryCodes[0]));
  });

  it("stores only scrypt hashes of the recovery codes", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    const { recoveryCodes } = await enable2fa(token);

    const hashes = await api.store.listRecoveryCodeHashes(user.accountId);
    assert.equal(hashes.length, 10);

    for (const { hash } of hashes) {
      assert.match(hash, /^scrypt\$/, "a recovery code is not stored as a slow hash");
      for (const code of recoveryCodes) {
        assert.ok(
          !hash.includes(code.replace("-", "")),
          "a recovery code is readable in the stored row",
        );
      }
    }
  });

  it("stores the TOTP secret, and is honest that it does", async () => {
    // Not a defect -- the server enforces the second factor, so it must be
    // able to generate codes. The point of the test is that this is the ONLY
    // usable secret it holds, and it is nowhere near the vault key.
    const user = await makeUser();
    const { token } = await register(api, user);
    const { secret } = await enable2fa(token);

    const account = await api.store.findAccount(user.accountId);
    assert.equal(account?.totpSecret, secret);
    assert.equal(account?.totpEnabled, true);

    // The master password and anything derived from it are still absent.
    assert.ok(!JSON.stringify(account).includes(user.masterPassword));
  });

  it("refuses a second enrolment while 2FA is already on", async () => {
    const { token } = await register(api);
    await enable2fa(token);

    const setup = await api.post("/api/auth/2fa/setup", {}, token);
    assert.equal(setup.status, 409);
  });

  it("needs authentication", async () => {
    assert.equal((await api.post("/api/auth/2fa/setup", {})).status, 401);
    assert.equal((await api.post("/api/auth/2fa/enable", { code: "123456" })).status, 401);
    assert.equal((await api.get("/api/auth/2fa")).status, 401);
  });
});

describe("login with 2FA on", () => {
  it("asks for a code once the auth key checks out", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    await enable2fa(token);

    const response = await login(user);

    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, "totp_required");
    assert.equal(response.body.accessToken, undefined);
  });

  it("succeeds with a valid code", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    const { secret } = await enable2fa(token);

    const response = await login(user, { totpCode: await nextCode(secret) });

    assert.equal(response.status, 200);
    assert.ok(response.body.accessToken);
    assert.equal(response.body.twoFactor.enabled, true);
    assert.equal(response.body.keyRecord.protectedVaultKey, user.protectedVaultKey);
  });

  it("rejects a wrong code without issuing a session", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    await enable2fa(token);

    const response = await login(user, { totpCode: "000000" });

    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, "totp_invalid");
    assert.equal(response.body.accessToken, undefined);
  });

  it("refuses to replay a code that already bought a session", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    const { secret } = await enable2fa(token);

    const code = await nextCode(secret);
    assert.equal((await login(user, { totpCode: code })).status, 200);

    // The code is still arithmetically valid for up to another 90 seconds.
    // Someone who watched it being typed must not be able to use it.
    const replay = await login(user, { totpCode: code });
    assert.equal(replay.status, 401);
    assert.equal(replay.body.error.code, "totp_invalid");
  });

  it("does not let a code from a different account's secret through", async () => {
    const victim = await makeUser();
    const { token: victimToken } = await register(api, victim);
    await enable2fa(victimToken);

    const attacker = await register(api);
    const { secret: attackerSecret } = await enable2fa(attacker.token);

    const response = await login(victim, { totpCode: await nextCode(attackerSecret) });
    assert.equal(response.status, 401);
  });

  it("still rejects a wrong master password, code or no code", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    const { secret } = await enable2fa(token);

    const wrong = await makeUser();
    const response = await api.post("/api/auth/login", {
      accountId: user.accountId,
      authKey: wrong.authKey,
      totpCode: await nextCode(secret),
    });

    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, "invalid_credentials");
  });
});

describe("recovery codes", () => {
  it("get the user in when the phone is gone", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    const { recoveryCodes } = await enable2fa(token);

    const response = await login(user, { recoveryCode: recoveryCodes[0] });

    assert.equal(response.status, 200);
    assert.ok(response.body.accessToken);
  });

  it("are single use", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    const { recoveryCodes } = await enable2fa(token);

    assert.equal((await login(user, { recoveryCode: recoveryCodes[0] })).status, 200);

    const replay = await login(user, { recoveryCode: recoveryCodes[0] });
    assert.equal(replay.status, 401);
    assert.equal(replay.body.error.code, "totp_invalid");
  });

  it("decrement the remaining count", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    const { recoveryCodes } = await enable2fa(token);

    const second = await login(user, { recoveryCode: recoveryCodes[0] });
    const status = await api.get("/api/auth/2fa", second.body.accessToken);

    assert.equal(status.body.recoveryCodesRemaining, 9);
  });

  it("accept the separators and casing a user actually types", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    const { recoveryCodes } = await enable2fa(token);

    const typed = recoveryCodes[0].toLowerCase().replace("-", " ");
    assert.equal((await login(user, { recoveryCode: typed })).status, 200);
  });

  it("reject a code that was never issued", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    await enable2fa(token);

    const response = await login(user, { recoveryCode: generateRecoveryCodes(1)[0] });
    assert.equal(response.status, 401);
  });

  it("are all revoked when 2FA is turned off", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    const { secret, recoveryCodes } = await enable2fa(token);

    const disabled = await api.post(
      "/api/auth/2fa/disable",
      { authKey: user.authKey, code: await nextCode(secret) },
      token,
    );
    assert.equal(disabled.status, 204, JSON.stringify(disabled.body));

    // 2FA is off, so login needs no second factor at all -- and the old codes
    // must not linger in the database waiting for 2FA to be switched back on.
    assert.equal((await login(user)).status, 200);

    const again = await enable2fa((await login(user)).body.accessToken);
    assert.equal(
      again.recoveryCodes.some((code) => recoveryCodes.includes(code)),
      false,
      "a code from the previous enrolment survived",
    );
  });
});

describe("turning 2FA off", () => {
  it("requires the auth key as well as a live session", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    const { secret } = await enable2fa(token);

    const wrong = await makeUser();
    const response = await api.post(
      "/api/auth/2fa/disable",
      { authKey: wrong.authKey, code: await nextCode(secret) },
      token,
    );

    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, "invalid_credentials");
    assert.equal((await api.get("/api/auth/2fa", token)).body.enabled, true);
  });

  it("requires a current code as well as the auth key", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    await enable2fa(token);

    const response = await api.post(
      "/api/auth/2fa/disable",
      { authKey: user.authKey, code: "000000" },
      token,
    );

    assert.equal(response.status, 401);
    assert.equal((await api.get("/api/auth/2fa", token)).body.enabled, true);
  });

  it("is a 409 when 2FA was never on", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);

    const response = await api.post(
      "/api/auth/2fa/disable",
      { authKey: user.authKey, code: "000000" },
      token,
    );

    assert.equal(response.status, 409);
    assert.equal(response.body.error.code, "totp_not_enrolled");
  });
});

describe("2FA must not leak who has it", () => {
  it("prelogin answers identically for 2FA, no 2FA, and no such account", async () => {
    const withTwoFactor = await makeUser();
    const { token } = await register(api, withTwoFactor);
    await enable2fa(token);

    const without = await makeUser();
    await register(api, without);

    const responses = await Promise.all([
      api.post("/api/auth/prelogin", { accountId: withTwoFactor.accountId }),
      api.post("/api/auth/prelogin", { accountId: without.accountId }),
      api.post("/api/auth/prelogin", { accountId: "nobody@example.com" }),
    ]);

    for (const response of responses) {
      assert.equal(response.status, 200);
      assert.deepEqual(Object.keys(response.body), ["kdf"]);
    }
    assert.deepEqual(responses[0].body.kdf, TEST_KDF);
    assert.deepEqual(responses[1].body.kdf, TEST_KDF);
  });

  it("a wrong password gives the same answer with or without 2FA", async () => {
    const withTwoFactor = await makeUser();
    const { token } = await register(api, withTwoFactor);
    await enable2fa(token);

    const without = await makeUser();
    await register(api, without);

    const wrong = await makeUser();
    const [a, b, c] = await Promise.all([
      api.post("/api/auth/login", { accountId: withTwoFactor.accountId, authKey: wrong.authKey }),
      api.post("/api/auth/login", { accountId: without.accountId, authKey: wrong.authKey }),
      api.post("/api/auth/login", { accountId: "nobody@example.com", authKey: wrong.authKey }),
    ]);

    assert.equal(a.status, 401);
    assert.deepEqual(a.body, b.body);
    assert.deepEqual(b.body, c.body);
    assert.equal(a.body.error.code, "invalid_credentials");
  });

  it("registration reports 2FA as off rather than omitting the field", async () => {
    const user = await makeUser();
    const response = await api.post("/api/auth/register", registrationBody(user));
    assert.deepEqual(response.body.twoFactor, { enabled: false, recoveryCodesRemaining: 0 });
  });
});

describe("the TOTP step marker", () => {
  it("advances to the step that was spent", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    const { secret } = await enable2fa(token);

    await login(user, { totpCode: await nextCode(secret) });

    const account = await api.store.findAccount(user.accountId);
    assert.equal(account?.totpLastStep, stepFor(Date.now()) + 1);
  });
});
