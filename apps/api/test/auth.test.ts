import { test, describe, afterEach } from "node:test";
import assert from "node:assert/strict";

import {
  makeUser,
  register,
  registrationBody,
  sealVault,
  startApi,
  TEST_KDF,
  type TestApi,
} from "./harness.ts";
import {
  changeMasterPassword,
  deriveKeys,
  deserialize,
  serialize,
} from "../../../packages/crypto/src/index.ts";

let api: TestApi;
const boot = async (env?: Record<string, string>) => (api = await startApi(env));

afterEach(async () => {
  await api?.close();
});

describe("POST /api/auth/register", () => {
  test("creates an account and returns a usable session", async () => {
    await boot();
    const user = await makeUser();
    const response = await api.post("/api/auth/register", registrationBody(user));

    assert.equal(response.status, 201);
    assert.equal(response.body.accountId, user.accountId);
    assert.equal(response.body.tokenType, "Bearer");
    assert.ok(response.body.accessToken);
    assert.equal(response.body.vault, null);
    assert.equal(response.body.vaultRevision, 0);

    const vault = await api.get("/api/vault", response.body.accessToken);
    assert.equal(vault.status, 200);
  });

  test("stores a hash of the auth key, never the auth key", async () => {
    await boot();
    const { user } = await register(api);
    const stored = await api.store.findAccount(user.accountId);

    assert.ok(stored);
    assert.notEqual(stored.authKeyHash, user.authKey);
    assert.ok(stored.authKeyHash.startsWith("scrypt$"));
    assert.ok(!stored.authKeyHash.includes(user.authKey));
  });

  test("the server never sees the master password", async () => {
    await boot();
    const user = await makeUser("a very distinctive master password");
    const body = JSON.stringify(registrationBody(user));
    assert.ok(!body.includes("a very distinctive master password"));
  });

  test("rejects a duplicate account", async () => {
    await boot();
    const { user } = await register(api);
    const again = await api.post("/api/auth/register", registrationBody(user));
    assert.equal(again.status, 409);
    assert.equal(again.body.error.code, "account_exists");
  });

  test("normalises the email the same way the client salts it", async () => {
    await boot();
    const user = await makeUser();
    await api.post("/api/auth/register", {
      ...registrationBody(user),
      accountId: "  " + user.accountId.toUpperCase() + " ",
    });
    assert.ok(await api.store.findAccount(user.accountId));
  });

  test("rejects a weakened KDF", async () => {
    await boot();
    const user = await makeUser();
    const response = await api.post("/api/auth/register", {
      ...registrationBody(user),
      kdf: { algorithm: "PBKDF2", iterations: 1000 },
    });
    assert.equal(response.status, 400);
    assert.match(response.body.error.message, /iterations/);
  });

  test("rejects a malformed protected vault key", async () => {
    await boot();
    const user = await makeUser();
    for (const bad of ["", "not-an-envelope", "2.AES-256-GCM.AAAAAAAAAAAAAAAA.AAAA"]) {
      const response = await api.post("/api/auth/register", {
        ...registrationBody(user),
        protectedVaultKey: bad,
      });
      assert.equal(response.status, 400, "accepted " + JSON.stringify(bad));
    }
  });

  test("rejects unknown fields", async () => {
    await boot();
    const user = await makeUser();
    const response = await api.post("/api/auth/register", {
      ...registrationBody(user),
      isAdmin: true,
    });
    assert.equal(response.status, 400);
  });
});

describe("POST /api/auth/prelogin", () => {
  test("returns the account's KDF parameters", async () => {
    await boot();
    const { user } = await register(api);
    const response = await api.post("/api/auth/prelogin", { accountId: user.accountId });
    assert.equal(response.status, 200);
    assert.deepEqual(response.body.kdf, TEST_KDF);
  });

  test("does not reveal whether an account exists", async () => {
    await boot();
    const known = await register(api);
    const unknown = await api.post("/api/auth/prelogin", { accountId: "nobody@example.com" });
    const existing = await api.post("/api/auth/prelogin", { accountId: known.user.accountId });

    assert.equal(unknown.status, existing.status);
    assert.deepEqual(Object.keys(unknown.body), Object.keys(existing.body));
    assert.equal(unknown.body.kdf.algorithm, "PBKDF2");
  });
});

describe("POST /api/auth/login", () => {
  test("accepts the correct auth key and returns the key record", async () => {
    await boot();
    const { user } = await register(api);

    const response = await api.post("/api/auth/login", {
      accountId: user.accountId,
      authKey: user.authKey,
    });

    assert.equal(response.status, 200);
    assert.ok(response.body.accessToken);
    assert.equal(response.body.keyRecord.protectedVaultKey, user.protectedVaultKey);
    assert.deepEqual(response.body.keyRecord.kdf, TEST_KDF);
  });

  test("the auth key derived from the master password is what unlocks login", async () => {
    // End-to-end over the real client library: derive, register, re-derive on a
    // "second device", log in. Nothing but the password crosses between them.
    await boot();
    const { user } = await register(api);

    const secondDevice = await deriveKeys(user.accountId, user.masterPassword, TEST_KDF);
    const response = await api.post("/api/auth/login", {
      accountId: user.accountId,
      authKey: secondDevice.authKey,
    });
    assert.equal(response.status, 200);
  });

  test("rejects the wrong master password", async () => {
    await boot();
    const { user } = await register(api);
    const wrong = await deriveKeys(user.accountId, "not the password", TEST_KDF);

    const response = await api.post("/api/auth/login", {
      accountId: user.accountId,
      authKey: wrong.authKey,
    });
    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, "invalid_credentials");
  });

  test("an unknown account is indistinguishable from a wrong password", async () => {
    await boot();
    const { user } = await register(api);
    const wrong = await deriveKeys(user.accountId, "not the password", TEST_KDF);

    const wrongPassword = await api.post("/api/auth/login", {
      accountId: user.accountId,
      authKey: wrong.authKey,
    });
    const noSuchAccount = await api.post("/api/auth/login", {
      accountId: "nobody@example.com",
      authKey: wrong.authKey,
    });

    assert.equal(wrongPassword.status, noSuchAccount.status);
    assert.deepEqual(wrongPassword.body, noSuchAccount.body);
  });

  test("spends comparable time on known and unknown accounts", async () => {
    // Guards the fakeVerify() path. A missing account must not return in
    // microseconds while a real one costs a full scrypt -- that gap is an
    // account-enumeration oracle.
    await boot();
    const { user } = await register(api);
    const wrong = await deriveKeys(user.accountId, "not the password", TEST_KDF);

    const time = async (accountId: string) => {
      const start = performance.now();
      await api.post("/api/auth/login", { accountId, authKey: wrong.authKey });
      return performance.now() - start;
    };

    const known = await time(user.accountId);
    const unknown = await time("nobody@example.com");
    const ratio = Math.max(known, unknown) / Math.max(1, Math.min(known, unknown));

    assert.ok(ratio < 4, "timing gap too wide: " + known.toFixed(0) + "ms vs " + unknown.toFixed(0) + "ms");
  });

  test("rate-limits repeated attempts", async () => {
    await boot();
    const { user } = await register(api);
    const wrong = await deriveKeys(user.accountId, "nope", TEST_KDF);

    let limited = 0;
    for (let i = 0; i < 12; i++) {
      const response = await api.post("/api/auth/login", {
        accountId: user.accountId,
        authKey: wrong.authKey,
      });
      if (response.status === 429) {
        limited++;
        assert.ok(response.headers.get("retry-after"));
      }
    }
    assert.ok(limited > 0, "login was never rate-limited");
  });
});

describe("POST /api/auth/logout", () => {
  test("revokes the session immediately", async () => {
    await boot();
    const { token } = await register(api);

    assert.equal((await api.get("/api/vault", token)).status, 200);
    assert.equal((await api.post("/api/auth/logout", undefined, token)).status, 204);

    // The JWT is still cryptographically valid and unexpired -- the session
    // lookup is what rejects it.
    const after = await api.get("/api/vault", token);
    assert.equal(after.status, 401);
    assert.match(after.body.error.message, /signed out/);
  });

  test("requires a token", async () => {
    await boot();
    assert.equal((await api.post("/api/auth/logout")).status, 401);
  });
});

describe("POST /api/auth/change-password", () => {
  test("rotates credentials, keeps the vault, and signs every device out", async () => {
    await boot();
    const { user, token } = await register(api);

    // Seal a vault under the original password.
    const sealed = await sealVault(user);
    const saved = await api.put("/api/vault", { vault: sealed, expectedRevision: 0 }, token);
    assert.equal(saved.status, 200);

    // Client-side rewrap, exactly as @vaultify/crypto does it. Note the vault
    // ciphertext is never part of this -- only the 32-byte wrapped key.
    const rotated = await changeMasterPassword(
      user.masterPassword,
      "a completely different master password",
      {
        accountId: user.accountId,
        kdf: TEST_KDF,
        protectedVaultKey: deserialize(user.protectedVaultKey),
      },
      TEST_KDF,
    );

    const response = await api.post(
      "/api/auth/change-password",
      {
        currentAuthKey: user.authKey,
        newAuthKey: rotated.authKey,
        kdf: TEST_KDF,
        protectedVaultKey: serialize(rotated.keyRecord.protectedVaultKey),
      },
      token,
    );
    assert.equal(response.status, 204);

    // Old session is dead.
    assert.equal((await api.get("/api/vault", token)).status, 401);

    // Old auth key no longer works.
    const oldLogin = await api.post("/api/auth/login", {
      accountId: user.accountId,
      authKey: user.authKey,
    });
    assert.equal(oldLogin.status, 401);

    // New one does, and the vault ciphertext is untouched.
    const newLogin = await api.post("/api/auth/login", {
      accountId: user.accountId,
      authKey: rotated.authKey,
    });
    assert.equal(newLogin.status, 200);

    const vault = await api.get("/api/vault", newLogin.body.accessToken);
    assert.equal(vault.body.vault, sealed);
    assert.equal(vault.body.vaultRevision, 1);
  });

  test("a stolen token alone cannot change the password", async () => {
    await boot();
    const { user, token } = await register(api);
    const other = await makeUser();

    const response = await api.post(
      "/api/auth/change-password",
      {
        currentAuthKey: other.authKey, // attacker does not know the real one
        newAuthKey: other.authKey,
        kdf: TEST_KDF,
        protectedVaultKey: other.protectedVaultKey,
      },
      token,
    );

    assert.equal(response.status, 401);
    assert.equal(response.body.error.code, "invalid_credentials");

    // The account is untouched.
    const stored = await api.store.findAccount(user.accountId);
    assert.equal(stored?.protectedVaultKey, user.protectedVaultKey);
  });
});
