import { test, describe, afterEach } from "node:test";
import assert from "node:assert/strict";

import { register, sampleVault, sealVault, startApi, type TestApi } from "./harness.ts";
import { decryptVault, deserialize } from "../../../packages/crypto/src/index.ts";

let api: TestApi;
const boot = async (env?: Record<string, string>) => (api = await startApi(env));

afterEach(async () => {
  await api?.close();
});

describe("GET /api/vault", () => {
  test("returns null before the first sync", async () => {
    await boot();
    const { token } = await register(api);

    const response = await api.get("/api/vault", token);
    assert.equal(response.status, 200);
    assert.equal(response.body.vault, null);
    assert.equal(response.body.vaultRevision, 0);
    assert.equal(response.body.vaultUpdatedAt, null);
  });

  test("includes the key record so a resumed session can unwrap", async () => {
    await boot();
    const { user, token } = await register(api);
    const response = await api.get("/api/vault", token);
    assert.equal(response.body.keyRecord.protectedVaultKey, user.protectedVaultKey);
  });

  test("requires authentication", async () => {
    await boot();
    assert.equal((await api.get("/api/vault")).status, 401);
    assert.equal((await api.get("/api/vault", "not-a-token")).status, 401);
  });

  test("a token for one account cannot read another's vault", async () => {
    await boot();
    const alice = await register(api);
    const bob = await register(api);

    await api.put("/api/vault", { vault: await sealVault(alice.user), expectedRevision: 0 }, alice.token);
    const bobsView = await api.get("/api/vault", bob.token);

    assert.equal(bobsView.body.vault, null);
    assert.equal(bobsView.body.keyRecord.accountId, bob.user.accountId);
  });

  test("responses are not cacheable", async () => {
    await boot();
    const { token } = await register(api);
    const response = await api.get("/api/vault", token);
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.equal(response.headers.get("etag"), null);
  });
});

describe("PUT /api/vault", () => {
  test("stores the blob and bumps the revision", async () => {
    await boot();
    const { user, token } = await register(api);
    const sealed = await sealVault(user);

    const saved = await api.put("/api/vault", { vault: sealed, expectedRevision: 0 }, token);
    assert.equal(saved.status, 200);
    assert.equal(saved.body.vaultRevision, 1);
    assert.ok(saved.body.vaultUpdatedAt);

    const loaded = await api.get("/api/vault", token);
    assert.equal(loaded.body.vault, sealed);
    assert.equal(loaded.body.vaultRevision, 1);
  });

  test("the round trip survives real decryption on the client", async () => {
    // The point of the whole exercise: what comes back out of the database
    // still decrypts, byte for byte, with a key the server never had.
    await boot();
    const { user, token } = await register(api);
    const original = sampleVault("a-password-the-server-never-sees");

    await api.put("/api/vault", { vault: await sealVault(user, original), expectedRevision: 0 }, token);
    const loaded = await api.get("/api/vault", token);

    const decrypted = await decryptVault(
      user.vaultKey,
      deserialize(loaded.body.vault),
      user.accountId,
    );
    assert.deepEqual(decrypted, original);
  });

  test("what the server stores contains no plaintext", async () => {
    await boot();
    const { user, token } = await register(api);
    const secret = "correct-battery-staple-9471";

    await api.put(
      "/api/vault",
      { vault: await sealVault(user, sampleVault(secret)), expectedRevision: 0 },
      token,
    );

    const row = await api.store.findAccount(user.accountId);
    const everything = JSON.stringify(row);
    for (const fragment of [secret, "GitHub", "github.com", user.masterPassword]) {
      assert.ok(!everything.includes(fragment), "found " + fragment + " in the stored row");
    }
  });

  test("successive writes increment the revision", async () => {
    await boot();
    const { user, token } = await register(api);

    for (let revision = 0; revision < 3; revision++) {
      const response = await api.put(
        "/api/vault",
        { vault: await sealVault(user), expectedRevision: revision },
        token,
      );
      assert.equal(response.body.vaultRevision, revision + 1);
    }
  });

  test("requires authentication", async () => {
    await boot();
    const { user } = await register(api);
    const response = await api.put("/api/vault", {
      vault: await sealVault(user),
      expectedRevision: 0,
    });
    assert.equal(response.status, 401);
  });
});

describe("concurrent writes", () => {
  test("a stale write is rejected rather than silently clobbering", async () => {
    // Two tabs both load revision 0 and both save. The server cannot merge --
    // it cannot read either blob -- so the second write must lose loudly.
    await boot();
    const { user, token } = await register(api);

    const tabOne = await sealVault(user, sampleVault("written-by-tab-one"));
    const tabTwo = await sealVault(user, sampleVault("written-by-tab-two"));

    const first = await api.put("/api/vault", { vault: tabOne, expectedRevision: 0 }, token);
    assert.equal(first.status, 200);

    const second = await api.put("/api/vault", { vault: tabTwo, expectedRevision: 0 }, token);
    assert.equal(second.status, 409);
    assert.equal(second.body.error.code, "conflict");
    assert.equal(second.body.currentRevision, 1);

    // Tab one's data is intact.
    const loaded = await api.get("/api/vault", token);
    assert.equal(loaded.body.vault, tabOne);
  });

  test("the loser can re-read and retry at the current revision", async () => {
    await boot();
    const { user, token } = await register(api);

    await api.put("/api/vault", { vault: await sealVault(user), expectedRevision: 0 }, token);
    const stale = await api.put("/api/vault", { vault: await sealVault(user), expectedRevision: 0 }, token);

    const retry = await api.put(
      "/api/vault",
      { vault: await sealVault(user), expectedRevision: stale.body.currentRevision },
      token,
    );
    assert.equal(retry.status, 200);
    assert.equal(retry.body.vaultRevision, 2);
  });

  test("only one of several simultaneous writes wins", async () => {
    await boot();
    const { user, token } = await register(api);
    const payload = { vault: await sealVault(user), expectedRevision: 0 };

    const results = await Promise.all(
      Array.from({ length: 5 }, () => api.put("/api/vault", payload, token)),
    );

    assert.equal(results.filter((r) => r.status === 200).length, 1);
    assert.equal(results.filter((r) => r.status === 409).length, 4);
  });
});

describe("input validation", () => {
  test("rejects a blob that is not a valid envelope", async () => {
    await boot();
    const { token } = await register(api);
    for (const bad of ["", "plaintext", "1.AES-128-CBC.AAAAAAAAAAAAAAAA.AAAA", "../../etc/passwd"]) {
      const response = await api.put("/api/vault", { vault: bad, expectedRevision: 0 }, token);
      assert.equal(response.status, 400, "accepted " + JSON.stringify(bad));
    }
  });

  test("rejects a missing or negative revision", async () => {
    await boot();
    const { user, token } = await register(api);
    const vault = await sealVault(user);

    assert.equal((await api.put("/api/vault", { vault }, token)).status, 400);
    assert.equal(
      (await api.put("/api/vault", { vault, expectedRevision: -1 }, token)).status,
      400,
    );
  });

  test("rejects an oversized vault", async () => {
    await boot({ MAX_VAULT_BYTES: "2048" });
    const { token } = await register(api);
    const huge = "1.AES-256-GCM." + "A".repeat(16) + "." + "A".repeat(4096);

    const response = await api.put("/api/vault", { vault: huge, expectedRevision: 0 }, token);
    assert.equal(response.status, 400);
    assert.match(response.body.error.message, /too large/);
  });
});
