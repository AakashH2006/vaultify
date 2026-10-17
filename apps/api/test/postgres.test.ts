/**
 * Integration tests for the Postgres store.
 *
 * Skipped unless TEST_DATABASE_URL points at a throwaway database:
 *
 *   docker compose up -d db
 *   TEST_DATABASE_URL=postgres://vaultify:vaultify@localhost:5432/vaultify npm test
 *
 * These exist because the in-memory store cannot prove the parts that only
 * Postgres can get wrong: that bigint revisions survive the round trip as
 * numbers, that the compare-and-set is genuinely atomic in SQL, and that the
 * CHECK constraints actually fire.
 */

import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";

import { PostgresStore } from "../src/store/postgres.ts";

const DATABASE_URL = process.env.TEST_DATABASE_URL;
const skip = DATABASE_URL ? false : "set TEST_DATABASE_URL to run Postgres integration tests";

let store: PostgresStore;
let counter = 0;

const nextAccount = () => ({
  accountId: "pg-user-" + ++counter + "-" + Date.now() + "@example.com",
  authKeyHash: "scrypt$32768$8$1$c2FsdA==$aGFzaA==",
  kdf: { algorithm: "PBKDF2", iterations: 600_000 } as const,
  protectedVaultKey: "1.AES-256-GCM." + "A".repeat(16) + "." + "B".repeat(64),
});

const envelope = (size: number) => "1.AES-256-GCM." + "A".repeat(16) + "." + "C".repeat(size);

describe("PostgresStore", { skip }, () => {
  before(async () => {
    store = new PostgresStore(DATABASE_URL!);
    await store.migrate();
  });

  after(async () => {
    await store?.close();
  });

  test("migrate is idempotent", async () => {
    await store.migrate();
    await store.migrate();
  });

  test("creates and reads back an account", async () => {
    const input = nextAccount();
    const created = await store.createAccount(input);

    assert.ok(created);
    assert.equal(created.accountId, input.accountId);
    assert.equal(created.vault, null);
    assert.equal(created.vaultRevision, 0);
    // bigint arrives from node-postgres as a string; the store must coerce it.
    assert.equal(typeof created.vaultRevision, "number");

    const found = await store.findAccount(input.accountId);
    assert.deepEqual(found, created);
  });

  test("returns null rather than throwing on a duplicate", async () => {
    const input = nextAccount();
    assert.ok(await store.createAccount(input));
    assert.equal(await store.createAccount(input), null);
  });

  test("findAccount returns null for an unknown account", async () => {
    assert.equal(await store.findAccount("nobody-" + Date.now() + "@example.com"), null);
  });

  test("saves a vault and increments the revision", async () => {
    const input = nextAccount();
    await store.createAccount(input);

    const first = await store.saveVault(input.accountId, envelope(64), 0);
    assert.equal(first.status, "saved");
    assert.equal(first.status === "saved" && first.vaultRevision, 1);

    const second = await store.saveVault(input.accountId, envelope(128), 1);
    assert.equal(second.status === "saved" && second.vaultRevision, 2);
  });

  test("rejects a stale revision", async () => {
    const input = nextAccount();
    await store.createAccount(input);
    await store.saveVault(input.accountId, envelope(64), 0);

    const stale = await store.saveVault(input.accountId, envelope(64), 0);
    assert.equal(stale.status, "conflict");
    assert.equal(stale.status === "conflict" && stale.currentRevision, 1);
  });

  test("the compare-and-set is atomic under concurrency", async () => {
    // Five connections racing on the same row. Exactly one must win, which is
    // the property the WHERE clause buys us and a read-then-write would not.
    const input = nextAccount();
    await store.createAccount(input);

    const results = await Promise.all(
      Array.from({ length: 5 }, () => store.saveVault(input.accountId, envelope(64), 0)),
    );

    assert.equal(results.filter((r) => r.status === "saved").length, 1);
    assert.equal(results.filter((r) => r.status === "conflict").length, 4);
  });

  test("reports a missing account distinctly from a conflict", async () => {
    const result = await store.saveVault("ghost-" + Date.now() + "@example.com", envelope(64), 0);
    assert.equal(result.status, "no_such_account");
  });

  test("stores a vault far larger than any VARCHAR default", async () => {
    // The brief calls out column sizing specifically. A truncated ciphertext is
    // an unopenable vault, so prove TEXT holds a realistic worst case.
    const input = nextAccount();
    await store.createAccount(input);

    const big = envelope(2 * 1024 * 1024);
    const saved = await store.saveVault(input.accountId, big, 0);
    assert.equal(saved.status, "saved");

    const loaded = await store.findAccount(input.accountId);
    assert.equal(loaded?.vault?.length, big.length);
    assert.equal(loaded?.vault, big);
  });

  test("the CHECK constraint refuses a weakened KDF", async () => {
    await assert.rejects(
      () =>
        store.createAccount({
          ...nextAccount(),
          kdf: { algorithm: "PBKDF2", iterations: 1000 } as never,
        }),
      /kdf_iterations/,
    );
  });

  test("rotates credentials without touching the vault", async () => {
    const input = nextAccount();
    await store.createAccount(input);
    const sealed = envelope(256);
    await store.saveVault(input.accountId, sealed, 0);

    const rotated = await store.rotateCredentials(input.accountId, {
      authKeyHash: "scrypt$32768$8$1$bmV3c2FsdA==$bmV3aGFzaA==",
      kdf: { algorithm: "PBKDF2", iterations: 700_000 },
      protectedVaultKey: "1.AES-256-GCM." + "D".repeat(16) + "." + "E".repeat(64),
    });
    assert.equal(rotated, true);

    const after = await store.findAccount(input.accountId);
    assert.equal(after?.vault, sealed);
    assert.equal(after?.vaultRevision, 1);
    assert.equal(after?.kdf.iterations, 700_000);
  });

  test("sessions can be created, checked and revoked", async () => {
    const input = nextAccount();
    await store.createAccount(input);
    const sessionId = crypto.randomUUID();

    await store.createSession({
      sessionId,
      accountId: input.accountId,
      expiresAt: new Date(Date.now() + 60_000),
    });
    assert.equal(await store.isSessionActive(sessionId), true);

    await store.revokeSession(sessionId);
    assert.equal(await store.isSessionActive(sessionId), false);
  });

  test("an expired session is not active", async () => {
    const input = nextAccount();
    await store.createAccount(input);
    const sessionId = crypto.randomUUID();

    await store.createSession({
      sessionId,
      accountId: input.accountId,
      expiresAt: new Date(Date.now() - 1000),
    });
    assert.equal(await store.isSessionActive(sessionId), false);
  });

  test("revokeAllSessions clears every session for one account only", async () => {
    const mine = nextAccount();
    const theirs = nextAccount();
    await store.createAccount(mine);
    await store.createAccount(theirs);

    const expiresAt = new Date(Date.now() + 60_000);
    const sessions = [crypto.randomUUID(), crypto.randomUUID()];
    for (const sessionId of sessions) {
      await store.createSession({ sessionId, accountId: mine.accountId, expiresAt });
    }
    const other = crypto.randomUUID();
    await store.createSession({ sessionId: other, accountId: theirs.accountId, expiresAt });

    await store.revokeAllSessions(mine.accountId);

    for (const sessionId of sessions) {
      assert.equal(await store.isSessionActive(sessionId), false);
    }
    assert.equal(await store.isSessionActive(other), true);
  });

  test("pruneExpiredSessions removes only expired rows", async () => {
    const input = nextAccount();
    await store.createAccount(input);
    const live = crypto.randomUUID();
    const dead = crypto.randomUUID();

    await store.createSession({
      sessionId: live,
      accountId: input.accountId,
      expiresAt: new Date(Date.now() + 60_000),
    });
    await store.createSession({
      sessionId: dead,
      accountId: input.accountId,
      expiresAt: new Date(Date.now() - 60_000),
    });

    await store.pruneExpiredSessions();
    assert.equal(await store.isSessionActive(live), true);
    assert.equal(await store.isSessionActive(dead), false);
  });
});
