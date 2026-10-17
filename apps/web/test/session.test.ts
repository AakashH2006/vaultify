/**
 * End-to-end tests of the client's session: real `@vaultify/crypto`, the real
 * `ApiClient`, and a fake server that enforces the real compare-and-set rule.
 *
 * No crypto is mocked, which follows the convention the rest of the repository
 * already uses. The consequence is that these tests are slow -- each unlock is
 * two genuine 600,000-iteration PBKDF2 runs -- so the KDF is dialled down to
 * the client's enforced minimum where the test is about sync rather than
 * about key derivation. The floor is still 100,000 iterations, so the code
 * path is identical; only the work factor changes.
 */

import assert from "node:assert/strict";
import { beforeEach, describe, it } from "node:test";

import { PBKDF2_MIN_ITERATIONS, decryptVault, deserialize, unlockAccount } from "@vaultify/crypto";

import { ApiClient, ApiError, toKeyRecord } from "../src/api.ts";
import { VaultSession } from "../src/session.ts";
import { FakeServer } from "./fake-server.ts";

const EMAIL = "ada@example.com";
const PASSWORD = "ledger marble quartz tunnel";

let server: FakeServer;
let api: ApiClient;

beforeEach(() => {
  server = new FakeServer();
  api = new ApiClient("https://api.test", server.fetch);
});

function register(email = EMAIL, password = PASSWORD): Promise<VaultSession> {
  return VaultSession.register(api, email, password);
}

describe("registration", () => {
  it("creates an account and opens an empty vault", async () => {
    const session = await register();

    assert.equal(session.accountId, EMAIL);
    assert.deepEqual([...session.entries], []);
    assert.equal(session.revision, 0);
    assert.equal(session.locked, false);
  });

  it("never sends the master password", async () => {
    await register();

    const sent = JSON.stringify(server.requests);
    assert.ok(!sent.includes(PASSWORD), "the master password reached the wire");
    for (const word of PASSWORD.split(" ")) {
      assert.ok(!sent.includes(word), `the fragment "${word}" reached the wire`);
    }
  });

  it("stores a wrapped vault key the server cannot unwrap", async () => {
    await register();

    const account = server.accounts.get(EMAIL);
    assert.ok(account);
    // Serialised envelope, and nothing resembling a key in the clear.
    assert.match(account.protectedVaultKey, /^1\.AES-256-GCM\.[\w+/=-]+\.[\w+/=-]+$/);
  });

  it("reports a duplicate account without claiming the password was wrong", async () => {
    await register();
    await assert.rejects(
      () => register(),
      (error: unknown) => error instanceof ApiError && error.code === "account_exists",
    );
  });

  it("normalises the email the same way the server does", async () => {
    await VaultSession.register(api, "  ADA@Example.COM ", PASSWORD);
    assert.ok(server.accounts.has(EMAIL));
  });
});

describe("unlock", () => {
  it("round-trips a vault through encryption, the server and back", async () => {
    const first = await register();
    first.addEntry({ name: "GitHub", username: "ada", password: "s3cret-ssh-key" });
    await first.save();

    const second = await VaultSession.unlock(api, EMAIL, PASSWORD);

    assert.equal(second.entries.length, 1);
    assert.equal(second.entries[0].name, "GitHub");
    assert.equal(second.entries[0].password, "s3cret-ssh-key");
  });

  it("refuses a wrong master password", async () => {
    await register();
    await assert.rejects(
      () => VaultSession.unlock(api, EMAIL, "ledger marble quartz tunnels"),
      (error: unknown) => error instanceof ApiError && error.code === "invalid_credentials",
    );
  });

  it("refuses an account that does not exist, indistinguishably", async () => {
    await assert.rejects(
      () => VaultSession.unlock(api, "nobody@example.com", PASSWORD),
      (error: unknown) => error instanceof ApiError && error.code === "invalid_credentials",
    );
  });

  it("treats a never-synced account as an empty vault, not an error", async () => {
    await register();
    const session = await VaultSession.unlock(api, EMAIL, PASSWORD);
    assert.deepEqual([...session.entries], []);
  });
});

describe("what the server can see", () => {
  it("holds ciphertext that does not contain any stored secret", async () => {
    const session = await register();
    session.addEntry({
      name: "Bank of Somewhere",
      username: "ada@example.com",
      password: "correct-battery-staple-42",
      notes: "recovery codes: 8821 4409",
    });
    await session.save();

    const stored = server.currentVault(EMAIL);
    assert.ok(stored);
    for (const secret of ["correct-battery-staple-42", "8821 4409", "Bank of Somewhere"]) {
      assert.ok(!stored.includes(secret), `"${secret}" is readable in the stored blob`);
    }
  });

  it("stores something only the vault key opens", async () => {
    const session = await register();
    session.addEntry({ name: "GitHub", username: "ada", password: "hunter2" });
    await session.save();

    // Do what a client with the master password would do, by hand.
    const account = server.accounts.get(EMAIL);
    assert.ok(account);
    const keyRecord = toKeyRecord(
      { accountId: account.accountId, kdf: account.kdf, protectedVaultKey: account.protectedVaultKey },
      deserialize,
    );
    const { vaultKey } = await unlockAccount(PASSWORD, keyRecord);
    const contents = await decryptVault(vaultKey, deserialize(account.vault!), EMAIL);

    assert.equal(contents.entries[0].password, "hunter2");
  });
});

describe("editing and saving", () => {
  it("tracks dirtiness across an edit and a save", async () => {
    const session = await register();
    assert.equal(session.dirty, false);

    session.addEntry({ name: "GitHub", username: "ada", password: "x" });
    assert.equal(session.dirty, true);

    await session.save();
    assert.equal(session.dirty, false);
  });

  it("bumps the revision on each successful write", async () => {
    const session = await register();
    session.addEntry({ name: "A", username: "", password: "a" });
    assert.equal((await session.save()).revision, 1);

    session.addEntry({ name: "B", username: "", password: "b" });
    assert.equal((await session.save()).revision, 2);
  });

  it("updates an entry and moves its updatedAt forward", async () => {
    const session = await register();
    const entry = session.addEntry({ name: "GitHub", username: "ada", password: "old" });
    const before = entry.updatedAt;

    await new Promise((resolve) => setTimeout(resolve, 2));
    const updated = session.updateEntry(entry.id, { password: "new" });

    assert.equal(updated.password, "new");
    assert.equal(updated.createdAt, entry.createdAt);
    assert.ok(updated.updatedAt >= before);
  });

  it("deletes an entry", async () => {
    const session = await register();
    const entry = session.addEntry({ name: "GitHub", username: "ada", password: "x" });
    session.deleteEntry(entry.id);
    assert.deepEqual([...session.entries], []);
  });

  it("refuses to update an entry that is not there", async () => {
    const session = await register();
    assert.throws(() => session.updateEntry("missing", { password: "x" }), /No such entry/);
  });
});

describe("a concurrent write from another device", () => {
  /** Register, save a baseline, then return a second session representing the
   *  same account open in another tab. */
  async function twoDevices(): Promise<[VaultSession, VaultSession]> {
    const first = await register();
    first.addEntry({ name: "Shared", username: "ada", password: "shared-password" });
    await first.save();

    const second = await VaultSession.unlock(api, EMAIL, PASSWORD);
    return [first, second];
  }

  it("merges instead of clobbering, and reports what it did", async () => {
    const [first, second] = await twoDevices();

    second.addEntry({ name: "From device two", username: "ada", password: "two" });
    await second.save();

    first.addEntry({ name: "From device one", username: "ada", password: "one" });
    const result = await first.save();

    // The losing write re-read, merged and retried -- without being asked to.
    const names = first.entries.map((entry) => entry.name).sort();
    assert.deepEqual(names, ["From device one", "From device two", "Shared"]);
    assert.ok(result.revision >= 3);

    // And the merged state is what is actually on the server.
    const reloaded = await VaultSession.unlock(api, EMAIL, PASSWORD);
    assert.deepEqual(reloaded.entries.map((entry) => entry.name).sort(), names);
  });

  it("does not lose the other device's entry when this one deletes a different entry", async () => {
    const [first, second] = await twoDevices();

    second.addEntry({ name: "Added elsewhere", username: "", password: "x" });
    await second.save();

    first.deleteEntry(first.entries[0].id);
    await first.save();

    const reloaded = await VaultSession.unlock(api, EMAIL, PASSWORD);
    assert.deepEqual(reloaded.entries.map((entry) => entry.name), ["Added elsewhere"]);
  });

  it("retries when the race is lost in the window between read and write", async () => {
    const [first, second] = await twoDevices();

    // The nastiest ordering: the other device commits *after* we encrypted and
    // sent, so our first attempt is already doomed when it leaves.
    server.beforeVaultWrite = async () => {
      server.beforeVaultWrite = null;
      second.addEntry({ name: "Interleaved", username: "", password: "x" });
      await second.save();
    };

    first.addEntry({ name: "Mine", username: "", password: "y" });
    const result = await first.save();

    assert.ok(result.revision > 0);
    assert.deepEqual(first.entries.map((entry) => entry.name).sort(), [
      "Interleaved", "Mine", "Shared",
    ]);
  });

  it("gives up rather than looping forever against relentless contention", async () => {
    const [first, second] = await twoDevices();

    // A write lands before every single attempt. The client must stop.
    server.beforeVaultWrite = async () => {
      const hook = server.beforeVaultWrite;
      server.beforeVaultWrite = null;
      second.addEntry({ name: `Noise ${second.entries.length}`, username: "", password: "x" });
      await second.save();
      server.beforeVaultWrite = hook;
    };

    first.addEntry({ name: "Mine", username: "", password: "y" });

    await assert.rejects(
      () => first.save(),
      (error: unknown) => error instanceof ApiError && error.code === "conflict",
    );
  });

  it("refresh pulls another device's changes without a local edit", async () => {
    const [first, second] = await twoDevices();

    second.addEntry({ name: "Elsewhere", username: "", password: "x" });
    await second.save();

    const outcome = await first.refresh();

    assert.equal(outcome.changed, true);
    assert.deepEqual(first.entries.map((entry) => entry.name).sort(), ["Elsewhere", "Shared"]);
  });

  it("refresh reports no change when nothing moved", async () => {
    const [first] = await twoDevices();
    const outcome = await first.refresh();
    assert.equal(outcome.changed, false);
    assert.deepEqual(outcome.notes, []);
  });
});

describe("changing the master password", () => {
  const NEW_PASSWORD = "cobalt lantern ribbon pasture";

  it("re-wraps the key, leaves the ciphertext alone, and locks the session", async () => {
    const session = await register();
    session.addEntry({ name: "GitHub", username: "ada", password: "hunter2" });
    await session.save();

    const ciphertextBefore = server.currentVault(EMAIL);
    const wrappedBefore = server.accounts.get(EMAIL)?.protectedVaultKey;

    await session.changePassword(PASSWORD, NEW_PASSWORD);

    assert.equal(session.locked, true, "the session must not survive its own password change");
    assert.equal(server.currentVault(EMAIL), ciphertextBefore, "the vault was needlessly re-encrypted");
    assert.notEqual(server.accounts.get(EMAIL)?.protectedVaultKey, wrappedBefore);
  });

  it("opens with the new password and not the old one", async () => {
    const session = await register();
    session.addEntry({ name: "GitHub", username: "ada", password: "hunter2" });
    await session.save();
    await session.changePassword(PASSWORD, NEW_PASSWORD);

    const reopened = await VaultSession.unlock(api, EMAIL, NEW_PASSWORD);
    assert.equal(reopened.entries[0].password, "hunter2");

    await assert.rejects(() => VaultSession.unlock(api, EMAIL, PASSWORD));
  });

  it("flushes unsaved edits first, because the session is about to die", async () => {
    const session = await register();
    session.addEntry({ name: "Saved just in time", username: "", password: "x" });

    await session.changePassword(PASSWORD, NEW_PASSWORD);

    const reopened = await VaultSession.unlock(api, EMAIL, NEW_PASSWORD);
    assert.deepEqual(reopened.entries.map((entry) => entry.name), ["Saved just in time"]);
  });

  it("rejects a wrong current password locally, before any request", async () => {
    const session = await register();
    const before = server.accounts.get(EMAIL)?.authKey;
    const requestsBefore = server.requests.length;

    // The wrong password fails at the unwrap, on this machine, because that is
    // where the check genuinely lives. The server is never asked, so a wrong
    // guess costs an attacker a full KDF run and buys them no oracle.
    await assert.rejects(
      () => session.changePassword("not the password", NEW_PASSWORD),
      (error: unknown) => error instanceof Error && error.name === "DecryptionError",
    );

    assert.equal(server.requests.length, requestsBefore, "a request went out anyway");
    assert.equal(server.accounts.get(EMAIL)?.authKey, before);
  });
});

describe("locking", () => {
  it("drops the entries and refuses further reads", async () => {
    const session = await register();
    session.addEntry({ name: "GitHub", username: "ada", password: "hunter2" });

    session.lock();

    assert.equal(session.locked, true);
    assert.throws(() => session.entries, /locked/i);
    assert.throws(() => session.addEntry({ name: "x", username: "", password: "y" }), /locked/i);
    await assert.rejects(() => session.save(), /locked/i);
  });

  it("clears the plaintext it was holding", async () => {
    const session = await register();
    const entry = session.addEntry({ name: "GitHub", username: "ada", password: "hunter2" });

    session.lock();

    // The caller may still hold a reference to the entry object we handed out.
    // Locking overwrites the secret fields in place so that reference goes stale.
    assert.equal(entry.password, "");
  });

  it("is idempotent", async () => {
    const session = await register();
    session.lock();
    session.lock();
    assert.equal(session.locked, true);
  });

  it("reports itself as not dirty once locked, so nothing tries to flush it", async () => {
    const session = await register();
    session.addEntry({ name: "GitHub", username: "ada", password: "x" });
    session.lock();
    assert.equal(session.dirty, false);
  });
});

describe("signing out", () => {
  it("revokes the session server-side and locks locally", async () => {
    const session = await register();
    assert.equal(server.sessions.size, 1);

    await session.signOut();

    assert.equal(server.sessions.size, 0);
    assert.equal(session.locked, true);
  });

  it("still locks locally when the network call fails", async () => {
    await register();

    // Unlock normally, then pull the network out from under the sign-out. A
    // server we cannot reach is no reason to leave a decrypted vault in the tab.
    let online = true;
    const flaky = new ApiClient("https://api.test", (input, init) =>
      online ? server.fetch(input, init) : Promise.reject(new Error("offline")),
    );
    const session = await VaultSession.unlock(flaky, EMAIL, PASSWORD);
    online = false;

    await session.signOut();
    assert.equal(session.locked, true);
  });
});

describe("the KDF floor", () => {
  it("is what the client derives against by default", () => {
    // Guards the thing a malicious server would most like to weaken. The
    // crypto package enforces the floor; this asserts the constant the UI
    // depends on has not quietly moved.
    assert.ok(PBKDF2_MIN_ITERATIONS >= 100_000);
  });
});
