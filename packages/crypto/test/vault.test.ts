import { test, describe } from "node:test";
import assert from "node:assert/strict";

import {
  changeMasterPassword,
  createAccount,
  decryptVault,
  encryptVault,
  unlockAccount,
} from "../src/vault.ts";
import { DecryptionError } from "../src/cipher.ts";
import { emptyVault, type VaultContents } from "../src/types.ts";
import { ACCOUNT, FAST_KDF, PASSWORD, tamper } from "./helpers.ts";

function sampleVault(): VaultContents {
  const now = new Date("2026-01-13T00:00:00.000Z").toISOString();
  return {
    ...emptyVault(),
    entries: [
      {
        id: "1",
        name: "GitHub",
        username: "ada",
        password: "s3cr3t-value",
        url: "https://github.com",
        createdAt: now,
        updatedAt: now,
      },
    ],
  };
}

describe("registration and unlock", () => {
  test("the key record contains nothing secret", async () => {
    const { keyRecord } = await createAccount(ACCOUNT, PASSWORD, FAST_KDF);
    const asJson = JSON.stringify(keyRecord);
    assert.ok(!asJson.includes(PASSWORD), "master password leaked into the key record");
    assert.deepEqual(Object.keys(keyRecord).sort(), ["accountId", "kdf", "protectedVaultKey"]);
  });

  test("unlocking with the right password yields the same auth key", async () => {
    const created = await createAccount(ACCOUNT, PASSWORD, FAST_KDF);
    const unlocked = await unlockAccount(PASSWORD, created.keyRecord);
    assert.equal(unlocked.authKey, created.authKey);
  });

  test("unlocking with the wrong password fails", async () => {
    const { keyRecord } = await createAccount(ACCOUNT, PASSWORD, FAST_KDF);
    await assert.rejects(() => unlockAccount(PASSWORD + "x", keyRecord), DecryptionError);
  });

  test("the vault key is non-extractable", async () => {
    const { vaultKey } = await createAccount(ACCOUNT, PASSWORD, FAST_KDF);
    assert.equal(vaultKey.extractable, false);
    const unlocked = await unlockAccount(PASSWORD, (await createAccount(ACCOUNT, PASSWORD, FAST_KDF)).keyRecord);
    assert.equal(unlocked.vaultKey.extractable, false);
  });

  test("two accounts with the same password get different vault keys", async () => {
    const ada = await createAccount("ada@example.com", PASSWORD, FAST_KDF);
    const grace = await createAccount("grace@example.com", PASSWORD, FAST_KDF);

    const sealed = await encryptVault(ada.vaultKey, sampleVault(), "ada@example.com");
    await assert.rejects(
      () => decryptVault(grace.vaultKey, sealed, "grace@example.com"),
      DecryptionError,
    );
  });

  test("a wrapped vault key cannot be moved to another account", async () => {
    // A malicious server swapping key records between users must not succeed.
    const ada = await createAccount("ada@example.com", PASSWORD, FAST_KDF);
    const stolen = { ...ada.keyRecord, accountId: "grace@example.com" };
    await assert.rejects(() => unlockAccount(PASSWORD, stolen), DecryptionError);
  });
});

describe("sealing the vault", () => {
  test("round-trips the contents", async () => {
    const { vaultKey } = await createAccount(ACCOUNT, PASSWORD, FAST_KDF);
    const vault = sampleVault();
    const sealed = await encryptVault(vaultKey, vault, ACCOUNT);
    assert.deepEqual(await decryptVault(vaultKey, sealed, ACCOUNT), vault);
  });

  test("the ciphertext contains no plaintext fragment", async () => {
    const { vaultKey } = await createAccount(ACCOUNT, PASSWORD, FAST_KDF);
    const sealed = await encryptVault(vaultKey, sampleVault(), ACCOUNT);
    const blob = JSON.stringify(sealed);
    for (const secret of ["s3cr3t-value", "GitHub", "ada", "github.com"]) {
      assert.ok(!blob.includes(secret), "found " + secret + " in the stored blob");
    }
  });

  test("rejects a tampered vault", async () => {
    const { vaultKey } = await createAccount(ACCOUNT, PASSWORD, FAST_KDF);
    const sealed = await encryptVault(vaultKey, sampleVault(), ACCOUNT);
    await assert.rejects(() => decryptVault(vaultKey, tamper(sealed), ACCOUNT), DecryptionError);
  });

  test("rejects a vault served under the wrong account", async () => {
    const { vaultKey } = await createAccount(ACCOUNT, PASSWORD, FAST_KDF);
    const sealed = await encryptVault(vaultKey, sampleVault(), ACCOUNT);
    await assert.rejects(
      () => decryptVault(vaultKey, sealed, "grace@example.com"),
      DecryptionError,
    );
  });

  test("refuses a vault written by a newer schema", async () => {
    const { vaultKey } = await createAccount(ACCOUNT, PASSWORD, FAST_KDF);
    const future = { ...sampleVault(), version: 99 };
    const sealed = await encryptVault(vaultKey, future, ACCOUNT);
    await assert.rejects(() => decryptVault(vaultKey, sealed, ACCOUNT), /newer version/);
  });
});

describe("changing the master password", () => {
  test("the old password stops working and the new one opens the same vault", async () => {
    const created = await createAccount(ACCOUNT, PASSWORD, FAST_KDF);
    const vault = sampleVault();
    const sealed = await encryptVault(created.vaultKey, vault, ACCOUNT);

    const NEW = "an entirely different master password";
    const changed = await changeMasterPassword(PASSWORD, NEW, created.keyRecord, FAST_KDF);

    await assert.rejects(() => unlockAccount(PASSWORD, changed.keyRecord), DecryptionError);

    const unlocked = await unlockAccount(NEW, changed.keyRecord);
    // The vault ciphertext was never rewritten -- only the 32-byte key wrapper.
    assert.deepEqual(await decryptVault(unlocked.vaultKey, sealed, ACCOUNT), vault);
  });

  test("produces a new auth key for the server", async () => {
    const created = await createAccount(ACCOUNT, PASSWORD, FAST_KDF);
    const changed = await changeMasterPassword(PASSWORD, "something else", created.keyRecord, FAST_KDF);
    assert.notEqual(changed.authKey, created.authKey);
  });

  test("rejects the wrong current password", async () => {
    const created = await createAccount(ACCOUNT, PASSWORD, FAST_KDF);
    await assert.rejects(
      () => changeMasterPassword("not it", "new one", created.keyRecord, FAST_KDF),
      DecryptionError,
    );
  });
});

describe("forgotten master password", () => {
  test("there is no recovery path, by design", async () => {
    // Deliverable 3 in the brief asks what happens here. The answer is encoded
    // as a test: with the password gone, the key record and the ciphertext are
    // all that remain, and neither yields the vault.
    const created = await createAccount(ACCOUNT, PASSWORD, FAST_KDF);
    const sealed = await encryptVault(created.vaultKey, sampleVault(), ACCOUNT);

    for (const guess of ["", "password", PASSWORD.toUpperCase(), PASSWORD.trim() + " "]) {
      await assert.rejects(() => unlockAccount(guess, created.keyRecord));
    }
    assert.ok(sealed.ct.length > 0);
  });
});
