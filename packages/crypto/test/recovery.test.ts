/**
 * The recovery kit.
 *
 * The decisive test here is the last suite: a kit plus a backup file, with
 * no server and no master password, must reproduce the original entries. If
 * that works, the promise in the architecture document is real; if it does
 * not, the kit is a printout of nothing.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  DecryptionError,
  RecoveryKeyError,
  buildBackup,
  createAccount,
  decodeRecoveryKey,
  decryptVault,
  deserialize,
  encodeRecoveryKey,
  encryptVault,
  parseBackup,
  randomBytes,
  recoveryKeyFromBase64,
  recoveryKeyToBase64,
  serialize,
  unlockAccount,
  vaultKeyFromRecoveryKey,
  VAULT_SCHEMA_VERSION,
  type VaultContents,
} from "../src/index.ts";

const KDF = { algorithm: "PBKDF2", iterations: 100_000 } as const;
const ACCOUNT = "ada@example.com";
const PASSWORD = "ledger marble quartz tunnel";

function vault(password = "s3cr3t-value"): VaultContents {
  const now = "2026-02-01T00:00:00.000Z";
  return {
    version: VAULT_SCHEMA_VERSION,
    entries: [
      {
        id: "entry-1",
        name: "GitHub",
        username: "ada",
        password,
        createdAt: now,
        updatedAt: now,
      },
    ],
  };
}

describe("recovery key encoding", () => {
  it("writes 32 bytes as groups of five characters", () => {
    const key = encodeRecoveryKey(randomBytes(32));
    assert.match(key, /^[0-9A-HJKMNP-TV-Z]{5}(-[0-9A-HJKMNP-TV-Z]{1,5}){10}$/);
    assert.equal(key.replace(/-/g, "").length, 52);
  });

  it("round-trips exactly", () => {
    for (let i = 0; i < 50; i++) {
      const raw = randomBytes(32);
      assert.deepEqual(decodeRecoveryKey(encodeRecoveryKey(raw)), raw);
    }
  });

  it("forgives the mistakes someone makes copying from paper", () => {
    const raw = randomBytes(32);
    const key = encodeRecoveryKey(raw);

    for (const typed of [
      key.toLowerCase(),
      key.replace(/-/g, ""),
      key.replace(/-/g, " "),
      `  ${key}  `,
    ]) {
      assert.deepEqual(decodeRecoveryKey(typed), raw, typed.slice(0, 20));
    }
  });

  it("maps the look-alike characters a human substitutes", () => {
    // The alphabet has no I, L or O, so anyone writing one meant 1, 1 and 0.
    const raw = decodeRecoveryKey("00000-00000-00000-00000-00000-00000-00000-00000-00000-00000-00");
    const withLetters = decodeRecoveryKey(
      "OOOOO-OOOOO-OOOOO-OOOOO-OOOOO-OOOOO-OOOOO-OOOOO-OOOOO-OOOOO-OO",
    );
    assert.deepEqual(withLetters, raw);
  });

  it("refuses a key of the wrong length rather than deriving a wrong vault key", () => {
    // Silently accepting a short key would produce a valid-looking CryptoKey
    // that simply never decrypts anything, which is a miserable thing to debug
    // while holding a printout and a backup file.
    assert.throws(() => decodeRecoveryKey("ABCDE-ABCDE"), RecoveryKeyError);
    assert.throws(() => decodeRecoveryKey(encodeRecoveryKey(randomBytes(16))), RecoveryKeyError);
    assert.throws(() => decodeRecoveryKey(""), RecoveryKeyError);
  });

  it("refuses characters that are not in the alphabet", () => {
    assert.throws(() => decodeRecoveryKey("ABCDE-ABCD!"), RecoveryKeyError);
  });

  it("round-trips through base64 for callers holding a serialised key", () => {
    const raw = randomBytes(32);
    const key = encodeRecoveryKey(raw);
    assert.equal(recoveryKeyFromBase64(recoveryKeyToBase64(key)), key);
  });
});

describe("createAccount with a recovery kit", () => {
  it("does not produce a recovery key unless asked", async () => {
    const account = await createAccount(ACCOUNT, PASSWORD, KDF);
    assert.equal(account.recoveryKey, undefined);
  });

  it("produces one on request", async () => {
    const account = await createAccount(ACCOUNT, PASSWORD, KDF, { exportRecoveryKey: true });
    assert.ok(account.recoveryKey);
    assert.equal(account.recoveryKey.replace(/-/g, "").length, 52);
  });

  it("hands back the key that actually opens this vault", async () => {
    const account = await createAccount(ACCOUNT, PASSWORD, KDF, { exportRecoveryKey: true });
    const sealed = await encryptVault(account.vaultKey, vault(), ACCOUNT);

    const restoredKey = await vaultKeyFromRecoveryKey(account.recoveryKey!);
    const opened = await decryptVault(restoredKey, sealed, ACCOUNT);

    assert.equal(opened.entries[0].password, "s3cr3t-value");
  });

  it("gives a different key to every account", async () => {
    const keys = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const account = await createAccount(`u${i}@example.com`, PASSWORD, KDF, {
        exportRecoveryKey: true,
      });
      keys.add(account.recoveryKey!);
    }
    assert.equal(keys.size, 5);
  });

  it("restores a key that is still non-extractable", async () => {
    const account = await createAccount(ACCOUNT, PASSWORD, KDF, { exportRecoveryKey: true });
    const restored = await vaultKeyFromRecoveryKey(account.recoveryKey!);

    assert.equal(restored.extractable, false);
    await assert.rejects(() => crypto.subtle.exportKey("raw", restored));
  });
});

describe("what the kit cannot do", () => {
  it("is not a login: it carries nothing that authenticates to the server", async () => {
    const account = await createAccount(ACCOUNT, PASSWORD, KDF, { exportRecoveryKey: true });

    // The auth key is derived from the master password, not from the vault
    // key, so nothing in the kit can produce it. Someone who finds the
    // printout cannot ask the server for the ciphertext it decrypts.
    assert.ok(!account.recoveryKey!.includes(account.authKey.slice(0, 8)));
    assert.notEqual(recoveryKeyToBase64(account.recoveryKey!), account.authKey);
  });

  it("does not open another account's vault", async () => {
    const alice = await createAccount("alice@example.com", PASSWORD, KDF, {
      exportRecoveryKey: true,
    });
    const bob = await createAccount("bob@example.com", PASSWORD, KDF);
    const bobsVault = await encryptVault(bob.vaultKey, vault(), "bob@example.com");

    const alicesKey = await vaultKeyFromRecoveryKey(alice.recoveryKey!);
    await assert.rejects(
      () => decryptVault(alicesKey, bobsVault, "bob@example.com"),
      DecryptionError,
    );
  });

  it("does not open the right vault under the wrong account id", async () => {
    // The account id is bound in as GCM additional data, so the backup file
    // must carry it -- the kit alone is not enough.
    const account = await createAccount(ACCOUNT, PASSWORD, KDF, { exportRecoveryKey: true });
    const sealed = await encryptVault(account.vaultKey, vault(), ACCOUNT);

    const key = await vaultKeyFromRecoveryKey(account.recoveryKey!);
    await assert.rejects(() => decryptVault(key, sealed, "someone@else.com"), DecryptionError);
  });

  it("a mistyped key fails cleanly rather than returning garbage", async () => {
    const account = await createAccount(ACCOUNT, PASSWORD, KDF, { exportRecoveryKey: true });
    const sealed = await encryptVault(account.vaultKey, vault(), ACCOUNT);

    // Flip one character to another valid alphabet member.
    const characters = [...account.recoveryKey!];
    const index = characters.findIndex((c) => c !== "-");
    characters[index] = characters[index] === "A" ? "B" : "A";

    const wrong = await vaultKeyFromRecoveryKey(characters.join(""));
    await assert.rejects(() => decryptVault(wrong, sealed, ACCOUNT), DecryptionError);
  });
});

describe("backup files", () => {
  it("round-trip through JSON", async () => {
    const account = await createAccount(ACCOUNT, PASSWORD, KDF);
    const sealed = serialize(await encryptVault(account.vaultKey, vault(), ACCOUNT));

    const backup = buildBackup(ACCOUNT, sealed);
    const parsed = parseBackup(JSON.stringify(backup));

    assert.deepEqual(parsed, backup);
  });

  it("contain ciphertext and nothing readable", async () => {
    const account = await createAccount(ACCOUNT, PASSWORD, KDF);
    const sealed = serialize(
      await encryptVault(account.vaultKey, vault("hunter2-the-real-password"), ACCOUNT),
    );

    const text = JSON.stringify(buildBackup(ACCOUNT, sealed));

    assert.ok(!text.includes("hunter2-the-real-password"));
    assert.ok(!text.includes("GitHub"));
    assert.ok(!text.includes(PASSWORD));
  });

  it("reject a file that is not a backup, with a message that says so", () => {
    assert.throws(() => parseBackup("not json at all"), RecoveryKeyError);
    assert.throws(() => parseBackup(JSON.stringify({ hello: "world" })), RecoveryKeyError);
    assert.throws(
      () => parseBackup(JSON.stringify({ format: "vaultify-backup", version: 1 })),
      RecoveryKeyError,
    );
  });

  it("refuse a backup from a newer schema rather than silently dropping fields", () => {
    const future = JSON.stringify({
      format: "vaultify-backup",
      version: 99,
      accountId: ACCOUNT,
      vault: "1.AES-256-GCM.aaaa.bbbb",
    });
    assert.throws(() => parseBackup(future), /newer version/);
  });
});

describe("the whole promise: kit plus backup, no server, no password", () => {
  it("reproduces the original entries", async () => {
    // 1. A user registers and takes their kit.
    const account = await createAccount(ACCOUNT, PASSWORD, KDF, { exportRecoveryKey: true });
    const printedKit = account.recoveryKey!;

    // 2. They save some passwords and download an encrypted backup.
    const contents = vault("correct-battery-staple-42");
    const sealed = serialize(await encryptVault(account.vaultKey, contents, ACCOUNT));
    const backupFile = JSON.stringify(buildBackup(ACCOUNT, sealed));

    // 3. Years later: the master password is gone, the account is
    //    unreachable, the server might not even exist. All they have is the
    //    printout and the file.
    const backup = parseBackup(backupFile);
    const key = await vaultKeyFromRecoveryKey(printedKit);
    const recovered = await decryptVault(key, deserialize(backup.vault), backup.accountId);

    assert.deepEqual(recovered.entries, contents.entries);
    assert.equal(recovered.entries[0].password, "correct-battery-staple-42");
  });

  it("still fails without the kit, which is the point", async () => {
    const account = await createAccount(ACCOUNT, PASSWORD, KDF, { exportRecoveryKey: true });
    const sealed = serialize(await encryptVault(account.vaultKey, vault(), ACCOUNT));
    const backup = parseBackup(JSON.stringify(buildBackup(ACCOUNT, sealed)));

    // Someone who stole the backup file and nothing else.
    const guess = await vaultKeyFromRecoveryKey(encodeRecoveryKey(randomBytes(32)));
    await assert.rejects(
      () => decryptVault(guess, deserialize(backup.vault), backup.accountId),
      DecryptionError,
    );
  });

  it("the master password still works too -- the kit is an addition, not a replacement", async () => {
    const account = await createAccount(ACCOUNT, PASSWORD, KDF, { exportRecoveryKey: true });
    const sealed = await encryptVault(account.vaultKey, vault(), ACCOUNT);

    const unlocked = await unlockAccount(PASSWORD, account.keyRecord);
    const opened = await decryptVault(unlocked.vaultKey, sealed, ACCOUNT);

    assert.equal(opened.entries[0].password, "s3cr3t-value");
  });
});
