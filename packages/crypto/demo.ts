/**
 * Week 1 deliverable, runnable: `npm run demo`.
 *
 * Walks the full zero-knowledge flow at production KDF settings and prints what
 * the server would see at each step. Paste the same calls into a browser
 * console against the built package and you get identical output -- the library
 * has no Node-specific code in it.
 */

import {
  changeMasterPassword,
  createAccount,
  decryptVault,
  encryptVault,
  entropyBits,
  generatePassword,
  serialize,
  unlockAccount,
  emptyVault,
  DEFAULT_KDF_PARAMS,
  type VaultContents,
} from "./src/index.ts";

const ACCOUNT = "ada@example.com";
const MASTER_PASSWORD = "correct horse battery staple";

const rule = (title: string) =>
  console.log("\n" + title + "\n" + "-".repeat(title.length));

const timed = async <T,>(label: string, work: () => Promise<T>): Promise<T> => {
  const start = performance.now();
  const result = await work();
  console.log("  " + label + ": " + Math.round(performance.now() - start) + " ms");
  return result;
};

rule("1. Registration");
console.log(
  "  KDF: PBKDF2-HMAC-SHA256, " +
    DEFAULT_KDF_PARAMS.iterations.toLocaleString("en-US") +
    " iterations",
);

const account = await timed("derive keys + generate vault key", () =>
  createAccount(ACCOUNT, MASTER_PASSWORD),
);

console.log("\n  What goes to the server at sign-up:");
console.log(JSON.stringify({ authKey: account.authKey, ...account.keyRecord }, null, 2)
  .split("\n")
  .map((line) => "    " + line)
  .join("\n"));
console.log("\n  What never leaves this process: the master password, the wrapping");
console.log("  key, and the unwrapped vault key.");

rule("2. Add an entry, using the generator");

const generated = generatePassword({ length: 24 });
console.log("  generated: " + generated);
console.log("  entropy:   " + entropyBits({ length: 24 }).toFixed(1) + " bits");

const now = new Date().toISOString();
const vault: VaultContents = {
  ...emptyVault(),
  entries: [
    {
      id: crypto.randomUUID(),
      name: "GitHub",
      username: "ada",
      password: generated,
      url: "https://github.com",
      createdAt: now,
      updatedAt: now,
    },
  ],
};

rule("3. Seal the vault (this is the PUT /vault body)");

const sealed = await encryptVault(account.vaultKey, vault, ACCOUNT);
const wire = serialize(sealed);
console.log("  " + wire.slice(0, 96) + "...");
console.log("  " + wire.length + " characters of ciphertext. Search it for the password:");
console.log("  contains \"" + generated + "\"? " + wire.includes(generated));
console.log("  contains \"GitHub\"? " + wire.includes("GitHub"));

rule("4. Unlock on another device (GET /vault, then decrypt locally)");

const unlocked = await timed("derive keys + unwrap vault key", () =>
  unlockAccount(MASTER_PASSWORD, account.keyRecord),
);
const opened = await decryptVault(unlocked.vaultKey, sealed, ACCOUNT);
console.log("  recovered entry: " + opened.entries[0].name + " / " + opened.entries[0].username);
console.log("  password matches: " + (opened.entries[0].password === generated));

rule("5. Wrong master password");

try {
  await unlockAccount("not the master password", account.keyRecord);
  console.log("  !! unlocked -- this should be unreachable");
} catch (error) {
  console.log("  rejected: " + (error as Error).message);
}

rule("6. Change the master password");

const changed = await changeMasterPassword(
  MASTER_PASSWORD,
  "a completely different master password",
  account.keyRecord,
);
const reopened = await unlockAccount("a completely different master password", changed.keyRecord);

// The vault blob from step 3 was never touched -- only the 32-byte wrapper.
const stillReadable = await decryptVault(reopened.vaultKey, sealed, ACCOUNT);
console.log("  vault ciphertext re-uploaded: no");
console.log("  old vault still opens:        " + (stillReadable.entries[0].password === generated));
console.log("  auth key changed:             " + (changed.authKey !== account.authKey));

rule("7. If the master password is lost");
console.log("  The server holds: an auth key hash, KDF parameters, a wrapped");
console.log("  vault key, and the ciphertext above. The wrapping key exists");
console.log("  nowhere but in the password. There is no reset -- see the");
console.log("  threat model in docs/architecture.md.\n");
