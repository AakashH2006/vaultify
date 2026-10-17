/**
 * The recovery kit.
 *
 * The architecture document promises this, and it is worth being exact about
 * what it is -- because "recovery" in a zero-knowledge product is a word that
 * usually signals a backdoor, and this is not one.
 *
 * **The kit is the vault key itself**, written down. Nothing derives it from
 * the master password; nothing on the server can produce it; it is generated
 * once at registration, shown once, and then exists only wherever the user
 * put it. The server's copy stays wrapped under a key it cannot compute.
 *
 * **What the kit recovers is data, not access.** With the kit you can decrypt
 * a vault blob you already hold. You cannot use it to log in: authenticating
 * to the server needs the auth key, which needs the master password. That is
 * not an oversight. A kit that also granted server access would be a second
 * credential capable of pulling the vault down, and anyone who found the
 * printout would have everything.
 *
 * So the kit is useful in exactly one scenario, and the UI says so plainly:
 * **kit + encrypted backup = your passwords back, forever, with no server
 * involved.** Download the backup, print the kit, keep them apart. If the
 * master password is lost, the account is unreachable -- but the data is not.
 *
 * The encoding is Crockford-style base32 in groups of five, because this is
 * a thing a human transcribes from paper under stress.
 */

import { AES_ALGORITHM, CRYPTO_VERSION, KEY_BITS } from "./constants.ts";
import { base64ToBytes, bytesToBase64, type Bytes } from "./encoding.ts";
import { DecryptionError, type Envelope } from "./cipher.ts";

/** Alphabet without I, L, O or U: the first three to avoid confusion with 1
 *  and 0, and U so that no transcription error spells anything unfortunate. */
const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const DECODE = (() => {
  const table = new Map<string, number>();
  for (let i = 0; i < ALPHABET.length; i++) {
    table.set(ALPHABET[i], i);
    table.set(ALPHABET[i].toLowerCase(), i);
  }
  // The substitutions a human makes when copying by hand.
  table.set("I", 1);
  table.set("i", 1);
  table.set("L", 1);
  table.set("l", 1);
  table.set("O", 0);
  table.set("o", 0);
  return table;
})();

export class RecoveryKeyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RecoveryKeyError";
  }
}

/** 32 bytes -> 52 base32 characters, grouped in fives. */
export function encodeRecoveryKey(raw: Bytes): string {
  let bits = 0;
  let buffer = 0;
  let out = "";

  for (const byte of raw) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += ALPHABET[(buffer << (5 - bits)) & 31];

  return (out.match(/.{1,5}/g) ?? []).join("-");
}

export function decodeRecoveryKey(key: string): Bytes {
  const cleaned = key.replace(/[\s-]/g, "");
  if (cleaned.length === 0) throw new RecoveryKeyError("The recovery key is empty.");

  const bytes: number[] = [];
  let bits = 0;
  let buffer = 0;

  for (const char of cleaned) {
    const value = DECODE.get(char);
    if (value === undefined) {
      throw new RecoveryKeyError(`"${char}" is not part of a recovery key.`);
    }
    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  if (bytes.length !== KEY_BITS / 8) {
    throw new RecoveryKeyError(
      `A recovery key is ${KEY_BITS / 8} bytes; this decoded to ${bytes.length}. ` +
        "It is probably mistyped or incomplete.",
    );
  }

  return Uint8Array.from(bytes) as Bytes;
}

/**
 * Turn a written-down key back into a usable vault key.
 *
 * Non-extractable, like every other vault key handle in this library: having
 * restored from paper is no reason to let the running page export it again.
 */
export async function vaultKeyFromRecoveryKey(key: string): Promise<CryptoKey> {
  const raw = decodeRecoveryKey(key);
  try {
    return await crypto.subtle.importKey(
      "raw",
      raw,
      { name: AES_ALGORITHM, length: KEY_BITS },
      false,
      ["encrypt", "decrypt"],
    );
  } finally {
    raw.fill(0);
  }
}

/**
 * The portable backup file: an encrypted vault plus the metadata needed to
 * open it later, and nothing that helps anyone without the key.
 *
 * `accountId` is in here because it is bound into the ciphertext as GCM
 * additional data -- without it the blob cannot be decrypted even with the
 * right key. It is not a secret; it is the user's own email address, and they
 * are the only one who will ever hold this file.
 */
export interface VaultBackup {
  readonly format: "vaultify-backup";
  readonly version: number;
  readonly accountId: string;
  readonly exportedAt: string;
  /** Serialised envelope, exactly as the server stores it. */
  readonly vault: string;
}

export function buildBackup(accountId: string, serialisedVault: string): VaultBackup {
  return {
    format: "vaultify-backup",
    version: CRYPTO_VERSION,
    accountId,
    exportedAt: new Date().toISOString(),
    vault: serialisedVault,
  };
}

/**
 * Parse a backup file.
 *
 * Validated strictly: a backup is opened at the worst possible moment, and a
 * confusing failure then is much worse than a clear one now.
 */
export function parseBackup(contents: string): VaultBackup {
  let parsed: unknown;
  try {
    parsed = JSON.parse(contents);
  } catch {
    throw new RecoveryKeyError("That file is not a Vaultify backup.");
  }

  const backup = parsed as Partial<VaultBackup>;
  if (backup?.format !== "vaultify-backup") {
    throw new RecoveryKeyError("That file is not a Vaultify backup.");
  }
  if (typeof backup.accountId !== "string" || typeof backup.vault !== "string") {
    throw new RecoveryKeyError("This backup is missing fields and cannot be opened.");
  }
  if (typeof backup.version !== "number" || backup.version > CRYPTO_VERSION) {
    throw new RecoveryKeyError(
      "This backup was written by a newer version of Vaultify. Update before opening it.",
    );
  }

  return {
    format: "vaultify-backup",
    version: backup.version,
    accountId: backup.accountId,
    exportedAt: typeof backup.exportedAt === "string" ? backup.exportedAt : "",
    vault: backup.vault,
  };
}

/**
 * Re-export of the raw vault key at registration.
 *
 * Deliberately a separate, explicitly-named function rather than an extra
 * field on `createAccount`'s result. The raw key as a JavaScript string is
 * precisely what the rest of this library works to avoid, so producing one
 * should be a thing a caller asks for in so many words.
 */
export function recoveryKeyFromRaw(raw: Bytes): string {
  if (raw.length !== KEY_BITS / 8) {
    throw new RecoveryKeyError("A vault key is " + KEY_BITS / 8 + " bytes.");
  }
  return encodeRecoveryKey(raw);
}

/** Convenience for the restore screen: does this key open this blob? */
export async function canOpen(
  recoveryKey: string,
  envelope: Envelope,
  accountId: string,
  decrypt: (key: CryptoKey, envelope: Envelope, accountId: string) => Promise<unknown>,
): Promise<boolean> {
  try {
    const key = await vaultKeyFromRecoveryKey(recoveryKey);
    await decrypt(key, envelope, accountId);
    return true;
  } catch (error) {
    if (error instanceof DecryptionError || error instanceof RecoveryKeyError) return false;
    throw error;
  }
}

/** Round-trips through base64, for callers holding a serialised key. */
export function recoveryKeyFromBase64(base64: string): string {
  return encodeRecoveryKey(base64ToBytes(base64));
}

export function recoveryKeyToBase64(key: string): string {
  return bytesToBase64(decodeRecoveryKey(key));
}
