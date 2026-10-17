/**
 * Account lifecycle: registration, unlock, vault sealing, master-password change.
 *
 * The one design decision worth explaining here is the extra layer of key.
 * We do *not* encrypt the vault directly with the key derived from the master
 * password. Instead:
 *
 *   master password --KDF--> wrapping key --wraps--> VAULT KEY --encrypts--> vault
 *
 * The vault key is 256 random bits, generated once at registration. The upshot:
 * changing the master password only re-wraps 32 bytes, instead of downloading,
 * decrypting, re-encrypting and re-uploading the entire vault. It also means the
 * long-lived secret protecting the data is full-entropy random, not a human
 * password -- the password only ever guards the wrapper.
 *
 * What the server ends up holding: a hash of the auth key, the KDF parameters,
 * the wrapped vault key, and an opaque ciphertext. None of it is useful without
 * the master password, which the server never sees.
 */

import { AES_ALGORITHM, CRYPTO_VERSION, IV_BYTES, KEY_BITS, TAG_BITS } from "./constants.ts";
import {
  base64ToBytes,
  bytesToBase64,
  randomBytes,
  toBytes,
  utf8ToBytes,
  type Bytes,
} from "./encoding.ts";
import {
  ALG_LABEL,
  DecryptionError,
  decryptString,
  encryptString,
  type Envelope,
} from "./cipher.ts";
import { DEFAULT_KDF_PARAMS, deriveKeys, type KdfParams } from "./kdf.ts";
import { recoveryKeyFromRaw } from "./recovery.ts";
import { VAULT_SCHEMA_VERSION, type VaultContents } from "./types.ts";

/** Everything the server stores about an account's keys. Public by design. */
export interface AccountKeyRecord {
  readonly accountId: string;
  readonly kdf: KdfParams;
  /** The vault key, encrypted under the wrapping key. */
  readonly protectedVaultKey: Envelope;
}

export interface UnlockedAccount {
  /** Send to the server to authenticate. See DerivedKeys.authKey. */
  readonly authKey: string;
  /** Non-extractable. Encrypts and decrypts the vault for this session only. */
  readonly vaultKey: CryptoKey;
}

export interface NewAccount extends UnlockedAccount {
  readonly keyRecord: AccountKeyRecord;
  /**
   * The vault key, written out for the printable recovery kit -- present only
   * when registration was asked for it.
   *
   * This is the one place in the library that hands back raw key material as
   * a string, and it is opt-in for that reason. See recovery.ts for what the
   * kit does and, more importantly, what it does not do.
   */
  readonly recoveryKey?: string;
}

/** Context strings bind each ciphertext to the account it belongs to, so a
 *  malicious server cannot serve one user's blob to another and learn anything
 *  from how the client reacts. */
const vaultKeyContext = (accountId: string) => accountId + "|vault-key";
const vaultContext = (accountId: string) => accountId + "|vault";

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------

export async function createAccount(
  accountId: string,
  masterPassword: string,
  kdf: KdfParams = DEFAULT_KDF_PARAMS,
  options: { exportRecoveryKey?: boolean } = {},
): Promise<NewAccount> {
  const { authKey, wrappingKey } = await deriveKeys(accountId, masterPassword, kdf);

  // Extractable only for the moment it takes to wrap it; the handle we hand
  // back to the caller is re-imported as non-extractable below.
  const rawVaultKey = randomBytes(KEY_BITS / 8);
  const extractableVaultKey = await importVaultKey(rawVaultKey, true);
  const protectedVaultKey = await wrapVaultKey(extractableVaultKey, wrappingKey, accountId);

  const vaultKey = await importVaultKey(rawVaultKey, false);

  // Encoded before the buffer is wiped, and only when asked. The caller is
  // expected to show it once and drop it.
  const recoveryKey = options.exportRecoveryKey ? recoveryKeyFromRaw(rawVaultKey) : undefined;

  rawVaultKey.fill(0);

  return { authKey, vaultKey, keyRecord: { accountId, kdf, protectedVaultKey }, recoveryKey };
}

// ---------------------------------------------------------------------------
// Unlock
// ---------------------------------------------------------------------------

/**
 * Reverse of registration. Throws DecryptionError when the master password is
 * wrong -- and note *where* that happens: entirely on the client. The server is
 * never asked to judge the master password, so a stolen database still costs an
 * attacker one full KDF run per guess.
 */
export async function unlockAccount(
  masterPassword: string,
  keyRecord: AccountKeyRecord,
): Promise<UnlockedAccount> {
  const { accountId, kdf, protectedVaultKey } = keyRecord;
  const { authKey, wrappingKey } = await deriveKeys(accountId, masterPassword, kdf);
  const vaultKey = await unwrapVaultKey(protectedVaultKey, wrappingKey, accountId, false);
  return { authKey, vaultKey };
}

// ---------------------------------------------------------------------------
// Sealing and opening the vault itself
// ---------------------------------------------------------------------------

export async function encryptVault(
  vaultKey: CryptoKey,
  contents: VaultContents,
  accountId: string,
): Promise<Envelope> {
  return encryptString(vaultKey, JSON.stringify(contents), vaultContext(accountId));
}

export async function decryptVault(
  vaultKey: CryptoKey,
  envelope: Envelope,
  accountId: string,
): Promise<VaultContents> {
  const json = await decryptString(vaultKey, envelope, vaultContext(accountId));

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    // Authentication passed, so this is our own data -- but malformed. Treat it
    // as a decryption failure rather than letting a bad shape reach the UI.
    throw new DecryptionError();
  }

  if (
    typeof parsed !== "object" ||
    parsed === null ||
    !Array.isArray((parsed as VaultContents).entries)
  ) {
    throw new DecryptionError();
  }

  const contents = parsed as VaultContents;
  if (contents.version > VAULT_SCHEMA_VERSION) {
    throw new Error(
      "Vault was written by a newer version of Vaultify (schema v" +
        contents.version +
        "). Update before opening it, or you risk discarding data this client cannot see.",
    );
  }
  return contents;
}

// ---------------------------------------------------------------------------
// Master password change
// ---------------------------------------------------------------------------

/**
 * Re-wraps the vault key under a key derived from the new password. The vault
 * ciphertext is untouched -- it is still encrypted with the same vault key.
 *
 * Note what this does *not* do: it cannot revoke a vault key an attacker already
 * extracted. Changing the master password after a suspected compromise should be
 * paired with rotating every credential stored inside.
 */
export async function changeMasterPassword(
  oldPassword: string,
  newPassword: string,
  keyRecord: AccountKeyRecord,
  newKdf: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<{ authKey: string; keyRecord: AccountKeyRecord }> {
  const { accountId, kdf, protectedVaultKey } = keyRecord;

  const oldKeys = await deriveKeys(accountId, oldPassword, kdf);
  // Extractable here, and only here: re-wrapping requires exporting the key.
  const vaultKey = await unwrapVaultKey(protectedVaultKey, oldKeys.wrappingKey, accountId, true);

  const newKeys = await deriveKeys(accountId, newPassword, newKdf);
  const rewrapped = await wrapVaultKey(vaultKey, newKeys.wrappingKey, accountId);

  return {
    authKey: newKeys.authKey,
    keyRecord: { accountId, kdf: newKdf, protectedVaultKey: rewrapped },
  };
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

function importVaultKey(raw: Bytes, extractable: boolean): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    raw,
    { name: AES_ALGORITHM, length: KEY_BITS },
    extractable,
    ["encrypt", "decrypt"],
  );
}

async function wrapVaultKey(
  vaultKey: CryptoKey,
  wrappingKey: CryptoKey,
  accountId: string,
): Promise<Envelope> {
  const iv = randomBytes(IV_BYTES);
  const wrapped = await crypto.subtle.wrapKey("raw", vaultKey, wrappingKey, {
    name: AES_ALGORITHM,
    iv,
    tagLength: TAG_BITS,
    additionalData: utf8ToBytes(vaultKeyContext(accountId)),
  });
  return {
    v: CRYPTO_VERSION,
    alg: ALG_LABEL,
    iv: bytesToBase64(iv),
    ct: bytesToBase64(toBytes(wrapped)),
  };
}

async function unwrapVaultKey(
  protectedVaultKey: Envelope,
  wrappingKey: CryptoKey,
  accountId: string,
  extractable: boolean,
): Promise<CryptoKey> {
  try {
    return await crypto.subtle.unwrapKey(
      "raw",
      base64ToBytes(protectedVaultKey.ct),
      wrappingKey,
      {
        name: AES_ALGORITHM,
        iv: base64ToBytes(protectedVaultKey.iv),
        tagLength: TAG_BITS,
        additionalData: utf8ToBytes(vaultKeyContext(accountId)),
      },
      { name: AES_ALGORITHM, length: KEY_BITS },
      extractable,
      ["encrypt", "decrypt"],
    );
  } catch {
    throw new DecryptionError();
  }
}
