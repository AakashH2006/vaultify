/**
 * Key derivation: turning one thing the user remembers into two keys that must
 * never be confused with each other.
 *
 *   master password
 *         |  PBKDF2-HMAC-SHA256, per-account salt, 600,000 iterations
 *         v
 *     master key (256 bits)  <-- never stored, never transmitted
 *         |
 *         +-- HKDF(info="...auth-key")     --> AUTH KEY      --> sent to server
 *         |
 *         +-- HKDF(info="...wrapping-key") --> WRAPPING KEY  --> stays in the browser
 *
 * Why two steps instead of one PBKDF2 call per key: PBKDF2 is the expensive part,
 * and we only want to pay for it once. HKDF is cheap and is designed exactly for
 * this -- expanding one strong secret into several independent ones. Because the
 * two expansions use different `info` labels, learning the auth key tells an
 * attacker nothing about the wrapping key. That property is the whole reason the
 * server can hold the auth key without being able to read the vault.
 */

import {
  INFO_AUTH,
  INFO_SALT,
  INFO_WRAPPING,
  KEY_BITS,
  PBKDF2_HASH,
  PBKDF2_ITERATIONS,
  PBKDF2_MIN_ITERATIONS,
  AES_ALGORITHM,
} from "./constants.ts";
import { bytesToBase64, toBytes, utf8ToBytes, type Bytes } from "./encoding.ts";

export interface KdfParams {
  /** Currently always "PBKDF2". Present so a future Argon2id path can coexist. */
  readonly algorithm: "PBKDF2";
  readonly iterations: number;
}

export const DEFAULT_KDF_PARAMS: KdfParams = {
  algorithm: "PBKDF2",
  iterations: PBKDF2_ITERATIONS,
};

export interface DerivedKeys {
  /**
   * Base64. The only derived value that ever crosses the network. The server
   * must treat it as a password: store a slow hash of it (Argon2id/scrypt) with
   * its own server-side salt, never the value itself.
   */
  readonly authKey: string;
  /**
   * Non-extractable AES-GCM key used solely to wrap/unwrap the vault key.
   * Marked non-extractable so that even a successful XSS cannot export the raw
   * bytes -- the attacker can use the key while the tab is open, but cannot
   * steal it and decrypt the vault offline later.
   */
  readonly wrappingKey: CryptoKey;
}

/**
 * Per-account salt, derived deterministically from the account identifier.
 *
 * Deterministic rather than random so the client can derive keys offline, with
 * no "fetch my salt" round trip before login -- one less endpoint that leaks
 * which email addresses have accounts. Uniqueness across users comes from the
 * identifier; uniqueness across *applications* comes from the INFO_SALT prefix,
 * so a Vaultify master key is useless against any other service's hashes.
 *
 * Trade-off, stated plainly: a random per-account salt would also defeat an
 * attacker who precomputes against a *known* target email. See
 * docs/architecture.md for why we accept this.
 */
export async function deriveSalt(accountId: string): Promise<Bytes> {
  const normalised = accountId.trim().toLowerCase();
  if (normalised.length === 0) {
    throw new Error("deriveSalt: account identifier must not be empty");
  }
  const digest = await crypto.subtle.digest(
    "SHA-256",
    utf8ToBytes(`${INFO_SALT}|${normalised}`),
  );
  return toBytes(digest);
}

/**
 * The expensive step. Stretches the master password into 256 bits of master key.
 * Everything else in Vaultify hangs off this value, and it exists only as a
 * non-extractable CryptoKey handle for the lifetime of the unlock.
 */
async function deriveMasterKey(
  masterPassword: string,
  salt: Bytes,
  params: KdfParams,
): Promise<CryptoKey> {
  if (params.iterations < PBKDF2_MIN_ITERATIONS) {
    // A hostile or compromised server could otherwise weaken the KDF by simply
    // telling us to use fewer iterations.
    throw new Error(
      `Refusing to derive keys with ${params.iterations} iterations; ` +
        `minimum is ${PBKDF2_MIN_ITERATIONS}`,
    );
  }

  const passwordKey = await crypto.subtle.importKey(
    "raw",
    utf8ToBytes(masterPassword),
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  const masterKeyBits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: params.iterations, hash: PBKDF2_HASH },
    passwordKey,
    KEY_BITS,
  );

  // Re-import as an HKDF key so the two expansions below can hang off it.
  return crypto.subtle.importKey("raw", masterKeyBits, "HKDF", false, [
    "deriveBits",
    "deriveKey",
  ]);
}

/**
 * Derive both account keys from the master password.
 *
 * This is the function to read first if you are reviewing Vaultify's security.
 * The master password is used here and nowhere else; it is never returned,
 * stored, or logged.
 */
export async function deriveKeys(
  accountId: string,
  masterPassword: string,
  params: KdfParams = DEFAULT_KDF_PARAMS,
): Promise<DerivedKeys> {
  if (masterPassword.length === 0) {
    throw new Error("deriveKeys: master password must not be empty");
  }

  const salt = await deriveSalt(accountId);
  const masterKey = await deriveMasterKey(masterPassword, salt, params);

  const authKeyBits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: PBKDF2_HASH, salt, info: utf8ToBytes(INFO_AUTH) },
    masterKey,
    KEY_BITS,
  );

  const wrappingKey = await crypto.subtle.deriveKey(
    { name: "HKDF", hash: PBKDF2_HASH, salt, info: utf8ToBytes(INFO_WRAPPING) },
    masterKey,
    { name: AES_ALGORITHM, length: KEY_BITS },
    false, // non-extractable: see DerivedKeys.wrappingKey
    ["wrapKey", "unwrapKey"],
  );

  return { authKey: bytesToBase64(toBytes(authKeyBits)), wrappingKey };
}
