/**
 * Every tunable crypto parameter lives here, in one place, so that a reviewer can
 * audit the entire security posture of the client without reading any other file.
 *
 * Anything that is written into stored data carries a version tag. If a parameter
 * below ever changes, bump CRYPTO_VERSION and keep the old path alive for reading
 * so existing vaults stay openable.
 */

/** Format version stamped into every envelope we persist. */
export const CRYPTO_VERSION = 1;

/** Label prefix used for domain separation. Keeps our KDF outputs distinct from
 *  any other application that might derive keys from the same password. */
export const DOMAIN = "vaultify";

// ---------------------------------------------------------------------------
// Key derivation (password -> master key)
// ---------------------------------------------------------------------------

/**
 * PBKDF2 work factor. OWASP's 2023 guidance for PBKDF2-HMAC-SHA256 is 600,000
 * iterations. This is deliberately slow (~0.3-1s on a laptop): it is the only
 * thing standing between a stolen vault blob and an offline brute-force attack.
 *
 * Stored server-side per account so the number can be raised later without
 * locking existing users out.
 */
export const PBKDF2_ITERATIONS = 600_000;

/** Floor we refuse to go below. Protects against a malicious server handing the
 *  client `iterations: 1` during login and silently gutting the KDF. */
export const PBKDF2_MIN_ITERATIONS = 100_000;

export const PBKDF2_HASH = "SHA-256" as const;

/** Size of the master key and of every derived key, in bits. */
export const KEY_BITS = 256;

// ---------------------------------------------------------------------------
// HKDF labels (master key -> two independent sub-keys)
// ---------------------------------------------------------------------------

/** info string for the key that unwraps the vault key. Never leaves the device. */
export const INFO_WRAPPING = `${DOMAIN}|v${CRYPTO_VERSION}|wrapping-key`;

/** info string for the key we hand to the server to prove who we are. */
export const INFO_AUTH = `${DOMAIN}|v${CRYPTO_VERSION}|auth-key`;

/** info string for the per-account salt derived from the account identifier. */
export const INFO_SALT = `${DOMAIN}|v${CRYPTO_VERSION}|salt`;

// ---------------------------------------------------------------------------
// Symmetric encryption
// ---------------------------------------------------------------------------

export const AES_ALGORITHM = "AES-GCM" as const;

/** 96 bits is the IV length GCM is specified and optimised for. Never reuse one
 *  with the same key -- we generate a fresh random IV on every single encrypt. */
export const IV_BYTES = 12;

/** 128-bit authentication tag. This is what makes GCM detect tampering. */
export const TAG_BITS = 128;
