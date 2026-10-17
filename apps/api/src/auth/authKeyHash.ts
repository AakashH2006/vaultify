/**
 * Server-side hashing of the client's auth key.
 *
 * Worth being precise about what this is for, because it is easy to
 * cargo-cult. The auth key is *not* a password: it is 256 bits of PBKDF2
 * output, so an attacker holding `auth_key_hash` cannot brute-force it no
 * matter how fast the hash is. The master password is already protected by
 * 600,000 PBKDF2 iterations on the client, and that is the work factor doing
 * the real job.
 *
 * We hash it anyway, slowly, for two reasons:
 *   1. The auth key is a bearer credential -- anyone holding the value can
 *      request the encrypted vault. A database dump must not hand that over
 *      directly, so it gets stored the way a password would be.
 *   2. It costs one scrypt call per login and removes a whole class of
 *      "we stored the token in plaintext" incidents.
 *
 * scrypt rather than Argon2id: it ships in Node's standard library, so there
 * is no native addon to build on every platform a contributor uses. It is
 * memory-hard and on OWASP's recommended list. Argon2id would be a marginal
 * improvement against custom hardware and is a drop-in change if wanted --
 * the stored format is self-describing, so both can coexist during migration.
 */

import { randomBytes, scrypt, timingSafeEqual, type ScryptOptions } from "node:crypto";

/** promisify() drops the options overload, so the wrapper is written out. */
function scryptAsync(
  password: string,
  salt: Buffer,
  keylen: number,
  options: ScryptOptions,
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(password, salt, keylen, options, (error, derived) => {
      if (error) reject(error);
      else resolve(derived);
    });
  });
}

/** OWASP's minimum scrypt parameters: N=2^15, r=8, p=1. ~32 MB per hash. */
const N = 32_768;
const R = 8;
const P = 1;
const KEY_BYTES = 32;
const SALT_BYTES = 16;

/** scrypt needs 128 * N * r bytes; Node's default maxmem (32 MB) is just under. */
const MAX_MEM = 128 * N * R * 2;

const PREFIX = "scrypt";

async function derive(authKey: string, salt: Buffer): Promise<Buffer> {
  return scryptAsync(authKey, salt, KEY_BYTES, { N, r: R, p: P, maxmem: MAX_MEM });
}

/** Returns "scrypt$N$r$p$<salt base64>$<hash base64>". Self-describing, so the
 *  parameters can be raised later without invalidating existing rows. */
export async function hashAuthKey(authKey: string): Promise<string> {
  const salt = randomBytes(SALT_BYTES);
  const hash = await derive(authKey, salt);
  return [PREFIX, N, R, P, salt.toString("base64"), hash.toString("base64")].join("$");
}

/**
 * Constant-time verification against a stored hash.
 *
 * Returns false rather than throwing on a malformed stored value: a corrupt
 * row should fail the login, not 500 the endpoint.
 */
export async function verifyAuthKey(authKey: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== PREFIX) return false;

  const [, n, r, p, saltB64, hashB64] = parts;
  const expected = Buffer.from(hashB64, "base64");

  let actual: Buffer;
  try {
    actual = await scryptAsync(authKey, Buffer.from(saltB64, "base64"), expected.length, {
      N: Number(n),
      r: Number(r),
      p: Number(p),
      maxmem: MAX_MEM,
    });
  } catch {
    return false;
  }

  // Lengths are equal by construction above, but timingSafeEqual throws if they
  // are not, so the guard stays.
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}

/**
 * Burns the same work as a real verification, for logins against accounts that
 * do not exist.
 *
 * Without this, "no such account" returns in microseconds while a wrong auth
 * key takes ~100 ms, and that gap is a reliable account-enumeration oracle --
 * which, for a password manager, tells an attacker exactly who to phish.
 */
export async function fakeVerify(): Promise<false> {
  await derive("not-a-real-auth-key", Buffer.alloc(SALT_BYTES));
  return false;
}
