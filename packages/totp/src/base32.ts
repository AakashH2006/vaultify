/**
 * RFC 4648 base32, the alphabet every authenticator app speaks.
 *
 * Why base32 and not base64, which is already used everywhere else in this
 * project: a TOTP secret is routinely typed in by hand when a camera is not
 * available. Base32 is case-insensitive and drops the two characters base64
 * uses that are easy to mistype (`+`, `/`), so "read it off the screen and
 * type it into your phone" works.
 *
 * Padding is accepted on decode and omitted on encode. Authenticator apps
 * disagree about whether to include it, and a secret that fails to scan
 * because of a trailing `=` is a bad afternoon for everyone.
 */

/** Same reasoning as @vaultify/crypto's alias of the same name: `crypto.subtle`
 *  will not accept a `Uint8Array` that might be backed by a `SharedArrayBuffer`,
 *  so every byte array heading for Web Crypto is pinned to a plain one. */
export type Bytes = Uint8Array<ArrayBuffer>;

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Decoding table, built once. -1 marks a character that is not base32. */
const LOOKUP = (() => {
  const table = new Int8Array(128).fill(-1);
  for (let i = 0; i < ALPHABET.length; i++) {
    table[ALPHABET.charCodeAt(i)] = i;
    // Lower case maps to the same value: the alphabet is case-insensitive.
    table[ALPHABET.toLowerCase().charCodeAt(i)] = i;
  }
  return table;
})();

export function base32Encode(bytes: Uint8Array): string {
  let output = "";
  let buffer = 0;
  let bits = 0;

  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += ALPHABET[(buffer >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  // Whatever is left over is padded on the right with zero bits, per RFC 4648.
  if (bits > 0) output += ALPHABET[(buffer << (5 - bits)) & 31];

  return output;
}

export class Base32Error extends Error {
  constructor(message = "Not a valid base32 secret.") {
    super(message);
    this.name = "Base32Error";
  }
}

/**
 * Decode, tolerating the way humans transcribe these: spaces, hyphens, mixed
 * case and padding are all ignored.
 *
 * Trailing bits that do not make a whole byte are discarded, which is what
 * RFC 4648 requires -- but a non-zero remainder means the input was truncated
 * or mistyped, so that is rejected rather than silently decoded into a secret
 * that will never produce a matching code.
 */
export function base32Decode(input: string): Bytes {
  const cleaned = input.replace(/[\s-]/g, "").replace(/=+$/, "");
  if (cleaned.length === 0) throw new Base32Error("The secret is empty.");

  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;

  for (const char of cleaned) {
    const code = char.charCodeAt(0);
    const value = code < 128 ? LOOKUP[code] : -1;
    if (value < 0) {
      throw new Base32Error(`"${char}" is not a base32 character.`);
    }

    buffer = (buffer << 5) | value;
    bits += 5;
    if (bits >= 8) {
      bytes.push((buffer >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  if (bits > 0 && (buffer & ((1 << bits) - 1)) !== 0) {
    throw new Base32Error("The secret is truncated or mistyped.");
  }

  return Uint8Array.from(bytes) as Bytes;
}

/** Groups of four, for a secret a user has to read off a screen and type in. */
export function formatSecret(secret: string): string {
  return (secret.match(/.{1,4}/g) ?? []).join(" ");
}
