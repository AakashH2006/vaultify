/**
 * Byte/string plumbing. No secrets are made or broken here, but getting these
 * wrong (e.g. using a lossy string conversion on ciphertext) silently corrupts
 * vaults, so each helper is deliberately boring and explicit.
 *
 * Everything below works identically in the browser and in Node.
 */

/**
 * Uint8Array over a plain ArrayBuffer. Web Crypto's BufferSource excludes
 * SharedArrayBuffer-backed views, and since TypeScript 5.7 the default
 * `Uint8Array` is generic over both -- so every byte array that reaches
 * crypto.subtle is typed with this alias rather than bare `Uint8Array`.
 */
export type Bytes = Uint8Array<ArrayBuffer>;

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder("utf-8", { fatal: true });

export function utf8ToBytes(text: string): Bytes {
  return textEncoder.encode(text);
}

export function bytesToUtf8(bytes: Bytes): string {
  return textDecoder.decode(bytes);
}

/** Cryptographically strong random bytes, from the platform CSPRNG. */
export function randomBytes(length: number): Bytes {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  // Chunked so that very large vaults do not blow the argument limit of apply().
  let binary = "";
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

export function base64ToBytes(base64: string): Bytes {
  const binary = atob(base64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

/** ArrayBuffer -> Bytes, for the values Web Crypto hands back. */
export function toBytes(buffer: ArrayBuffer): Bytes {
  return new Uint8Array(buffer);
}

/**
 * Comparison that takes the same amount of time regardless of where the first
 * difference is. Use this for anything an attacker can submit repeatedly
 * (auth keys, tags) so response timing does not leak the correct value.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Best-effort wipe of a buffer that held key material.
 *
 * Caveat worth stating out loud: JavaScript gives no guarantee here. Strings are
 * immutable and the GC may have already copied the bytes elsewhere. This reduces
 * the window in which a heap snapshot is useful; it does not close it.
 */
export function zero(bytes: Uint8Array): void {
  bytes.fill(0);
}
