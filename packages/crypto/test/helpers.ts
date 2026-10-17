import type { KdfParams } from "../src/kdf.ts";
import { base64ToBytes, bytesToBase64 } from "../src/encoding.ts";
import type { Envelope } from "../src/cipher.ts";

/**
 * The lowest iteration count the library will accept. Keeps the suite fast
 * without routing around the floor the production code enforces -- if someone
 * lowers PBKDF2_MIN_ITERATIONS, these tests get faster and the review should
 * catch it, rather than the tests silently hiding the change.
 */
export const FAST_KDF: KdfParams = { algorithm: "PBKDF2", iterations: 100_000 };

export const ACCOUNT = "ada@example.com";
export const PASSWORD = "correct horse battery staple";

/** Flip one bit in the ciphertext of an envelope. */
export function tamper(envelope: Envelope): Envelope {
  const bytes = base64ToBytes(envelope.ct);
  bytes[0] ^= 0x01;
  return { ...envelope, ct: bytesToBase64(bytes) };
}
