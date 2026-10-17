/**
 * Authenticated symmetric encryption, AES-256-GCM.
 *
 * GCM gives us confidentiality *and* integrity in one pass: if a single bit of
 * the ciphertext, the IV, or the associated data is altered, decryption throws
 * instead of returning plausible-looking garbage. That matters here because the
 * server storing our blobs is explicitly untrusted -- it could try to serve a
 * modified or stale vault, and we want that to fail loudly.
 *
 * The two rules GCM is unforgiving about, and how we hold to them:
 *   1. Never reuse an (key, IV) pair. We generate a fresh random 96-bit IV on
 *      every encrypt and never derive it from the plaintext.
 *   2. Authenticate the context, not just the bytes. The envelope header is fed
 *      in as additional authenticated data, so an attacker cannot relabel a v1
 *      blob as some future, weaker v0.
 */

import { AES_ALGORITHM, CRYPTO_VERSION, IV_BYTES, TAG_BITS } from "./constants.ts";
import {
  base64ToBytes,
  bytesToBase64,
  randomBytes,
  toBytes,
  utf8ToBytes,
  type Bytes,
} from "./encoding.ts";

export const ALG_LABEL = "AES-256-GCM" as const;

/** A self-describing encrypted blob. Safe to hand to the server verbatim. */
export interface Envelope {
  readonly v: number;
  readonly alg: typeof ALG_LABEL;
  /** Base64, 12 bytes. Public by design -- an IV is not a secret, only unique. */
  readonly iv: string;
  /** Base64 of ciphertext || 128-bit GCM tag. */
  readonly ct: string;
}

/**
 * Bytes bound to the ciphertext but left in the clear. Any mismatch at decrypt
 * time is a hard failure, which is what stops header downgrade and lets callers
 * pin a blob to, say, a particular account or record id.
 */
function associatedData(envelope: Pick<Envelope, "v" | "alg">, context?: string): Bytes {
  return utf8ToBytes(`${envelope.v}|${envelope.alg}|${context ?? ""}`);
}

export async function encryptBytes(
  key: CryptoKey,
  plaintext: Bytes,
  context?: string,
): Promise<Envelope> {
  const iv = randomBytes(IV_BYTES);
  const header = { v: CRYPTO_VERSION, alg: ALG_LABEL } as const;

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: AES_ALGORITHM,
      iv,
      tagLength: TAG_BITS,
      additionalData: associatedData(header, context),
    },
    key,
    plaintext,
  );

  return { ...header, iv: bytesToBase64(iv), ct: bytesToBase64(toBytes(ciphertext)) };
}

/**
 * Rejects with a deliberately vague error on any failure. The caller cannot tell
 * "wrong key" from "tampered ciphertext" from "wrong context", and neither can an
 * attacker probing us as an oracle.
 */
export async function decryptBytes(
  key: CryptoKey,
  envelope: Envelope,
  context?: string,
): Promise<Bytes> {
  assertSupported(envelope);

  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: AES_ALGORITHM,
        iv: base64ToBytes(envelope.iv),
        tagLength: TAG_BITS,
        additionalData: associatedData(envelope, context),
      },
      key,
      base64ToBytes(envelope.ct),
    );
    return toBytes(plaintext);
  } catch {
    throw new DecryptionError();
  }
}

export async function encryptString(
  key: CryptoKey,
  plaintext: string,
  context?: string,
): Promise<Envelope> {
  return encryptBytes(key, utf8ToBytes(plaintext), context);
}

export async function decryptString(
  key: CryptoKey,
  envelope: Envelope,
  context?: string,
): Promise<string> {
  const bytes = await decryptBytes(key, envelope, context);
  return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
}

/** Thrown for every decryption failure, with no detail about which one. */
export class DecryptionError extends Error {
  constructor() {
    super("Decryption failed: wrong key, or the data has been altered.");
    this.name = "DecryptionError";
  }
}

function assertSupported(envelope: Envelope): void {
  if (envelope?.alg !== ALG_LABEL || envelope.v !== CRYPTO_VERSION) {
    throw new Error(
      `Unsupported envelope (v=${envelope?.v}, alg=${envelope?.alg}). ` +
        `This client understands v${CRYPTO_VERSION}/${ALG_LABEL} only.`,
    );
  }
}

// ---------------------------------------------------------------------------
// Compact wire format: "1.AES-256-GCM.<iv>.<ct>"
// ---------------------------------------------------------------------------

export function serialize(envelope: Envelope): string {
  return `${envelope.v}.${envelope.alg}.${envelope.iv}.${envelope.ct}`;
}

export function deserialize(serialized: string): Envelope {
  const parts = serialized.split(".");
  if (parts.length !== 4) throw new Error("Malformed envelope string");
  const [version, alg, iv, ct] = parts;
  const envelope = { v: Number(version), alg, iv, ct } as Envelope;
  assertSupported(envelope);
  return envelope;
}
