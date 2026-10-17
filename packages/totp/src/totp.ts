/**
 * TOTP -- RFC 6238, which is HOTP (RFC 4226) with a counter derived from the
 * clock.
 *
 *   counter = floor(unix_seconds / 30)
 *   hash    = HMAC-SHA1(secret, counter as 8-byte big-endian)
 *   offset  = hash[19] & 0x0f                      <- "dynamic truncation"
 *   code    = (4 bytes at offset, high bit cleared) % 10^6
 *
 * Two things about this are worth stating plainly rather than leaving a
 * reviewer to wonder.
 *
 * **SHA-1 is correct here.** It is broken for collision resistance, which is
 * what matters for signatures and certificates. HMAC-SHA1 does not depend on
 * collision resistance, there is no practical attack on it, and SHA-1 is what
 * every authenticator app implements. Choosing SHA-256 would be marginally
 * stronger in theory and unusable in practice, because a meaningful share of
 * authenticator apps would silently generate the wrong codes. RFC 6238 allows
 * both; the algorithm is carried in the otpauth URI so it can be changed later.
 *
 * **The code is six digits -- a one-in-a-million guess per attempt.** That is
 * not much on its own, which is why the verification window is kept to one
 * step either side, each code is accepted exactly once, and the login route
 * rate-limits before it ever gets here. The arithmetic matters: with a +/-1
 * window, three codes are live at any moment, so a blind guess succeeds with
 * probability 3/10^6. The login limiter allows 10 attempts per 15 minutes,
 * which puts a successful blind guess somewhere past a century.
 *
 * Pure Web Crypto, so the same file runs in the browser (enrolment, and the
 * per-entry authenticator) and in Node (login verification).
 */

import { base32Decode, base32Encode, type Bytes } from "./base32.ts";

/** RFC 6238's recommended step. Every authenticator app assumes it. */
export const DEFAULT_PERIOD_SECONDS = 30;
export const DEFAULT_DIGITS = 6;

/**
 * How many steps either side of "now" are accepted.
 *
 * One step (+/-30s) is the usual compromise: it absorbs ordinary clock drift
 * between a phone and a server, and the user taking a few seconds to type.
 * Widening it multiplies the number of simultaneously-valid codes, which is a
 * direct and linear weakening of a six-digit secret.
 */
export const DEFAULT_WINDOW = 1;

/** 160 bits, matching HMAC-SHA1's block output. RFC 4226 requires at least 128
 *  and recommends 160. */
export const SECRET_BYTES = 20;

export interface TotpOptions {
  digits?: number;
  periodSeconds?: number;
  /** Milliseconds since the epoch. Injectable so the tests can pin the clock
   *  to the RFC 6238 test vectors. */
  now?: number;
}

/** A fresh secret, base32-encoded and ready for an otpauth URI. */
export function generateSecret(bytes = SECRET_BYTES): string {
  const raw: Bytes = new Uint8Array(bytes);
  crypto.getRandomValues(raw);
  return base32Encode(raw);
}

/** The counter value for a moment in time. Exposed because replay prevention
 *  needs to record *which* step was spent, not just that a code was right. */
export function stepFor(now: number, periodSeconds = DEFAULT_PERIOD_SECONDS): number {
  return Math.floor(now / 1000 / periodSeconds);
}

/** Seconds until the current code rolls over, for the countdown ring. */
export function secondsRemaining(
  now: number = Date.now(),
  periodSeconds = DEFAULT_PERIOD_SECONDS,
): number {
  return periodSeconds - Math.floor(now / 1000) % periodSeconds;
}

async function hmacSha1(key: Bytes, message: Bytes): Promise<Bytes> {
  const handle = await crypto.subtle.importKey(
    "raw",
    key,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  return new Uint8Array(await crypto.subtle.sign("HMAC", handle, message));
}

/** The 8-byte big-endian counter RFC 4226 specifies. */
function counterBytes(counter: number): Bytes {
  const bytes: Bytes = new Uint8Array(8);
  // Counter is seconds/30, so it stays well inside Number's safe range until
  // the year ~8.5 million. Split rather than use BigInt to keep this cheap.
  let high = Math.floor(counter / 0x1_0000_0000);
  let low = counter >>> 0;
  for (let i = 7; i >= 4; i--) {
    bytes[i] = low & 0xff;
    low = low >>> 8;
  }
  for (let i = 3; i >= 0; i--) {
    bytes[i] = high & 0xff;
    high = Math.floor(high / 256);
  }
  return bytes;
}

/** HOTP: the code for one specific counter value. */
export async function hotp(
  secret: string | Bytes,
  counter: number,
  digits = DEFAULT_DIGITS,
): Promise<string> {
  const key = typeof secret === "string" ? base32Decode(secret) : secret;
  const hash = await hmacSha1(key, counterBytes(counter));

  // Dynamic truncation (RFC 4226 section 5.3): the low nibble of the last byte
  // chooses where to read the code from, so the output does not always come
  // from the same part of the digest.
  const offset = hash[hash.length - 1] & 0x0f;
  const binary =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  return String(binary % 10 ** digits).padStart(digits, "0");
}

/** The code for right now. */
export function totp(secret: string | Bytes, options: TotpOptions = {}): Promise<string> {
  const now = options.now ?? Date.now();
  const period = options.periodSeconds ?? DEFAULT_PERIOD_SECONDS;
  return hotp(secret, stepFor(now, period), options.digits ?? DEFAULT_DIGITS);
}

export interface VerifyOptions extends TotpOptions {
  window?: number;
  /**
   * The last step this account successfully spent. A code from that step or
   * earlier is refused, which is what stops a code shoulder-surfed or sniffed
   * from the network being replayed inside its 90-second validity.
   */
  lastUsedStep?: number | null;
}

export interface VerifyResult {
  readonly ok: boolean;
  /** The step the code belonged to. Persist it as `lastUsedStep`. */
  readonly step: number | null;
  readonly reason?: "malformed" | "mismatch" | "replayed";
}

/**
 * Verify a submitted code.
 *
 * Returns the matched step so the caller can record it and refuse a replay.
 * That bookkeeping genuinely belongs to the caller: it has to be persisted
 * atomically with the login, and only the caller knows how.
 */
export async function verifyTotp(
  secret: string | Bytes,
  code: string,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const digits = options.digits ?? DEFAULT_DIGITS;
  const period = options.periodSeconds ?? DEFAULT_PERIOD_SECONDS;
  const window = options.window ?? DEFAULT_WINDOW;
  const now = options.now ?? Date.now();

  // Users paste codes with a space in the middle; phones sometimes show them
  // that way. Strip before anything else.
  const normalised = code.replace(/\D/g, "");
  if (normalised.length !== digits) return { ok: false, step: null, reason: "malformed" };

  const current = stepFor(now, period);

  for (let offset = -window; offset <= window; offset++) {
    const step = current + offset;
    const expected = await hotp(secret, step, digits);

    // Constant-time compare. The codes are short and public-ish, but a timing
    // side channel on a six-digit secret is cheap to close and embarrassing to
    // leave open.
    if (!equal(expected, normalised)) continue;

    if (options.lastUsedStep != null && step <= options.lastUsedStep) {
      return { ok: false, step, reason: "replayed" };
    }
    return { ok: true, step };
  }

  return { ok: false, step: null, reason: "mismatch" };
}

/** Length-independent constant-time string comparison. */
function equal(a: string, b: string): boolean {
  let diff = a.length ^ b.length;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i++) {
    diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  }
  return diff === 0;
}

/**
 * The `otpauth://` URI authenticator apps read from a QR code.
 *
 * The label convention is `Issuer:account`, with the issuer repeated as a
 * parameter. It is redundant and it is what the apps actually parse, so both
 * are sent.
 */
export function otpauthUri(options: {
  secret: string;
  account: string;
  issuer?: string;
  digits?: number;
  periodSeconds?: number;
}): string {
  const issuer = options.issuer ?? "Vaultify";
  const label = `${issuer}:${options.account}`;
  const params = new URLSearchParams({
    secret: options.secret,
    issuer,
    algorithm: "SHA1",
    digits: String(options.digits ?? DEFAULT_DIGITS),
    period: String(options.periodSeconds ?? DEFAULT_PERIOD_SECONDS),
  });
  // encodeURIComponent, not URLSearchParams, for the label: the path segment
  // must keep its colon unescaped but escape the "@" in an email.
  return `otpauth://totp/${encodeURIComponent(label)}?${params.toString()}`;
}
