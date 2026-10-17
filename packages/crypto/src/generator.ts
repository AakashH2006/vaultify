/**
 * Cryptographically strong password generation.
 *
 * The subtle part is not "get random bytes" -- it is turning them into
 * characters without skewing the distribution. `randomValue % alphabet.length`
 * is the classic bug: unless the alphabet size divides 256 exactly, the first
 * `256 % length` characters come up slightly more often, and the password has
 * less entropy than the length suggests. We use rejection sampling instead.
 */

import { randomBytes } from "./encoding.ts";

export const CHARSETS = {
  lowercase: "abcdefghijklmnopqrstuvwxyz",
  uppercase: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.<>?",
} as const;

/** Characters that are easy to misread when a password is typed by hand. */
const AMBIGUOUS = new Set("Il1O0oB8S5Z2");

export interface PasswordOptions {
  length?: number;
  lowercase?: boolean;
  uppercase?: boolean;
  digits?: boolean;
  symbols?: boolean;
  /** Drop look-alike characters. Costs a little entropy, saves transcription errors. */
  excludeAmbiguous?: boolean;
}

const DEFAULTS: Required<PasswordOptions> = {
  length: 20,
  lowercase: true,
  uppercase: true,
  digits: true,
  symbols: true,
  excludeAmbiguous: false,
};

export const MIN_LENGTH = 8;
export const MAX_LENGTH = 128;

/**
 * Uniformly random integer in [0, max). Rejection sampling: draw a byte, discard
 * anything in the uneven tail, retry. The loop is unbounded in theory but
 * discards at most half the draws for any alphabet we use here.
 */
function randomInt(max: number): number {
  if (max <= 0 || max > 256) throw new RangeError("randomInt: max must be in (0, 256]");
  const limit = 256 - (256 % max); // largest multiple of max that fits in a byte
  for (;;) {
    const [byte] = randomBytes(1);
    if (byte < limit) return byte % max;
  }
}

function pick(alphabet: string): string {
  return alphabet[randomInt(alphabet.length)];
}

/** Fisher-Yates with an unbiased index source. */
function shuffle(items: string[]): string[] {
  for (let i = items.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [items[i], items[j]] = [items[j], items[i]];
  }
  return items;
}

export function generatePassword(options: PasswordOptions = {}): string {
  const config = { ...DEFAULTS, ...options };

  if (config.length < MIN_LENGTH || config.length > MAX_LENGTH) {
    throw new RangeError(
      "Password length must be between " + MIN_LENGTH + " and " + MAX_LENGTH,
    );
  }

  const pools: string[] = [];
  if (config.lowercase) pools.push(CHARSETS.lowercase);
  if (config.uppercase) pools.push(CHARSETS.uppercase);
  if (config.digits) pools.push(CHARSETS.digits);
  if (config.symbols) pools.push(CHARSETS.symbols);

  const filtered = (config.excludeAmbiguous
    ? pools.map((pool) => [...pool].filter((c) => !AMBIGUOUS.has(c)).join(""))
    : pools
  ).filter((pool) => pool.length > 0);

  if (filtered.length === 0) {
    throw new Error("generatePassword: at least one character class must be enabled");
  }
  if (config.length < filtered.length) {
    throw new RangeError("Password is too short to include every selected character class");
  }

  // One character from each class first, so the result always satisfies the
  // "must contain a digit/symbol" rules sites impose, then fill the rest from
  // the union and shuffle so the guaranteed characters are not at fixed spots.
  const union = filtered.join("");
  const chars = filtered.map(pick);
  while (chars.length < config.length) chars.push(pick(union));

  return shuffle(chars).join("");
}

/**
 * Entropy of the *generation process*, in bits -- length x log2(alphabet size).
 *
 * This is an upper bound and only honest for passwords this function produced.
 * It says nothing about a password a human invented, where the real entropy is
 * whatever it cost to guess the pattern, not the character count.
 */
export function entropyBits(options: PasswordOptions = {}): number {
  const config = { ...DEFAULTS, ...options };
  let alphabet = 0;
  const count = (set: string) =>
    config.excludeAmbiguous ? [...set].filter((c) => !AMBIGUOUS.has(c)).length : set.length;

  if (config.lowercase) alphabet += count(CHARSETS.lowercase);
  if (config.uppercase) alphabet += count(CHARSETS.uppercase);
  if (config.digits) alphabet += count(CHARSETS.digits);
  if (config.symbols) alphabet += count(CHARSETS.symbols);

  return alphabet === 0 ? 0 : config.length * Math.log2(alphabet);
}
