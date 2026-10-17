/**
 * Master-password strength, estimated honestly.
 *
 * This number matters more here than in most places. The master password is
 * the *only* thing between a stolen database and the user's entire credential
 * set, and no amount of server-side hardening compensates for a weak one.
 *
 * What this is: a search-space estimate, discounted for the patterns that make
 * a password far easier to guess than its character count suggests -- repeats,
 * runs, keyboard walks, dates, and a short list of passwords that appear at the
 * top of every breach corpus.
 *
 * What this is not: zxcvbn. A real estimator carries a dictionary of ~30k words
 * and n-gram tables, and would roughly double the download on the login path.
 * The gap is deliberate and worth stating: this will happily rate `Tr0ub4dor&3`
 * as strong when a dictionary-aware cracker breaks it quickly. It is a nudge
 * away from obviously bad choices, not a guarantee, and the UI says so.
 */

export interface Strength {
  /** Estimated bits of entropy against an attacker who knows our scheme. */
  readonly bits: number;
  readonly score: 0 | 1 | 2 | 3 | 4;
  readonly label: "very weak" | "weak" | "fair" | "strong" | "excellent";
  /** Concrete, actionable advice. Empty once the password is excellent. */
  readonly hints: string[];
}

/** Passwords so common that any cracker tries them in the first few thousand
 *  guesses. Not a dictionary -- just the floor. */
const TOP_PASSWORDS = new Set([
  "password", "123456", "123456789", "12345678", "qwerty", "abc123", "monkey",
  "letmein", "dragon", "111111", "baseball", "iloveyou", "trustno1", "sunshine",
  "master", "welcome", "shadow", "ashley", "football", "jesus", "michael",
  "ninja", "mustang", "password1", "qwerty123", "admin", "login", "passw0rd",
  "starwars", "whatever", "zaq12wsx", "superman", "hello", "freedom",
  "correct horse battery staple",
]);

const KEYBOARD_ROWS = [
  "`1234567890-=",
  "qwertyuiop[]\\",
  "asdfghjkl;'",
  "zxcvbnm,./",
];

const CLASSES: Array<[RegExp, number]> = [
  [/[a-z]/, 26],
  [/[A-Z]/, 26],
  [/[0-9]/, 10],
  [/[^a-zA-Z0-9]/, 33],
];

export function estimateStrength(password: string): Strength {
  if (password.length === 0) {
    return { bits: 0, score: 0, label: "very weak", hints: ["Enter a master password."] };
  }

  const normalised = password.toLowerCase();
  if (TOP_PASSWORDS.has(normalised)) {
    return {
      bits: 1,
      score: 0,
      label: "very weak",
      hints: ["This is one of the most-guessed passwords in existence. Pick anything else."],
    };
  }

  let alphabet = 0;
  for (const [pattern, size] of CLASSES) {
    if (pattern.test(password)) alphabet += size;
  }

  const unique = new Set(password).size;
  // Repetition does not add search space. Charge for distinct characters, with
  // the rest counted at a discount rather than free.
  const effectiveLength = unique + (password.length - unique) * 0.4;

  let bits = effectiveLength * Math.log2(Math.max(alphabet, 2));

  const hints: string[] = [];

  // A long string of lowercase words is a passphrase, and the per-character
  // estimate badly understates it. Credit words instead.
  const words = password.trim().split(/\s+/).filter((word) => word.length >= 3);
  if (words.length >= 3) {
    // ~11 bits per word is the conservative figure for a human-chosen word.
    bits = Math.max(bits, words.length * 11);
  }

  if (hasRun(password, 4)) {
    bits -= 12;
    hints.push("Avoid runs like `abcd` or `1234` — they are the first thing a cracker tries.");
  }
  if (hasRepeat(password, 3)) {
    bits -= 8;
    hints.push("Avoid repeated characters.");
  }
  if (hasKeyboardWalk(password, 4)) {
    bits -= 12;
    hints.push("Avoid keyboard patterns like `qwerty` or `asdf`.");
  }
  if (/(19|20)\d{2}/.test(password)) {
    bits -= 6;
    hints.push("A year is close to free for an attacker to guess.");
  }

  bits = Math.max(0, Math.round(bits));

  if (password.length < 12) {
    hints.unshift("Use at least 12 characters — length buys more than complexity does.");
  }
  if (alphabet <= 26 && words.length < 3) {
    hints.push("Mix in capitals, digits or symbols, or use several words.");
  }

  const { score, label } = grade(bits);
  if (score >= 4) hints.length = 0;

  return { bits, score, label, hints };
}

function grade(bits: number): { score: Strength["score"]; label: Strength["label"] } {
  if (bits < 36) return { score: 0, label: "very weak" };
  if (bits < 60) return { score: 1, label: "weak" };
  if (bits < 80) return { score: 2, label: "fair" };
  if (bits < 100) return { score: 3, label: "strong" };
  return { score: 4, label: "excellent" };
}

function hasRun(value: string, length: number): boolean {
  let ascending = 1;
  let descending = 1;
  for (let i = 1; i < value.length; i++) {
    const delta = value.charCodeAt(i) - value.charCodeAt(i - 1);
    ascending = delta === 1 ? ascending + 1 : 1;
    descending = delta === -1 ? descending + 1 : 1;
    if (ascending >= length || descending >= length) return true;
  }
  return false;
}

function hasRepeat(value: string, length: number): boolean {
  let run = 1;
  for (let i = 1; i < value.length; i++) {
    run = value[i] === value[i - 1] ? run + 1 : 1;
    if (run >= length) return true;
  }
  return false;
}

function hasKeyboardWalk(value: string, length: number): boolean {
  const lower = value.toLowerCase();
  for (const row of KEYBOARD_ROWS) {
    for (let start = 0; start + length <= row.length; start++) {
      const slice = row.slice(start, start + length);
      if (lower.includes(slice)) return true;
      if (lower.includes([...slice].reverse().join(""))) return true;
    }
  }
  return false;
}
