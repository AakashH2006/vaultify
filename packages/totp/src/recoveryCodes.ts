/**
 * Recovery codes -- the way back in when the phone is lost.
 *
 * Without these, enabling 2FA on a password manager is a loaded gun: a dropped
 * phone means the vault is unreachable even though the user still knows their
 * master password perfectly well. And unlike a forgotten master password,
 * that loss would be *our* design's fault rather than an unavoidable
 * consequence of zero knowledge.
 *
 * Note what a recovery code is and is not. It replaces the **second** factor,
 * not the first: using one still requires the master password, because the
 * master password is the only thing that can derive the keys. So a leaked
 * recovery code puts an attacker exactly where they would have been before
 * 2FA was turned on, and no further. That is why they can be shown once and
 * written on paper without it being reckless.
 *
 * Each code carries 10 base32 characters, which is 50 bits. Ten of them are
 * issued, each usable once, and the server stores only scrypt hashes.
 */

import { base32Encode, type Bytes } from "./base32.ts";

export const RECOVERY_CODE_COUNT = 10;
/** 50 bits each. Long enough that guessing is hopeless, short enough to type. */
const CODE_BYTES = 7;
const CODE_LENGTH = 10;

/**
 * Codes are displayed as `XXXXX-XXXXX`. The hyphen is cosmetic -- it makes a
 * code easier to transcribe and easier to recognise on a page of notes -- and
 * `normaliseRecoveryCode` strips it, so a user who types it either way is fine.
 */
export function generateRecoveryCodes(count = RECOVERY_CODE_COUNT): string[] {
  const codes: string[] = [];
  for (let i = 0; i < count; i++) {
    const raw: Bytes = new Uint8Array(CODE_BYTES);
    crypto.getRandomValues(raw);
    const encoded = base32Encode(raw).slice(0, CODE_LENGTH);
    codes.push(`${encoded.slice(0, 5)}-${encoded.slice(5)}`);
  }
  return codes;
}

/**
 * Canonical form for comparison: upper case, no separators.
 *
 * Both the enrolment path and the redemption path must call this, or a code
 * typed with the hyphen will not match a hash taken without it -- a failure
 * that looks like "your recovery codes do not work" at the worst moment.
 */
export function normaliseRecoveryCode(code: string): string {
  return code.replace(/[\s-]/g, "").toUpperCase();
}

/** Shape check before spending a scrypt verification on it. Cheap filter for
 *  obvious nonsense; it says nothing about whether the code is valid. */
export function looksLikeRecoveryCode(code: string): boolean {
  return /^[A-Z2-7]{10}$/.test(normaliseRecoveryCode(code));
}
