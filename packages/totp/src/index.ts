/**
 * @vaultify/totp -- base32, TOTP and recovery codes.
 *
 * Kept out of @vaultify/crypto on purpose. That package's claim is that it is
 * the entire trust boundary and that six short files are all an auditor needs
 * to read; TOTP is a different concern with a different threat model -- it
 * protects *account access*, not the vault contents -- and folding it in would
 * dilute a claim worth keeping precise.
 *
 * Nothing here can decrypt a vault. A compromised TOTP secret lets an attacker
 * pass the second factor; it does not move them one step closer to the
 * plaintext, which still needs the master password.
 */

export {
  Base32Error,
  base32Decode,
  base32Encode,
  formatSecret,
  type Bytes,
} from "./base32.ts";

export {
  DEFAULT_DIGITS,
  DEFAULT_PERIOD_SECONDS,
  DEFAULT_WINDOW,
  SECRET_BYTES,
  generateSecret,
  hotp,
  otpauthUri,
  secondsRemaining,
  stepFor,
  totp,
  verifyTotp,
  type TotpOptions,
  type VerifyOptions,
  type VerifyResult,
} from "./totp.ts";

export {
  RECOVERY_CODE_COUNT,
  generateRecoveryCodes,
  looksLikeRecoveryCode,
  normaliseRecoveryCode,
} from "./recoveryCodes.ts";
