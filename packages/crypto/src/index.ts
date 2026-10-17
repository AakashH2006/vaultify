/**
 * @vaultify/crypto -- the entire trust boundary of the application.
 *
 * Nothing outside this package touches a key. If you are auditing Vaultify,
 * everything you need to read is in these six files; the API and the UI only
 * ever see opaque envelopes and already-derived handles.
 *
 * The module is pure Web Crypto, so the same code runs in the browser and under
 * Node's test runner -- the tests exercise the real primitives, not a mock.
 */

export {
  AES_ALGORITHM,
  CRYPTO_VERSION,
  IV_BYTES,
  KEY_BITS,
  PBKDF2_HASH,
  PBKDF2_ITERATIONS,
  PBKDF2_MIN_ITERATIONS,
  TAG_BITS,
} from "./constants.ts";

export {
  base64ToBytes,
  bytesToBase64,
  bytesToUtf8,
  constantTimeEqual,
  randomBytes,
  utf8ToBytes,
  zero,
  type Bytes,
} from "./encoding.ts";

export {
  DEFAULT_KDF_PARAMS,
  deriveKeys,
  deriveSalt,
  type DerivedKeys,
  type KdfParams,
} from "./kdf.ts";

export {
  ALG_LABEL,
  DecryptionError,
  decryptBytes,
  decryptString,
  deserialize,
  encryptBytes,
  encryptString,
  serialize,
  type Envelope,
} from "./cipher.ts";

export {
  changeMasterPassword,
  createAccount,
  decryptVault,
  encryptVault,
  unlockAccount,
  type AccountKeyRecord,
  type NewAccount,
  type UnlockedAccount,
} from "./vault.ts";

export {
  CHARSETS,
  MAX_LENGTH,
  MIN_LENGTH,
  entropyBits,
  generatePassword,
  type PasswordOptions,
} from "./generator.ts";

export {
  RecoveryKeyError,
  buildBackup,
  canOpen,
  decodeRecoveryKey,
  encodeRecoveryKey,
  parseBackup,
  recoveryKeyFromBase64,
  recoveryKeyFromRaw,
  recoveryKeyToBase64,
  vaultKeyFromRecoveryKey,
  type VaultBackup,
} from "./recovery.ts";

export {
  VAULT_SCHEMA_VERSION,
  emptyVault,
  type VaultContents,
  type VaultEntry,
} from "./types.ts";
