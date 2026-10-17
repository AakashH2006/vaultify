/**
 * The storage contract.
 *
 * Note what is *not* in these types: no plaintext, no master password, no
 * encryption key. Every secret-bearing field here is either a slow hash
 * (`authKeyHash`) or a ciphertext envelope the server cannot open
 * (`protectedVaultKey`, `vault`). That is the whole point of the architecture,
 * and keeping the interface this narrow is what makes it easy to verify.
 */

export interface KdfParams {
  readonly algorithm: "PBKDF2";
  readonly iterations: number;
}

export interface AccountRecord {
  readonly accountId: string;
  /** scrypt hash of the client's auth key. Never the auth key itself. */
  readonly authKeyHash: string;
  readonly kdf: KdfParams;
  /** Serialized envelope: the vault key wrapped under the client's wrapping key. */
  readonly protectedVaultKey: string;
  /** Serialized envelope, or null before the first sync. */
  readonly vault: string | null;
  /** Incremented on every successful write. Drives optimistic concurrency. */
  readonly vaultRevision: number;
  readonly vaultUpdatedAt: string | null;
  readonly createdAt: string;

  /**
   * Base32 TOTP seed. Present once setup has started, which is not the same as
   * 2FA being on -- `totpEnabled` is only set after the user proves they can
   * generate a code from it.
   *
   * This is the one genuinely usable secret the server holds. It guards
   * account access, not vault contents: see the note in schema.sql.
   */
  readonly totpSecret: string | null;
  readonly totpEnabled: boolean;
  /** Last TOTP step spent, so a code cannot be used twice inside its window. */
  readonly totpLastStep: number | null;

  /** Consecutive failed credential attempts, for the progressive lockout. */
  readonly failedAttempts: number;
  /** When set and in the future, credential routes refuse this account. */
  readonly lockedUntil: string | null;
}

/** What `GET /api/auth/activity` returns, and all the server ever keeps about
 *  how an account is used. Both `ipPrefix` and `client` are deliberately
 *  coarse -- see schema.sql. */
export interface AuditEvent {
  readonly event: string;
  readonly succeeded: boolean;
  readonly ipPrefix: string | null;
  readonly client: string | null;
  readonly createdAt: string;
}

export interface NewAuditEvent {
  readonly accountId: string;
  readonly event: string;
  readonly succeeded: boolean;
  readonly ipPrefix: string | null;
  readonly client: string | null;
}

export interface TotpEnrolment {
  readonly secret: string;
  /** scrypt hashes of the single-use recovery codes. */
  readonly recoveryCodeHashes: readonly string[];
}

export interface NewAccount {
  readonly accountId: string;
  readonly authKeyHash: string;
  readonly kdf: KdfParams;
  readonly protectedVaultKey: string;
}

export interface RotatedCredentials {
  readonly authKeyHash: string;
  readonly kdf: KdfParams;
  readonly protectedVaultKey: string;
}

export interface SavedVault {
  readonly vaultRevision: number;
  readonly vaultUpdatedAt: string;
}

/** `saveVault` outcomes, as data rather than exceptions, so routes handle each
 *  case explicitly instead of pattern-matching on error messages. */
export type SaveVaultResult =
  | ({ readonly status: "saved" } & SavedVault)
  | { readonly status: "conflict"; readonly currentRevision: number }
  | { readonly status: "no_such_account" };

export interface SessionRecord {
  readonly sessionId: string;
  readonly accountId: string;
  readonly expiresAt: Date;
}

export interface Store {
  /** Resolves to null when the account id is already taken. */
  createAccount(account: NewAccount): Promise<AccountRecord | null>;
  findAccount(accountId: string): Promise<AccountRecord | null>;

  /**
   * Writes the vault only if `expectedRevision` matches what is stored.
   *
   * Without this check, two tabs that both decrypt, edit and re-upload would
   * silently clobber each other -- and because the server cannot read either
   * blob, it could never merge them or even notice. Last-write-wins on an
   * opaque ciphertext means permanent, invisible data loss.
   */
  saveVault(
    accountId: string,
    vault: string,
    expectedRevision: number,
  ): Promise<SaveVaultResult>;

  /** Master-password change: new auth key hash, KDF params and rewrapped vault
   *  key land together or not at all. The vault ciphertext is untouched. */
  rotateCredentials(accountId: string, credentials: RotatedCredentials): Promise<boolean>;

  // -------------------------------------------------------------------------
  // Two-factor authentication
  // -------------------------------------------------------------------------

  /** Stash a secret from `2fa/setup`. 2FA is NOT on until `enableTotp`. */
  startTotpEnrolment(accountId: string, secret: string): Promise<boolean>;

  /**
   * Turn 2FA on and replace the recovery codes, atomically. Both halves must
   * land together: codes without 2FA are harmless clutter, but 2FA without
   * codes locks a user out of their own vault the moment they lose the phone.
   */
  enableTotp(accountId: string, enrolment: TotpEnrolment): Promise<boolean>;

  /** Turn 2FA off and discard the secret and every remaining recovery code. */
  disableTotp(accountId: string): Promise<boolean>;

  /** Record the step a successful code belonged to, so it cannot be replayed. */
  recordTotpStep(accountId: string, step: number): Promise<void>;

  /** Hashes of the codes still unspent, for verification. */
  listRecoveryCodeHashes(accountId: string): Promise<readonly { id: string; hash: string }[]>;

  /** Spend one. Returns false if it was already spent -- which is the race
   *  that matters, two tabs redeeming the same code at once. */
  consumeRecoveryCode(accountId: string, id: string): Promise<boolean>;

  // -------------------------------------------------------------------------
  // Lockout and audit
  // -------------------------------------------------------------------------

  /** Bump the consecutive-failure counter and apply the backoff. Returns the
   *  new count so the caller can log it. */
  recordFailedAttempt(accountId: string, lockedUntil: string | null): Promise<number>;

  /** Clear the counter after a success. */
  clearFailedAttempts(accountId: string): Promise<void>;

  appendAuditEvent(event: NewAuditEvent): Promise<void>;
  listAuditEvents(accountId: string, limit: number): Promise<readonly AuditEvent[]>;

  createSession(session: SessionRecord): Promise<void>;
  isSessionActive(sessionId: string): Promise<boolean>;
  revokeSession(sessionId: string): Promise<void>;
  /** Used on password change: every other device must re-authenticate. */
  revokeAllSessions(accountId: string): Promise<void>;

  close(): Promise<void>;
}
