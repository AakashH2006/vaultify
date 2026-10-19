/**
 * In-memory store, for development and the test suite.
 *
 * It implements the same contract as the Postgres store, including the
 * optimistic-concurrency check, so the behavioural tests exercise real route
 * logic rather than a simplified stand-in. `loadConfig` refuses to let this run
 * in production.
 */

import type {
  AccountRecord,
  AuditEvent,
  NewAccount,
  NewAuditEvent,
  RotatedCredentials,
  SaveVaultResult,
  SessionRecord,
  Store,
  TotpEnrolment,
} from "./types.ts";

interface RecoveryCodeRow {
  readonly id: string;
  readonly accountId: string;
  readonly hash: string;
}

export class MemoryStore implements Store {
  readonly #accounts = new Map<string, AccountRecord>();
  readonly #sessions = new Map<string, SessionRecord>();
  readonly #recoveryCodes = new Map<string, RecoveryCodeRow>();
  readonly #audit: Array<AuditEvent & { accountId: string }> = [];
  #nextRecoveryCodeId = 1;

  readonly kind = "memory" as const;

  /** Always reachable: it is this process. */
  async ping(): Promise<void> {}

  async createAccount(account: NewAccount): Promise<AccountRecord | null> {
    if (this.#accounts.has(account.accountId)) return null;

    const record: AccountRecord = {
      ...account,
      vault: null,
      vaultRevision: 0,
      vaultUpdatedAt: null,
      createdAt: new Date().toISOString(),
      totpSecret: null,
      totpEnabled: false,
      totpLastStep: null,
      failedAttempts: 0,
      lockedUntil: null,
    };
    this.#accounts.set(account.accountId, record);
    return record;
  }

  async findAccount(accountId: string): Promise<AccountRecord | null> {
    return this.#accounts.get(accountId) ?? null;
  }

  async saveVault(
    accountId: string,
    vault: string,
    expectedRevision: number,
  ): Promise<SaveVaultResult> {
    const existing = this.#accounts.get(accountId);
    if (!existing) return { status: "no_such_account" };

    if (existing.vaultRevision !== expectedRevision) {
      return { status: "conflict", currentRevision: existing.vaultRevision };
    }

    const vaultUpdatedAt = new Date().toISOString();
    const vaultRevision = existing.vaultRevision + 1;
    this.#accounts.set(accountId, { ...existing, vault, vaultRevision, vaultUpdatedAt });
    return { status: "saved", vaultRevision, vaultUpdatedAt };
  }

  async rotateCredentials(
    accountId: string,
    credentials: RotatedCredentials,
  ): Promise<boolean> {
    const existing = this.#accounts.get(accountId);
    if (!existing) return false;
    this.#accounts.set(accountId, { ...existing, ...credentials });
    return true;
  }

  // -------------------------------------------------------------------------
  // Two-factor authentication
  // -------------------------------------------------------------------------

  async startTotpEnrolment(accountId: string, secret: string): Promise<boolean> {
    return this.#patch(accountId, { totpSecret: secret, totpEnabled: false, totpLastStep: null });
  }

  async enableTotp(accountId: string, enrolment: TotpEnrolment): Promise<boolean> {
    const existing = this.#accounts.get(accountId);
    if (!existing) return false;

    // Replacing the codes means dropping whatever was there. Re-running
    // enrolment must not leave an old set live alongside the new one.
    this.#deleteRecoveryCodes(accountId);
    for (const hash of enrolment.recoveryCodeHashes) {
      const id = String(this.#nextRecoveryCodeId++);
      this.#recoveryCodes.set(id, { id, accountId, hash });
    }

    this.#accounts.set(accountId, {
      ...existing,
      totpSecret: enrolment.secret,
      totpEnabled: true,
    });
    return true;
  }

  async disableTotp(accountId: string): Promise<boolean> {
    this.#deleteRecoveryCodes(accountId);
    return this.#patch(accountId, {
      totpSecret: null,
      totpEnabled: false,
      totpLastStep: null,
    });
  }

  async recordTotpStep(accountId: string, step: number): Promise<void> {
    this.#patch(accountId, { totpLastStep: step });
  }

  async listRecoveryCodeHashes(
    accountId: string,
  ): Promise<readonly { id: string; hash: string }[]> {
    return [...this.#recoveryCodes.values()]
      .filter((row) => row.accountId === accountId)
      .map((row) => ({ id: row.id, hash: row.hash }));
  }

  async consumeRecoveryCode(accountId: string, id: string): Promise<boolean> {
    const row = this.#recoveryCodes.get(id);
    if (!row || row.accountId !== accountId) return false;
    // Delete-and-report mirrors the Postgres `delete ... returning`, so two
    // concurrent redemptions of the same code cannot both succeed.
    return this.#recoveryCodes.delete(id);
  }

  #deleteRecoveryCodes(accountId: string): void {
    for (const [id, row] of this.#recoveryCodes) {
      if (row.accountId === accountId) this.#recoveryCodes.delete(id);
    }
  }

  // -------------------------------------------------------------------------
  // Lockout and audit
  // -------------------------------------------------------------------------

  async recordFailedAttempt(accountId: string, lockedUntil: string | null): Promise<number> {
    const existing = this.#accounts.get(accountId);
    if (!existing) return 0;
    const failedAttempts = existing.failedAttempts + 1;
    this.#accounts.set(accountId, { ...existing, failedAttempts, lockedUntil });
    return failedAttempts;
  }

  async clearFailedAttempts(accountId: string): Promise<void> {
    this.#patch(accountId, { failedAttempts: 0, lockedUntil: null });
  }

  async appendAuditEvent(event: NewAuditEvent): Promise<void> {
    this.#audit.push({ ...event, createdAt: new Date().toISOString() });
  }

  async listAuditEvents(accountId: string, limit: number): Promise<readonly AuditEvent[]> {
    return this.#audit
      .filter((row) => row.accountId === accountId)
      .slice(-limit)
      .reverse()
      .map(({ accountId: _ignored, ...event }) => event);
  }

  #patch(accountId: string, patch: Partial<AccountRecord>): boolean {
    const existing = this.#accounts.get(accountId);
    if (!existing) return false;
    this.#accounts.set(accountId, { ...existing, ...patch });
    return true;
  }

  async createSession(session: SessionRecord): Promise<void> {
    this.#sessions.set(session.sessionId, session);
  }

  async isSessionActive(sessionId: string): Promise<boolean> {
    const session = this.#sessions.get(sessionId);
    if (!session) return false;
    if (session.expiresAt.getTime() <= Date.now()) {
      this.#sessions.delete(sessionId);
      return false;
    }
    return true;
  }

  async revokeSession(sessionId: string): Promise<void> {
    this.#sessions.delete(sessionId);
  }

  async revokeAllSessions(accountId: string): Promise<void> {
    for (const [id, session] of this.#sessions) {
      if (session.accountId === accountId) this.#sessions.delete(id);
    }
  }

  async close(): Promise<void> {
    this.#accounts.clear();
    this.#sessions.clear();
    this.#recoveryCodes.clear();
    this.#audit.length = 0;
  }
}
