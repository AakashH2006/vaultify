/**
 * The unlocked session: the only object in the application that holds anything
 * secret, and the only one that can read the vault.
 *
 * Two rules govern everything below.
 *
 * **Nothing secret is ever persisted.** No localStorage, no sessionStorage, no
 * cookie, no IndexedDB. The vault key, the decrypted entries and the access
 * token exist as fields on one object; dropping that object is what "lock"
 * means. The cost is honest and visible: a page refresh asks for the master
 * password again. The alternative -- keeping a key where a later page load can
 * find it -- hands the vault to any XSS that lands on the origin, including one
 * that lands tomorrow.
 *
 * **A write never silently loses a credential.** save() is a compare-and-set
 * against the server's revision; on 409 it re-reads, merges three-way (see
 * merge.ts), and retries. The merge is reported back to the caller so the UI
 * can tell the user what happened.
 */

import {
  DEFAULT_KDF_PARAMS,
  buildBackup,
  changeMasterPassword,
  createAccount,
  decryptVault,
  deriveKeys,
  deserialize,
  emptyVault,
  encryptVault,
  serialize,
  unlockAccount,
  type AccountKeyRecord,
  type KdfParams,
  type VaultContents,
  type VaultEntry,
} from "@vaultify/crypto";

import { ApiError, toKeyRecord, type ApiClient, type TwoFactorStatus } from "./api.ts";
import { mergeVaults, type MergeOutcome } from "./merge.ts";

export interface SaveResult {
  readonly revision: number;
  /** Set when a concurrent write forced a merge. The UI surfaces these. */
  readonly mergeNotes: string[];
}

/** How many times a losing write re-reads and retries before giving up. Three
 *  is enough for any realistic contention; an unbounded loop against a server
 *  that is wrong about something would spin forever. */
const MAX_SYNC_ATTEMPTS = 3;

export class VaultSession {
  readonly accountId: string;
  readonly #api: ApiClient;

  #accessToken: string;
  #vaultKey: CryptoKey;
  #keyRecord: AccountKeyRecord;

  /** The working copy the UI edits. */
  #vault: VaultContents;
  /** The last state known to match the server -- the merge base. */
  #base: VaultContents;
  #revision: number;
  #expiresAt: number;
  #locked = false;
  #twoFactor: TwoFactorStatus;

  /**
   * The recovery kit, held only between registration and the user dismissing
   * the screen that shows it. Cleared by `forgetRecoveryKey()`, and by `lock`
   * like everything else.
   */
  #recoveryKey: string | null = null;

  private constructor(init: {
    api: ApiClient;
    accountId: string;
    accessToken: string;
    expiresIn: number;
    vaultKey: CryptoKey;
    keyRecord: AccountKeyRecord;
    vault: VaultContents;
    revision: number;
    twoFactor: TwoFactorStatus;
    recoveryKey?: string | null;
  }) {
    this.#api = init.api;
    this.accountId = init.accountId;
    this.#accessToken = init.accessToken;
    this.#vaultKey = init.vaultKey;
    this.#keyRecord = init.keyRecord;
    this.#vault = init.vault;
    this.#base = clone(init.vault);
    this.#revision = init.revision;
    this.#expiresAt = Date.now() + init.expiresIn * 1000;
    this.#twoFactor = init.twoFactor;
    this.#recoveryKey = init.recoveryKey ?? null;
  }

  // -------------------------------------------------------------------------
  // Opening a session
  // -------------------------------------------------------------------------

  /**
   * Sign up. Note the ordering: the keys are generated and the vault key is
   * wrapped *before* the first byte goes to the server, so a registration
   * request that never arrives leaks nothing.
   */
  static async register(
    api: ApiClient,
    email: string,
    masterPassword: string,
  ): Promise<VaultSession> {
    const accountId = normaliseEmail(email);
    // The recovery kit is requested here and nowhere else. The raw vault key
    // exists for exactly this moment in an account's life; after registration
    // there is no way to produce it again, which is the property that makes
    // the kit meaningful rather than a second server-held credential.
    const account = await createAccount(accountId, masterPassword, DEFAULT_KDF_PARAMS, {
      exportRecoveryKey: true,
    });

    const response = await api.register({
      accountId,
      authKey: account.authKey,
      kdf: account.keyRecord.kdf,
      protectedVaultKey: serialize(account.keyRecord.protectedVaultKey),
    });

    return new VaultSession({
      api,
      accountId,
      accessToken: response.accessToken,
      expiresIn: response.expiresIn,
      vaultKey: account.vaultKey,
      keyRecord: account.keyRecord,
      vault: emptyVault(),
      revision: response.vaultRevision,
      twoFactor: response.twoFactor ?? { enabled: false, recoveryCodesRemaining: 0 },
      recoveryKey: account.recoveryKey ?? null,
    });
  }

  /**
   * Log in and unlock, in that order, and note that they are different things.
   * The server decides whether the auth key is right; only the client can
   * decide whether the master password is right, by trying to unwrap the vault
   * key with it. Both derive from the same password, so in practice a wrong
   * password fails at the server first -- but the unwrap below is the check
   * that actually matters, and it happens here, on this machine.
   */
  static async unlock(
    api: ApiClient,
    email: string,
    masterPassword: string,
    second: { totpCode?: string; recoveryCode?: string } = {},
  ): Promise<VaultSession> {
    const accountId = normaliseEmail(email);

    const { kdf } = await api.prelogin(accountId);
    const authKey = await deriveAuthKey(accountId, masterPassword, kdf);

    // A `totp_required` error from here is the server saying the password was
    // right and a second factor is outstanding. The caller catches it and
    // re-runs this with a code -- which costs another full key derivation,
    // and is still the correct trade: holding a derived auth key in memory
    // across a user-facing prompt is a worse place for it to live.
    const response = await api.login(accountId, authKey, second);
    const keyRecord = toKeyRecord(response.keyRecord, deserialize);
    const unlocked = await unlockAccount(masterPassword, keyRecord);

    const remote = await api.getVault(response.accessToken);
    const vault = remote.vault
      ? await decryptVault(unlocked.vaultKey, deserialize(remote.vault), accountId)
      : emptyVault();

    return new VaultSession({
      api,
      accountId,
      accessToken: response.accessToken,
      expiresIn: response.expiresIn,
      vaultKey: unlocked.vaultKey,
      keyRecord,
      vault,
      revision: remote.vaultRevision,
      twoFactor: response.twoFactor ?? { enabled: false, recoveryCodesRemaining: 0 },
    });
  }

  // -------------------------------------------------------------------------
  // Reading
  // -------------------------------------------------------------------------

  get locked(): boolean {
    return this.#locked;
  }

  get revision(): number {
    return this.#revision;
  }

  get expiresAt(): number {
    return this.#expiresAt;
  }

  get twoFactor(): TwoFactorStatus {
    return this.#twoFactor;
  }

  /** Present only immediately after registration. */
  get recoveryKey(): string | null {
    return this.#recoveryKey;
  }

  /** Drop the kit once the user says they have saved it. */
  forgetRecoveryKey(): void {
    this.#recoveryKey = null;
  }

  /** The bearer token, for the few calls the session does not wrap itself. */
  get accessToken(): string {
    this.#assertUnlocked();
    return this.#accessToken;
  }

  async refreshTwoFactor(): Promise<TwoFactorStatus> {
    this.#assertUnlocked();
    this.#twoFactor = await this.#api.twoFactorStatus(this.#accessToken);
    return this.#twoFactor;
  }

  /**
   * Re-derive the auth key from the master password, for the operations that
   * demand proof of it on top of a live session -- disabling 2FA, and the
   * password change. Never cached: the point is that it is produced from a
   * password the user just typed, not from something sitting in memory.
   */
  deriveAuthKey(masterPassword: string): Promise<string> {
    this.#assertUnlocked();
    return deriveAuthKey(this.accountId, masterPassword, this.#keyRecord.kdf);
  }

  /**
   * An encrypted backup file, exactly as the server would store it.
   *
   * Pairs with the recovery kit: the kit alone proves nothing without a blob
   * to open, and the blob alone is ciphertext. Together they are a copy of
   * the vault that survives this service disappearing entirely.
   */
  async exportBackup(): Promise<{ filename: string; contents: string }> {
    this.#assertUnlocked();
    const sealed = await encryptVault(this.#vaultKey, this.#vault, this.accountId);
    const backup = buildBackup(this.accountId, serialize(sealed));
    const stamp = new Date().toISOString().slice(0, 10);
    return {
      filename: `vaultify-backup-${stamp}.json`,
      contents: JSON.stringify(backup, null, 2),
    };
  }

  /** The live entry list. Callers must not mutate it -- use the methods below,
   *  which keep updatedAt honest and the merge base intact. */
  get entries(): readonly VaultEntry[] {
    this.#assertUnlocked();
    return this.#vault.entries;
  }

  /** True when the working copy differs from what the server has. */
  get dirty(): boolean {
    if (this.#locked) return false;
    return JSON.stringify(this.#vault) !== JSON.stringify(this.#base);
  }

  // -------------------------------------------------------------------------
  // Editing. These touch memory only; save() is what reaches the network.
  // -------------------------------------------------------------------------

  addEntry(draft: Omit<VaultEntry, "id" | "createdAt" | "updatedAt">): VaultEntry {
    this.#assertUnlocked();
    const now = new Date().toISOString();
    const entry: VaultEntry = {
      ...draft,
      id: crypto.randomUUID(),
      createdAt: now,
      updatedAt: now,
    };
    this.#vault.entries.push(entry);
    return entry;
  }

  updateEntry(id: string, patch: Partial<Omit<VaultEntry, "id" | "createdAt">>): VaultEntry {
    this.#assertUnlocked();
    const index = this.#vault.entries.findIndex((entry) => entry.id === id);
    if (index === -1) throw new Error("No such entry");
    const updated: VaultEntry = {
      ...this.#vault.entries[index],
      ...patch,
      updatedAt: new Date().toISOString(),
    };
    this.#vault.entries[index] = updated;
    return updated;
  }

  deleteEntry(id: string): void {
    this.#assertUnlocked();
    this.#vault.entries = this.#vault.entries.filter((entry) => entry.id !== id);
  }

  // -------------------------------------------------------------------------
  // Syncing
  // -------------------------------------------------------------------------

  /**
   * Seal the working copy and push it, resolving a lost race by merging rather
   * than by overwriting. Returns the notes from any merge so the UI can show
   * them -- silently reconciling two devices is how a user ends up not noticing
   * that an entry grew a conflicted copy.
   */
  async save(): Promise<SaveResult> {
    this.#assertUnlocked();
    const notes: string[] = [];

    for (let attempt = 1; attempt <= MAX_SYNC_ATTEMPTS; attempt++) {
      const sealed = await encryptVault(this.#vaultKey, this.#vault, this.accountId);

      try {
        const result = await this.#api.putVault(
          this.#accessToken,
          serialize(sealed),
          this.#revision,
        );
        this.#revision = result.vaultRevision;
        this.#base = clone(this.#vault);
        return { revision: this.#revision, mergeNotes: notes };
      } catch (error) {
        if (!(error instanceof ApiError) || error.code !== "conflict") throw error;
        if (attempt === MAX_SYNC_ATTEMPTS) throw error;

        const outcome = await this.#reconcile();
        notes.push(...outcome.notes);
      }
    }

    // Unreachable: the loop either returns or throws.
    throw new ApiError("conflict", 409, "Could not sync after repeated conflicts");
  }

  /** Pull the newer vault and fold our edits into it. */
  async #reconcile(): Promise<MergeOutcome> {
    const remote = await this.#api.getVault(this.#accessToken);
    const theirs = remote.vault
      ? await decryptVault(this.#vaultKey, deserialize(remote.vault), this.accountId)
      : emptyVault();

    const outcome = mergeVaults(this.#base, this.#vault, theirs);
    this.#vault = outcome.vault;
    this.#revision = remote.vaultRevision;
    // The base is now what the server holds, not what we are about to write.
    this.#base = clone(theirs);
    return outcome;
  }

  /** Pull without a pending write -- used by the manual refresh button. */
  async refresh(): Promise<MergeOutcome> {
    this.#assertUnlocked();
    return this.#reconcile();
  }

  // -------------------------------------------------------------------------
  // Credentials
  // -------------------------------------------------------------------------

  /**
   * Rotate the master password. The vault ciphertext is not touched -- only the
   * 32-byte wrapped vault key is re-wrapped and uploaded. The server then
   * revokes every session including this one, so the caller must lock and send
   * the user back to the unlock screen.
   */
  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    this.#assertUnlocked();

    // Flush pending edits first. A password change invalidates this session, so
    // anything unsaved would be lost at the redirect.
    if (this.dirty) await this.save();

    const rotated = await changeMasterPassword(
      currentPassword,
      newPassword,
      this.#keyRecord,
      DEFAULT_KDF_PARAMS,
    );
    const currentAuthKey = await deriveAuthKey(
      this.accountId,
      currentPassword,
      this.#keyRecord.kdf,
    );

    await this.#api.changePassword(this.#accessToken, {
      currentAuthKey,
      newAuthKey: rotated.authKey,
      kdf: rotated.keyRecord.kdf,
      protectedVaultKey: serialize(rotated.keyRecord.protectedVaultKey),
    });

    this.lock();
  }

  /** Tell the server to revoke the session, then drop everything locally.
   *  Local teardown happens even if the network call fails -- a server we
   *  cannot reach is no reason to leave a decrypted vault in the tab. */
  async signOut(): Promise<void> {
    const token = this.#accessToken;
    this.lock();
    try {
      await this.#api.logout(token);
    } catch {
      // Already locked locally; the token expires on its own.
    }
  }

  /**
   * Drop every secret this object holds.
   *
   * Overwriting the fields is best-effort and we say so: the strings may
   * already have been copied by the garbage collector, and CryptoKey material
   * lives outside JavaScript's reach entirely. What this *does* guarantee is
   * that the application has no path back to the plaintext without the master
   * password.
   */
  lock(): void {
    if (this.#locked) return;
    this.#locked = true;
    for (const entry of this.#vault.entries) {
      entry.password = "";
      entry.notes = "";
      entry.totpSecret = "";
    }
    this.#vault = emptyVault();
    this.#base = emptyVault();
    this.#accessToken = "";
    this.#recoveryKey = null;
    this.#vaultKey = undefined as unknown as CryptoKey;
    this.#keyRecord = undefined as unknown as AccountKeyRecord;
  }

  #assertUnlocked(): void {
    if (this.#locked) throw new Error("The vault is locked.");
  }
}

/** Derive the auth key alone, without unwrapping anything. Used where we must
 *  prove knowledge of a password we are not unlocking with. */
async function deriveAuthKey(
  accountId: string,
  masterPassword: string,
  kdf: KdfParams,
): Promise<string> {
  const { authKey } = await deriveKeys(accountId, masterPassword, kdf);
  return authKey;
}

/** Must match the server's normalisation exactly. If the two ever disagree the
 *  salt changes and the derived keys silently stop matching -- a failure that
 *  looks like "wrong password" and is nearly impossible to diagnose. */
export function normaliseEmail(email: string): string {
  return email.trim().toLowerCase();
}

function clone(vault: VaultContents): VaultContents {
  return structuredClone(vault);
}
