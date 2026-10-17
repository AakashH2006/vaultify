/**
 * Auto-lock.
 *
 * An unlocked tab holds the vault key and every plaintext password in memory.
 * That is unavoidable -- it is the only place they can be -- but the window it
 * is true for should be as short as the user will tolerate. Auto-lock closes
 * that window on idle, on the tab being hidden, and on the access token
 * expiring.
 *
 * What locking actually does is drop references: the `CryptoKey` handle, the
 * decrypted vault, the access token. It is not a guarantee. JavaScript cannot
 * promise that the garbage collector has not already copied a string somewhere
 * unreachable, and the threat model says so plainly. What it does guarantee is
 * that the *application* can no longer read the vault without the master
 * password, so a left-open laptop is not an open vault.
 *
 * The clock is injected so this is testable without waiting out real minutes;
 * `test/autolock.test.ts` drives it with a fake one.
 */

export type LockReason = "idle" | "hidden" | "session-expired" | "manual";

export interface AutoLockOptions {
  /** Inactivity before locking. */
  idleMs: number;
  /**
   * Grace period after the tab is hidden. Short, but not zero: switching tabs
   * to copy a password somewhere is the single most common thing a user does
   * here, and locking instantly would make the app unusable.
   */
  hiddenGraceMs?: number;
  /** Absolute deadline, regardless of activity. Set from the token expiry. */
  expiresAt?: number | null;
  now?: () => number;
  onLock: (reason: LockReason) => void;
  /** Fired each tick while unlocked, with ms until the lock. Drives the UI countdown. */
  onTick?: (msRemaining: number, reason: LockReason) => void;
}

export const DEFAULT_IDLE_MS = 5 * 60 * 1000;
export const MIN_IDLE_MS = 30 * 1000;
export const MAX_IDLE_MS = 60 * 60 * 1000;
const DEFAULT_HIDDEN_GRACE_MS = 60 * 1000;

export class AutoLock {
  #idleMs: number;
  #hiddenGraceMs: number;
  #expiresAt: number | null;
  #now: () => number;
  #onLock: (reason: LockReason) => void;
  #onTick?: (msRemaining: number, reason: LockReason) => void;

  #lastActivity: number;
  #hiddenSince: number | null = null;
  #armed = false;

  constructor(options: AutoLockOptions) {
    this.#idleMs = clampIdle(options.idleMs);
    this.#hiddenGraceMs = options.hiddenGraceMs ?? DEFAULT_HIDDEN_GRACE_MS;
    this.#expiresAt = options.expiresAt ?? null;
    this.#now = options.now ?? Date.now;
    this.#onLock = options.onLock;
    this.#onTick = options.onTick;
    this.#lastActivity = this.#now();
  }

  /** Begin watching. Call on unlock. */
  arm(expiresAt?: number | null): void {
    this.#armed = true;
    this.#hiddenSince = null;
    this.#lastActivity = this.#now();
    if (expiresAt !== undefined) this.#expiresAt = expiresAt;
  }

  /** Stop watching, without firing. Call after locking by any route. */
  disarm(): void {
    this.#armed = false;
    this.#hiddenSince = null;
  }

  get armed(): boolean {
    return this.#armed;
  }

  get idleMs(): number {
    return this.#idleMs;
  }

  setIdleMs(ms: number): void {
    this.#idleMs = clampIdle(ms);
    this.#lastActivity = this.#now();
  }

  /** Any sign of a human: pointer, key, scroll, or a successful sync. */
  activity(): void {
    if (!this.#armed) return;
    this.#lastActivity = this.#now();
  }

  visibilityChanged(hidden: boolean): void {
    if (!this.#armed) return;
    if (hidden) {
      this.#hiddenSince ??= this.#now();
    } else {
      this.#hiddenSince = null;
      this.#lastActivity = this.#now();
    }
  }

  /**
   * Advance the clock. The caller ticks this on an interval; everything the
   * class decides is a pure function of the injected time, so the interval
   * being coarse or throttled by a background tab cannot be exploited -- a
   * throttled tab that wakes up late simply locks immediately.
   */
  tick(): void {
    if (!this.#armed) return;
    const now = this.#now();

    const deadlines: Array<[LockReason, number]> = [["idle", this.#lastActivity + this.#idleMs]];
    if (this.#hiddenSince !== null) {
      deadlines.push(["hidden", this.#hiddenSince + this.#hiddenGraceMs]);
    }
    if (this.#expiresAt !== null) {
      deadlines.push(["session-expired", this.#expiresAt]);
    }

    let soonest = deadlines[0];
    for (const candidate of deadlines) {
      if (candidate[1] < soonest[1]) soonest = candidate;
    }

    const [reason, deadline] = soonest;
    if (now >= deadline) {
      this.#armed = false;
      this.#onLock(reason);
      return;
    }
    this.#onTick?.(deadline - now, reason);
  }

  /** Lock now, by user request. */
  lockNow(): void {
    if (!this.#armed) return;
    this.#armed = false;
    this.#onLock("manual");
  }
}

function clampIdle(ms: number): number {
  if (!Number.isFinite(ms)) return DEFAULT_IDLE_MS;
  return Math.min(MAX_IDLE_MS, Math.max(MIN_IDLE_MS, Math.round(ms)));
}
