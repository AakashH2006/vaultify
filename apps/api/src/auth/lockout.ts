/**
 * Progressive lockout, layered under the fixed-window rate limiter.
 *
 * The two do different jobs and both are needed.
 *
 * The rate limiter is per-process, in memory, and keyed on IP *and* account.
 * It stops a burst. It also forgets everything on restart, and behind several
 * API nodes each one enforces its own share -- so a patient attacker spread
 * across hosts, or one that waits out each 15-minute window, walks straight
 * through it.
 *
 * This is per-account, lives in the database, survives restarts, and grows
 * with each consecutive failure. It is what makes a slow grind expensive.
 *
 * The backoff doubles and then stops: 1, 2, 4, 8, 15, 15, 15 minutes. It is
 * capped on purpose. An uncapped lockout is a denial-of-service someone can
 * aim at a victim by failing their login on a schedule -- and locking the
 * real owner out of their password vault is a serious harm, not a minor
 * inconvenience. Fifteen minutes slows a grind to roughly 400 guesses a year
 * while keeping the worst an attacker can inflict to a quarter of an hour.
 */

/** Failures tolerated before any lockout. Fat-fingering a passphrase twice is
 *  normal; five times is not. */
export const FREE_ATTEMPTS = 4;

const BACKOFF_MINUTES = [1, 2, 4, 8, 15] as const;

export interface LockoutState {
  readonly lockedUntil: string | null;
}

/**
 * How long to lock after `consecutiveFailures` failed attempts, in ms.
 * Returns 0 while the account is still inside its free allowance.
 */
export function lockoutDurationMs(consecutiveFailures: number): number {
  if (consecutiveFailures <= FREE_ATTEMPTS) return 0;
  const index = Math.min(consecutiveFailures - FREE_ATTEMPTS - 1, BACKOFF_MINUTES.length - 1);
  return BACKOFF_MINUTES[index] * 60_000;
}

/** The timestamp to store after a failure, or null if no lock applies yet. */
export function lockoutUntil(consecutiveFailures: number, now = Date.now()): string | null {
  const duration = lockoutDurationMs(consecutiveFailures);
  return duration === 0 ? null : new Date(now + duration).toISOString();
}

/** Seconds remaining on a lock, or 0 if it has expired or was never set. */
export function secondsRemaining(lockedUntil: string | null, now = Date.now()): number {
  if (!lockedUntil) return 0;
  const until = Date.parse(lockedUntil);
  if (Number.isNaN(until)) return 0;
  return Math.max(0, Math.ceil((until - now) / 1000));
}

export function isLockedOut(state: LockoutState, now = Date.now()): boolean {
  return secondsRemaining(state.lockedUntil, now) > 0;
}
