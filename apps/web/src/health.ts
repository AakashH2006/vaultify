/**
 * The vault health report: which stored passwords are actually a problem.
 *
 * All of this runs on decrypted entries inside the unlocked tab. Nothing here
 * talks to the network -- `breach.ts` does that separately, opt-in, and hands
 * its findings in as a map. Keeping the two apart means the report still works
 * entirely offline, with the breach column simply absent.
 *
 * The findings are ordered by what a user should fix first, which is not the
 * same as what is easiest to detect:
 *
 *   1. **Breached.** The password is in a public corpus. Credential-stuffing
 *      is automated and cheap; this is being attacked right now.
 *   2. **Reused.** One breach elsewhere compromises every site sharing it.
 *      This is the failure a password manager exists to prevent.
 *   3. **Weak.** Guessable, but only once someone targets that account.
 *   4. **Stale.** Age alone is not a vulnerability. Listed last, and
 *      deliberately quiet about it -- see the note on `STALE_DAYS`.
 */

import type { VaultEntry } from "@vaultify/crypto";
import { estimateStrength } from "./strength.ts";

export type FindingKind = "breached" | "reused" | "weak" | "stale";

export interface Finding {
  readonly kind: FindingKind;
  readonly entryId: string;
  readonly entryName: string;
  /** One line, specific enough to act on. */
  readonly detail: string;
  /** Sort key; lower is more urgent. */
  readonly severity: number;
}

export interface HealthReport {
  readonly findings: readonly Finding[];
  readonly checked: number;
  /** Entries with nothing wrong. */
  readonly healthy: number;
  readonly counts: Readonly<Record<FindingKind, number>>;
  /** True when a breach lookup contributed to this report. */
  readonly breachChecked: boolean;
}

/**
 * Rotation age. One year, and reported as information rather than as a
 * problem.
 *
 * Forced periodic rotation is discredited advice -- NIST dropped it in
 * SP 800-63B, because it pushes people towards predictable increments
 * (`spring2024`, `spring2025`) and buys nothing against an attacker who
 * already has the password. It is listed because "I have not touched this
 * since the breach I read about" is a real question, not because old
 * passwords are inherently unsafe.
 */
export const STALE_DAYS = 365;

/** Below "fair" in `estimateStrength` -- the same bar registration enforces. */
const WEAK_SCORE = 2;

const SEVERITY: Record<FindingKind, number> = {
  breached: 0,
  reused: 1,
  weak: 2,
  stale: 3,
};

export function buildHealthReport(
  entries: readonly VaultEntry[],
  options: {
    /** password -> number of times it appears in the breach corpus. A missing
     *  key means "not looked up", which is not the same as "clean". */
    breaches?: ReadonlyMap<string, number>;
    now?: number;
  } = {},
): HealthReport {
  const breaches = options.breaches;
  const now = options.now ?? Date.now();
  const findings: Finding[] = [];

  const reuseCounts = new Map<string, number>();
  for (const entry of entries) {
    if (!entry.password) continue;
    reuseCounts.set(entry.password, (reuseCounts.get(entry.password) ?? 0) + 1);
  }

  const flagged = new Set<string>();

  for (const entry of entries) {
    if (!entry.password) continue;

    const add = (kind: FindingKind, detail: string) => {
      findings.push({
        kind,
        entryId: entry.id,
        entryName: entry.name,
        detail,
        severity: SEVERITY[kind],
      });
      flagged.add(entry.id);
    };

    const breachCount = breaches?.get(entry.password);
    if (breachCount !== undefined && breachCount > 0) {
      add(
        "breached",
        breachCount === 1
          ? "This password appears once in a public breach corpus. Change it."
          : `This password appears ${formatCount(breachCount)} times in public breach corpora. Change it.`,
      );
    }

    const reused = reuseCounts.get(entry.password) ?? 0;
    if (reused > 1) {
      add("reused", `Used on ${reused} entries. One breach exposes all of them.`);
    }

    const strength = estimateStrength(entry.password);
    if (strength.score < WEAK_SCORE) {
      add("weak", `Rated ${strength.label} — about ${strength.bits} bits of entropy.`);
    }

    const age = ageInDays(entry.updatedAt, now);
    if (age !== null && age > STALE_DAYS) {
      add("stale", `Unchanged for ${Math.floor(age / 365)} year${age >= 730 ? "s" : ""}.`);
    }
  }

  findings.sort(
    (a, b) => a.severity - b.severity || a.entryName.localeCompare(b.entryName),
  );

  const counts: Record<FindingKind, number> = { breached: 0, reused: 0, weak: 0, stale: 0 };
  for (const finding of findings) counts[finding.kind]++;

  return {
    findings,
    checked: entries.length,
    healthy: entries.length - flagged.size,
    counts,
    breachChecked: breaches !== undefined && breaches.size > 0,
  };
}

function ageInDays(timestamp: string, now: number): number | null {
  const then = Date.parse(timestamp);
  if (Number.isNaN(then)) return null;
  return (now - then) / 86_400_000;
}

function formatCount(count: number): string {
  if (count >= 1_000_000) return `${Math.round(count / 100_000) / 10} million`;
  if (count >= 1_000) return `${Math.round(count / 100) / 10} thousand`;
  return String(count);
}

/** One-line summary for the dashboard badge. */
export function summarise(report: HealthReport): string {
  if (report.checked === 0) return "Nothing to check yet.";
  if (report.findings.length === 0) {
    return report.breachChecked
      ? "No problems found, and no password appears in a known breach."
      : "No reused or weak passwords.";
  }

  const parts: string[] = [];
  if (report.counts.breached) parts.push(`${report.counts.breached} breached`);
  if (report.counts.reused) parts.push(`${report.counts.reused} reused`);
  if (report.counts.weak) parts.push(`${report.counts.weak} weak`);
  if (report.counts.stale) parts.push(`${report.counts.stale} over a year old`);

  return parts.join(", ");
}
