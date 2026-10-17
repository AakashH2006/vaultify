/**
 * Three-way merge of two divergent vaults.
 *
 * The server cannot do this. It holds one opaque ciphertext and has no way to
 * tell a reordered list from a deleted entry, so when two devices write from
 * the same revision it rejects the second with `409` and says nothing more.
 * Reconciling is the client's job, because the client is the only party that
 * can read either version.
 *
 * We have three documents to work from:
 *
 *   base    the vault as it stood when this tab last synced  (the common ancestor)
 *   mine    this tab's working copy, with the edit that just lost the race
 *   theirs  what the other device wrote, freshly downloaded
 *
 * Having `base` is what makes this a merge rather than a guess. Without it,
 * "this entry is in `theirs` but not in `mine`" is ambiguous -- did they add it,
 * or did I delete it? With it, the question is answerable.
 *
 * The one rule that decides every ambiguous case: **never silently lose a
 * credential.** A duplicate entry is a visible annoyance the user can fix in
 * two clicks. A password that quietly disappears may not be noticed until it is
 * needed, which is exactly when it cannot be recovered. So an edit always beats
 * a concurrent delete, and the losing side of a genuine field-level conflict is
 * preserved as a copy rather than discarded.
 */

import { VAULT_SCHEMA_VERSION, type VaultContents, type VaultEntry } from "@vaultify/crypto";

export interface MergeOutcome {
  readonly vault: VaultContents;
  /** Human-readable notes, surfaced in the UI so a merge is never invisible. */
  readonly notes: string[];
  /** True when the merge changed anything relative to `mine`. */
  readonly changed: boolean;
}

/** Fields whose divergence constitutes a real conflict. `updatedAt` is excluded:
 *  it is metadata about the edit, not content, and always differs. */
const CONTENT_FIELDS = [
  "name",
  "username",
  "password",
  "url",
  "notes",
  "totpSecret",
] as const;

function sameContent(a: VaultEntry, b: VaultEntry): boolean {
  return CONTENT_FIELDS.every((field) => (a[field] ?? "") === (b[field] ?? ""));
}

function byId(vault: VaultContents): Map<string, VaultEntry> {
  return new Map(vault.entries.map((entry) => [entry.id, entry]));
}

/** Later of two ISO timestamps, treating an unparseable one as "oldest". */
function newer(a: VaultEntry, b: VaultEntry): VaultEntry {
  const ta = Date.parse(a.updatedAt);
  const tb = Date.parse(b.updatedAt);
  if (Number.isNaN(ta)) return Number.isNaN(tb) ? a : b;
  if (Number.isNaN(tb)) return a;
  // A tie goes to `mine` -- the caller passes the local entry as `a`, and the
  // user is looking at it right now.
  return tb > ta ? b : a;
}

export function mergeVaults(
  base: VaultContents | null,
  mine: VaultContents,
  theirs: VaultContents,
): MergeOutcome {
  const baseEntries = base ? byId(base) : new Map<string, VaultEntry>();
  const myEntries = byId(mine);
  const theirEntries = byId(theirs);
  const notes: string[] = [];

  // Start from `theirs` and fold our side in. Iterating the remote order first
  // keeps the result stable for the device that is already in sync, and new
  // local entries land at the end where the user expects them.
  const merged: VaultEntry[] = [];
  const emitted = new Set<string>();

  const emit = (entry: VaultEntry) => {
    if (emitted.has(entry.id)) return;
    emitted.add(entry.id);
    merged.push(entry);
  };

  for (const their of theirs.entries) {
    const mineEntry = myEntries.get(their.id);
    const baseEntry = baseEntries.get(their.id);

    if (!mineEntry) {
      if (baseEntry && sameContent(baseEntry, their)) {
        // I deleted it; they left it untouched. The delete stands.
        continue;
      }
      if (baseEntry) {
        // I deleted it while they edited it. Keep it: a delete is cheap to
        // repeat, an edited password is not cheap to recreate.
        notes.push(`Kept "${their.name}" — another device edited it while this one deleted it.`);
      }
      emit(their);
      continue;
    }

    if (sameContent(mineEntry, their)) {
      emit(newer(mineEntry, their));
      continue;
    }

    if (baseEntry && sameContent(baseEntry, mineEntry)) {
      emit(their); // only they changed it
      continue;
    }
    if (baseEntry && sameContent(baseEntry, their)) {
      emit(mineEntry); // only I changed it
      continue;
    }

    // Both sides edited the same entry differently. Take the newer one and keep
    // the other as a visible copy rather than overwriting it into oblivion.
    const winner = newer(mineEntry, their);
    const loser = winner === mineEntry ? their : mineEntry;
    emit(winner);
    emit({ ...loser, id: conflictId(loser.id), name: `${loser.name} (conflicted copy)` });
    notes.push(`"${mineEntry.name}" was edited on two devices. Both versions were kept.`);
  }

  for (const mineEntry of mine.entries) {
    if (emitted.has(mineEntry.id)) continue;
    if (theirEntries.has(mineEntry.id)) continue;

    const baseEntry = baseEntries.get(mineEntry.id);
    if (baseEntry && sameContent(baseEntry, mineEntry)) {
      // They deleted it and I did not touch it. Their delete stands.
      continue;
    }
    if (baseEntry) {
      notes.push(`Kept "${mineEntry.name}" — another device deleted it while this one edited it.`);
    }
    emit(mineEntry);
  }

  const vault: VaultContents = {
    version: Math.max(mine.version, theirs.version, VAULT_SCHEMA_VERSION),
    entries: merged,
  };

  return { vault, notes, changed: !identical(mine, vault) };
}

/** A conflicted copy needs its own id, and one that is stable: re-running the
 *  same merge must not keep minting new entries. Derived from the original. */
function conflictId(id: string): string {
  return id.endsWith("-conflict") ? id : `${id}-conflict`;
}

function identical(a: VaultContents, b: VaultContents): boolean {
  if (a.entries.length !== b.entries.length) return false;
  return a.entries.every((entry, index) => {
    const other = b.entries[index];
    return entry.id === other.id && sameContent(entry, other);
  });
}
