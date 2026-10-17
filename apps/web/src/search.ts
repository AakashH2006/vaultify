/**
 * Filtering and ordering for the vault list.
 *
 * Pure, and kept out of the view for one reason beyond testability: the
 * password field is deliberately *not* searchable. Matching on it would let a
 * shoulder-surfer or a screenshot narrow a password down a character at a time
 * by watching which rows survive each keystroke. Names, usernames, URLs and
 * notes are fair game; the secret is not.
 */

import type { VaultEntry } from "@vaultify/crypto";

export type SortOrder = "name" | "recent" | "created";

const SEARCHABLE = ["name", "username", "url", "notes"] as const;

export function filterEntries(entries: readonly VaultEntry[], query: string): VaultEntry[] {
  const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (terms.length === 0) return [...entries];

  return entries.filter((entry) => {
    const haystack = SEARCHABLE.map((field) => entry[field] ?? "")
      .join("\n")
      .toLowerCase();
    // Every term must appear somewhere. Typing more words narrows the list,
    // which is what a person expects from a search box.
    return terms.every((term) => haystack.includes(term));
  });
}

export function sortEntries(entries: VaultEntry[], order: SortOrder): VaultEntry[] {
  const sorted = [...entries];
  switch (order) {
    case "name":
      return sorted.sort((a, b) =>
        a.name.localeCompare(b.name, undefined, { sensitivity: "base" }),
      );
    case "recent":
      return sorted.sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
    case "created":
      return sorted.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  }
}

/** Host of an entry's URL, for the row subtitle. Returns null rather than
 *  throwing on the many things users paste into a URL field. */
export function hostOf(url: string | undefined): string | null {
  if (!url) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`;
  try {
    return new URL(candidate).host || null;
  } catch {
    return null;
  }
}

/**
 * A link we are willing to render. Anything that is not http(s) is refused --
 * `javascript:` in an entry's URL field would otherwise be a stored XSS with
 * the vault key in scope, and `data:` is nearly as bad.
 */
export function safeHref(url: string | undefined): string | null {
  if (!url) return null;
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(url) ? url : `https://${url}`;
  try {
    const parsed = new URL(candidate);
    return parsed.protocol === "http:" || parsed.protocol === "https:" ? parsed.href : null;
  } catch {
    return null;
  }
}

/** Initials for the avatar tile. Falls back to a bullet for an unnamed entry. */
export function initials(name: string): string {
  const words = name.trim().split(/\s+/).filter(Boolean);
  if (words.length === 0) return "•";
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}
