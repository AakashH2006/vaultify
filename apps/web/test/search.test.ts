/**
 * Search, sorting, and the two URL helpers.
 *
 * `safeHref` is the one here that is a security control rather than a
 * convenience: an entry's URL field is attacker-influenced data rendered into
 * an `href` inside a tab that holds the vault key. The tests below are the
 * payloads that control exists to refuse.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import type { VaultEntry } from "@vaultify/crypto";
import { filterEntries, hostOf, initials, safeHref, sortEntries } from "../src/search.ts";

function entry(overrides: Partial<VaultEntry> & { id: string }): VaultEntry {
  return {
    name: overrides.id,
    username: "",
    password: "hunter2",
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

const entries: VaultEntry[] = [
  entry({ id: "1", name: "GitHub", username: "ada", url: "https://github.com", updatedAt: "2026-03-01T00:00:00.000Z", createdAt: "2026-01-03T00:00:00.000Z" }),
  entry({ id: "2", name: "bank of somewhere", username: "ada@example.com", notes: "sort code 00-00-00", updatedAt: "2026-02-01T00:00:00.000Z", createdAt: "2026-01-01T00:00:00.000Z" }),
  entry({ id: "3", name: "Αθήνα Energy", username: "lovelace", url: "energy.example.gr", updatedAt: "2026-01-15T00:00:00.000Z", createdAt: "2026-01-02T00:00:00.000Z" }),
];

const ids = (list: VaultEntry[]) => list.map((item) => item.id);

describe("filterEntries", () => {
  it("returns everything for an empty query", () => {
    assert.equal(filterEntries(entries, "").length, 3);
    assert.equal(filterEntries(entries, "   ").length, 3);
  });

  it("matches on name, case-insensitively", () => {
    assert.deepEqual(ids(filterEntries(entries, "github")), ["1"]);
  });

  it("matches on username, URL and notes", () => {
    assert.deepEqual(ids(filterEntries(entries, "lovelace")), ["3"]);
    assert.deepEqual(ids(filterEntries(entries, "github.com")), ["1"]);
    assert.deepEqual(ids(filterEntries(entries, "sort code")), ["2"]);
  });

  it("narrows as terms are added, rather than widening", () => {
    assert.deepEqual(ids(filterEntries(entries, "bank")), ["2"]);
    assert.deepEqual(ids(filterEntries(entries, "bank somewhere")), ["2"]);
    assert.deepEqual(ids(filterEntries(entries, "bank github")), []);
  });

  it("never matches on the password", () => {
    // The whole point: a search box that filtered on the secret would let an
    // observer binary-search a password out of the visible row count.
    assert.deepEqual(filterEntries(entries, "hunter2"), []);
  });

  it("does not mutate or alias the input array", () => {
    const result = filterEntries(entries, "");
    result.pop();
    assert.equal(entries.length, 3);
  });
});

describe("sortEntries", () => {
  it("sorts by name, ignoring case", () => {
    assert.deepEqual(ids(sortEntries(entries, "name")).slice(0, 2), ["2", "1"]);
  });

  it("sorts by most recently updated", () => {
    assert.deepEqual(ids(sortEntries(entries, "recent")), ["1", "2", "3"]);
  });

  it("sorts by most recently added", () => {
    assert.deepEqual(ids(sortEntries(entries, "created")), ["1", "3", "2"]);
  });

  it("leaves the caller's array alone", () => {
    const input = [...entries];
    sortEntries(input, "name");
    assert.deepEqual(ids(input), ["1", "2", "3"]);
  });
});

describe("safeHref", () => {
  it("accepts http and https", () => {
    assert.equal(safeHref("https://github.com/ada"), "https://github.com/ada");
    assert.equal(safeHref("http://example.test/"), "http://example.test/");
  });

  it("assumes https for a bare host", () => {
    assert.equal(safeHref("github.com"), "https://github.com/");
  });

  it("refuses every scheme that could execute", () => {
    // An entry's URL field is rendered into an href inside an unlocked tab.
    for (const hostile of [
      "javascript:alert(document.cookie)",
      "JavaScript:alert(1)",
      "  javascript:alert(1)",
      "data:text/html,<script>alert(1)</script>",
      "vbscript:msgbox(1)",
      "file:///etc/passwd",
      "blob:https://example.test/uuid",
    ]) {
      assert.equal(safeHref(hostile), null, `${hostile} must not become a link`);
    }
  });

  it("returns null for an empty or unparseable value", () => {
    assert.equal(safeHref(undefined), null);
    assert.equal(safeHref(""), null);
    assert.equal(safeHref("http://"), null);
  });
});

describe("hostOf", () => {
  it("extracts the host with or without a scheme", () => {
    assert.equal(hostOf("https://github.com/ada/repo"), "github.com");
    assert.equal(hostOf("energy.example.gr"), "energy.example.gr");
  });

  it("keeps a non-default port, which distinguishes two local services", () => {
    assert.equal(hostOf("http://localhost:4000/api"), "localhost:4000");
  });

  it("returns null rather than throwing on nonsense", () => {
    assert.equal(hostOf(""), null);
    assert.equal(hostOf(undefined), null);
    assert.equal(hostOf("not a url at all"), null);
  });
});

describe("initials", () => {
  it("takes two letters from one word and one from each of two", () => {
    assert.equal(initials("GitHub"), "GI");
    assert.equal(initials("bank of somewhere"), "BO");
  });

  it("handles non-Latin names", () => {
    assert.equal(initials("Αθήνα Energy"), "ΑE");
  });

  it("falls back to a bullet for an empty name", () => {
    assert.equal(initials("   "), "•");
  });
});
