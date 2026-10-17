/**
 * The merge is the part of the client that can lose a password if it is wrong,
 * so these tests are written as the scenarios a user would actually hit on two
 * devices, not as unit tests of the helper functions.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { VAULT_SCHEMA_VERSION, type VaultContents, type VaultEntry } from "@vaultify/crypto";
import { mergeVaults } from "../src/merge.ts";

let clock = Date.parse("2026-03-01T10:00:00.000Z");
function at(offsetMinutes: number): string {
  return new Date(clock + offsetMinutes * 60_000).toISOString();
}

function entry(id: string, overrides: Partial<VaultEntry> = {}): VaultEntry {
  return {
    id,
    name: id,
    username: `${id}@example.com`,
    password: `password-${id}`,
    createdAt: at(0),
    updatedAt: at(0),
    ...overrides,
  };
}

function vault(...entries: VaultEntry[]): VaultContents {
  return { version: VAULT_SCHEMA_VERSION, entries };
}

const names = (contents: VaultContents) => contents.entries.map((e) => e.name).sort();
const ids = (contents: VaultContents) => contents.entries.map((e) => e.id).sort();

describe("mergeVaults", () => {
  it("keeps additions from both sides", () => {
    const base = vault(entry("shared"));
    const mine = vault(entry("shared"), entry("mine-only"));
    const theirs = vault(entry("shared"), entry("theirs-only"));

    const { vault: merged } = mergeVaults(base, mine, theirs);

    assert.deepEqual(ids(merged), ["mine-only", "shared", "theirs-only"]);
  });

  it("honours a delete the other side did not touch", () => {
    const base = vault(entry("a"), entry("b"));
    const mine = vault(entry("a")); // I deleted b
    const theirs = vault(entry("a"), entry("b"));

    const { vault: merged } = mergeVaults(base, mine, theirs);

    assert.deepEqual(ids(merged), ["a"]);
  });

  it("honours a delete made on the other device", () => {
    const base = vault(entry("a"), entry("b"));
    const mine = vault(entry("a"), entry("b"));
    const theirs = vault(entry("a")); // they deleted b

    const { vault: merged } = mergeVaults(base, mine, theirs);

    assert.deepEqual(ids(merged), ["a"]);
  });

  it("takes the remote edit when the local side did not change the entry", () => {
    const base = vault(entry("a", { password: "old" }));
    const mine = vault(entry("a", { password: "old" }));
    const theirs = vault(entry("a", { password: "rotated", updatedAt: at(5) }));

    const { vault: merged } = mergeVaults(base, mine, theirs);

    assert.equal(merged.entries[0].password, "rotated");
  });

  it("keeps the local edit when the remote side did not change the entry", () => {
    const base = vault(entry("a", { password: "old" }));
    const mine = vault(entry("a", { password: "mine", updatedAt: at(5) }));
    const theirs = vault(entry("a", { password: "old" }));

    const { vault: merged } = mergeVaults(base, mine, theirs);

    assert.equal(merged.entries[0].password, "mine");
  });

  describe("the rule that matters: never silently lose a credential", () => {
    it("resurrects an entry the other device edited while this one deleted it", () => {
      const base = vault(entry("a"), entry("b", { password: "old" }));
      const mine = vault(entry("a")); // deleted b
      const theirs = vault(entry("a"), entry("b", { password: "rotated", updatedAt: at(5) }));

      const { vault: merged, notes } = mergeVaults(base, mine, theirs);

      assert.deepEqual(ids(merged), ["a", "b"]);
      assert.equal(merged.entries.find((e) => e.id === "b")?.password, "rotated");
      assert.match(notes.join(" "), /edited it while this one deleted it/);
    });

    it("resurrects an entry this device edited while the other deleted it", () => {
      const base = vault(entry("a"), entry("b", { password: "old" }));
      const mine = vault(entry("a"), entry("b", { password: "mine", updatedAt: at(5) }));
      const theirs = vault(entry("a")); // they deleted b

      const { vault: merged, notes } = mergeVaults(base, mine, theirs);

      assert.deepEqual(ids(merged), ["a", "b"]);
      assert.equal(merged.entries.find((e) => e.id === "b")?.password, "mine");
      assert.match(notes.join(" "), /deleted it while this one edited it/);
    });

    it("keeps both versions when the same entry was edited differently on each device", () => {
      const base = vault(entry("a", { name: "Bank", password: "old" }));
      const mine = vault(entry("a", { name: "Bank", password: "mine", updatedAt: at(2) }));
      const theirs = vault(entry("a", { name: "Bank", password: "theirs", updatedAt: at(9) }));

      const { vault: merged, notes } = mergeVaults(base, mine, theirs);

      assert.equal(merged.entries.length, 2);
      const passwords = merged.entries.map((e) => e.password).sort();
      assert.deepEqual(passwords, ["mine", "theirs"]);

      // The newer edit keeps the original name and id; the older becomes a copy.
      const winner = merged.entries.find((e) => e.id === "a");
      assert.equal(winner?.password, "theirs");
      const loser = merged.entries.find((e) => e.id !== "a");
      assert.equal(loser?.name, "Bank (conflicted copy)");
      assert.match(notes.join(" "), /edited on two devices/);
    });

    it("gives a conflicted copy a stable id, so re-merging does not multiply it", () => {
      const base = vault(entry("a", { password: "old" }));
      const mine = vault(entry("a", { password: "mine", updatedAt: at(2) }));
      const theirs = vault(entry("a", { password: "theirs", updatedAt: at(9) }));

      const first = mergeVaults(base, mine, theirs).vault;
      const second = mergeVaults(base, first, first).vault;

      assert.equal(second.entries.length, 2);
      assert.deepEqual(ids(first), ids(second));
    });
  });

  describe("without a common ancestor", () => {
    it("keeps everything from both sides rather than guessing at deletes", () => {
      // This is the state after an unlock that has never synced: we have no
      // base, so an absent entry is indistinguishable from a deleted one.
      const mine = vault(entry("a"), entry("b"));
      const theirs = vault(entry("a"), entry("c"));

      const { vault: merged } = mergeVaults(null, mine, theirs);

      assert.deepEqual(ids(merged), ["a", "b", "c"]);
    });
  });

  describe("bookkeeping", () => {
    it("reports changed: false when the remote side adds nothing new", () => {
      const base = vault(entry("a"));
      const mine = vault(entry("a"));
      const theirs = vault(entry("a"));

      assert.equal(mergeVaults(base, mine, theirs).changed, false);
    });

    it("reports changed: true when the merge pulled something in", () => {
      const base = vault(entry("a"));
      const mine = vault(entry("a"));
      const theirs = vault(entry("a"), entry("b"));

      assert.equal(mergeVaults(base, mine, theirs).changed, true);
    });

    it("ignores an updatedAt that differs with identical content", () => {
      const base = vault(entry("a"));
      const mine = vault(entry("a", { updatedAt: at(1) }));
      const theirs = vault(entry("a", { updatedAt: at(2) }));

      const { vault: merged, notes } = mergeVaults(base, mine, theirs);

      assert.equal(merged.entries.length, 1);
      assert.deepEqual(notes, []);
    });

    it("survives an unparseable updatedAt instead of throwing", () => {
      const base = vault(entry("a", { password: "old" }));
      const mine = vault(entry("a", { password: "mine", updatedAt: "not a date" }));
      const theirs = vault(entry("a", { password: "theirs", updatedAt: at(3) }));

      const { vault: merged } = mergeVaults(base, mine, theirs);

      assert.equal(merged.entries.length, 2);
      assert.equal(merged.entries.find((e) => e.id === "a")?.password, "theirs");
    });

    it("preserves remote ordering and appends local additions", () => {
      const base = vault();
      const mine = vault(entry("local", { name: "Local" }));
      const theirs = vault(entry("x", { name: "X" }), entry("y", { name: "Y" }));

      const { vault: merged } = mergeVaults(base, mine, theirs);

      assert.deepEqual(merged.entries.map((e) => e.name), ["X", "Y", "Local"]);
    });

    it("never produces a duplicate id", () => {
      const base = vault(entry("a", { password: "old" }), entry("b"));
      const mine = vault(entry("a", { password: "mine", updatedAt: at(1) }), entry("b"));
      const theirs = vault(entry("a", { password: "theirs", updatedAt: at(2) }), entry("b"));

      const { vault: merged } = mergeVaults(base, mine, theirs);
      const seen = new Set(merged.entries.map((e) => e.id));

      assert.equal(seen.size, merged.entries.length);
      assert.deepEqual(names(merged).length, merged.entries.length);
    });
  });
});
