/**
 * The strength estimator is advisory, so these tests assert its *ordering* and
 * its floor rather than exact bit counts. Pinning the arithmetic would make the
 * suite break every time the heuristics are tuned, which is the opposite of
 * what we want from a test of a heuristic.
 *
 * The one hard requirement is the floor: anything a cracker finds in its first
 * few thousand guesses must come out as "very weak", because the registration
 * form refuses to proceed below score 2 and that gate is the only thing
 * stopping a one-word master password.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { estimateStrength } from "../src/strength.ts";

describe("estimateStrength", () => {
  it("rates an empty password as unusable and says so", () => {
    const result = estimateStrength("");
    assert.equal(result.score, 0);
    assert.equal(result.bits, 0);
    assert.ok(result.hints.length > 0);
  });

  it("floors the passwords at the top of every breach corpus", () => {
    for (const password of ["password", "123456", "qwerty", "letmein", "Password"]) {
      const result = estimateStrength(password);
      assert.equal(result.score, 0, `${password} should be score 0`);
      assert.ok(result.bits <= 1, `${password} should carry essentially no entropy`);
    }
  });

  it("rejects the example passphrase from our own documentation", () => {
    // It appears in the README, the architecture doc and the demo. A published
    // example is a published password.
    assert.equal(estimateStrength("correct horse battery staple").score, 0);
  });

  it("ranks longer above shorter for the same alphabet", () => {
    const short = estimateStrength("Tf7qK2");
    const long = estimateStrength("Tf7qK2wR9xB4mN6p");
    assert.ok(long.bits > short.bits);
  });

  it("ranks a mixed alphabet above a single one at equal length", () => {
    const lower = estimateStrength("abcdhjkmnpqrstvw");
    const mixed = estimateStrength("aBc3hJk!nPq7stVw");
    assert.ok(mixed.bits > lower.bits);
  });

  it("credits a multi-word passphrase that per-character scoring would underrate", () => {
    const passphrase = estimateStrength("ledger marble quartz tunnel");
    assert.ok(passphrase.score >= 3, `expected a strong passphrase, got ${passphrase.label}`);
  });

  it("discounts repetition rather than counting it as length", () => {
    const repeated = estimateStrength("aaaaaaaaaaaaaaaaaaaa");
    const varied = estimateStrength("qwstdhjkmnbvcxzplrfg");
    assert.ok(varied.bits > repeated.bits * 1.5);
  });

  describe("pattern penalties", () => {
    const cases: Array<[string, string, RegExp]> = [
      ["a sequential run", "abcdefgh!Q3", /runs/i],
      ["a keyboard walk", "qwertyui!Q3", /keyboard/i],
      ["a year", "Tunnel2019!q", /year/i],
      ["a repeat", "Taaa9!qmZ", /repeated/i],
    ];

    for (const [what, password, hint] of cases) {
      it(`penalises ${what} and explains why`, () => {
        const result = estimateStrength(password);
        assert.match(result.hints.join(" "), hint);
      });
    }
  });

  it("stops nagging once the password is excellent", () => {
    const result = estimateStrength("ledger marble quartz tunnel vineyard copper");
    assert.equal(result.score, 4);
    assert.deepEqual(result.hints, []);
  });

  it("always advises length on a short password", () => {
    const result = estimateStrength("Ab3!xZ");
    assert.match(result.hints[0], /at least 12 characters/i);
  });

  it("never returns a negative bit count, however many penalties apply", () => {
    const result = estimateStrength("aaaa1234qwer2019");
    assert.ok(result.bits >= 0);
  });

  it("produces labels that march in step with the scores", () => {
    const samples = ["a", "abcdefgh", "Ab3!xZq9", "Ab3!xZq9Lm5#Tr", "ledger marble quartz tunnel vineyard"];
    const scores = samples.map((sample) => estimateStrength(sample).score);
    const sorted = [...scores].sort((a, b) => a - b);
    assert.deepEqual(scores, sorted, "longer/more varied samples should never score lower");
  });
});
