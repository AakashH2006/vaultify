import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { CHARSETS, entropyBits, generatePassword } from "../src/generator.ts";

const has = (value: string, set: string) => [...value].some((c) => set.includes(c));

describe("generatePassword", () => {
  test("honours the requested length", () => {
    for (const length of [8, 16, 20, 64, 128]) {
      assert.equal(generatePassword({ length }).length, length);
    }
  });

  test("includes at least one character from every enabled class", () => {
    for (let i = 0; i < 200; i++) {
      const value = generatePassword({ length: 8 });
      assert.ok(has(value, CHARSETS.lowercase), "no lowercase in " + value);
      assert.ok(has(value, CHARSETS.uppercase), "no uppercase in " + value);
      assert.ok(has(value, CHARSETS.digits), "no digit in " + value);
      assert.ok(has(value, CHARSETS.symbols), "no symbol in " + value);
    }
  });

  test("uses only the enabled classes", () => {
    const value = generatePassword({ length: 40, symbols: false, uppercase: false });
    assert.ok(!has(value, CHARSETS.symbols));
    assert.ok(!has(value, CHARSETS.uppercase));
  });

  test("excludeAmbiguous drops look-alike characters", () => {
    for (let i = 0; i < 50; i++) {
      const value = generatePassword({ length: 60, excludeAmbiguous: true });
      assert.ok(!has(value, "Il1O0oB8S5Z2"), "ambiguous character in " + value);
    }
  });

  test("does not repeat itself", () => {
    const seen = new Set(Array.from({ length: 500 }, () => generatePassword({ length: 20 })));
    assert.equal(seen.size, 500);
  });

  test("the guaranteed characters are not pinned to fixed positions", () => {
    // Without the final shuffle, index 0 would always be lowercase and index 2
    // always a digit. Sample and confirm each position varies by class.
    const classAt = (position: number) =>
      new Set(
        Array.from({ length: 300 }, () => {
          const c = generatePassword({ length: 8 })[position];
          if (CHARSETS.lowercase.includes(c)) return "lower";
          if (CHARSETS.uppercase.includes(c)) return "upper";
          if (CHARSETS.digits.includes(c)) return "digit";
          return "symbol";
        }),
      );
    for (const position of [0, 1, 2, 3]) {
      assert.equal(classAt(position).size, 4, "position " + position + " is not varied");
    }
  });

  test("character selection is close to uniform", () => {
    // A modulo-biased generator would skew the low end of the alphabet. With
    // 26 letters over ~20,000 draws, every letter should land near 1/26.
    const counts = new Map<string, number>();
    for (let i = 0; i < 1000; i++) {
      for (const c of generatePassword({
        length: 20,
        uppercase: false,
        digits: false,
        symbols: false,
      })) {
        counts.set(c, (counts.get(c) ?? 0) + 1);
      }
    }
    assert.equal(counts.size, 26);
    const expected = 20_000 / 26;
    for (const [char, count] of counts) {
      const deviation = Math.abs(count - expected) / expected;
      assert.ok(deviation < 0.25, char + " appeared " + count + " times (expected ~" + Math.round(expected) + ")");
    }
  });

  test("rejects impossible requests", () => {
    assert.throws(() => generatePassword({ length: 4 }), RangeError);
    assert.throws(() => generatePassword({ length: 200 }), RangeError);
    assert.throws(
      () =>
        generatePassword({
          lowercase: false,
          uppercase: false,
          digits: false,
          symbols: false,
        }),
      /at least one character class/,
    );
  });
});

describe("entropyBits", () => {
  test("matches length x log2(alphabet)", () => {
    // 26+26+10+25 = 87 characters.
    assert.equal(Math.round(entropyBits({ length: 20 })), Math.round(20 * Math.log2(87)));
  });

  test("the default is comfortably beyond brute force", () => {
    assert.ok(entropyBits() > 128);
  });

  test("falls to zero with no classes enabled", () => {
    assert.equal(
      entropyBits({ lowercase: false, uppercase: false, digits: false, symbols: false }),
      0,
    );
  });
});
