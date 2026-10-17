/**
 * Base32, against RFC 4648's test vectors, plus the transcription mistakes a
 * human makes when typing a secret off a screen.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  Base32Error,
  base32Decode,
  base32Encode,
  formatSecret,
  generateRecoveryCodes,
  looksLikeRecoveryCode,
  normaliseRecoveryCode,
} from "../src/index.ts";

const utf8 = (value: string) => new TextEncoder().encode(value);
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);

describe("RFC 4648 base32 vectors", () => {
  // Section 10. Padding is stripped, since we encode without it.
  const vectors: Array<[input: string, encoded: string]> = [
    ["", ""],
    ["f", "MY"],
    ["fo", "MZXQ"],
    ["foo", "MZXW6"],
    ["foob", "MZXW6YQ"],
    ["fooba", "MZXW6YTB"],
    ["foobar", "MZXW6YTBOI"],
  ];

  for (const [input, encoded] of vectors) {
    it(`encodes "${input}" as "${encoded}"`, () => {
      assert.equal(base32Encode(utf8(input)), encoded);
    });
  }

  for (const [input, encoded] of vectors.slice(1)) {
    it(`decodes "${encoded}" back to "${input}"`, () => {
      assert.equal(text(base32Decode(encoded)), input);
    });
  }
});

describe("base32Decode", () => {
  it("accepts the padding other implementations emit", () => {
    assert.equal(text(base32Decode("MZXW6===")), "foo");
    assert.equal(text(base32Decode("MZXW6YQ=")), "foob");
  });

  it("accepts lower case", () => {
    assert.equal(text(base32Decode("mzxw6ytboi")), "foobar");
  });

  it("accepts the spacing a user types from a grouped display", () => {
    assert.equal(text(base32Decode("MZXW 6YTB OI")), "foobar");
    assert.equal(text(base32Decode("MZXW-6YTB-OI")), "foobar");
  });

  it("round-trips arbitrary bytes", () => {
    for (let length = 1; length <= 40; length++) {
      const bytes = crypto.getRandomValues(new Uint8Array(length));
      assert.deepEqual(base32Decode(base32Encode(bytes)), bytes, `length ${length}`);
    }
  });

  it("rejects characters that are not in the alphabet", () => {
    // 0, 1, 8 and 9 are excluded from base32 precisely because they look like
    // O, I/l and B/g. Silently mapping them would produce a secret that never
    // generates a matching code.
    for (const bad of ["MZXW0", "MZXW1", "MZXW8", "MZXW9", "MZX!W", "MZXW6+"]) {
      assert.throws(() => base32Decode(bad), Base32Error, bad);
    }
  });

  it("rejects an empty secret rather than returning zero bytes", () => {
    assert.throws(() => base32Decode(""), Base32Error);
    assert.throws(() => base32Decode("   "), Base32Error);
  });

  it("rejects a truncated secret whose leftover bits are not zero", () => {
    // "MZXW6YTBOIA" is 11 chars = 55 bits: 6 whole bytes plus 7 stray bits.
    // Those bits are zero here, so it decodes; flipping one must not.
    assert.doesNotThrow(() => base32Decode("MZXW6YTBOIA"));
    assert.throws(() => base32Decode("MZXW6YTBOIB"), Base32Error);
  });
});

describe("formatSecret", () => {
  it("groups in fours for a user to read aloud", () => {
    assert.equal(formatSecret("JBSWY3DPEHPK3PXP"), "JBSW Y3DP EHPK 3PXP");
  });

  it("leaves a short tail alone", () => {
    assert.equal(formatSecret("JBSWY"), "JBSW Y");
    assert.equal(formatSecret(""), "");
  });

  it("produces something that decodes to the same bytes", () => {
    const secret = base32Encode(crypto.getRandomValues(new Uint8Array(20)));
    assert.deepEqual(base32Decode(formatSecret(secret)), base32Decode(secret));
  });
});

describe("recovery codes", () => {
  it("issues ten by default", () => {
    assert.equal(generateRecoveryCodes().length, 10);
  });

  it("formats them as XXXXX-XXXXX", () => {
    for (const code of generateRecoveryCodes()) {
      assert.match(code, /^[A-Z2-7]{5}-[A-Z2-7]{5}$/, code);
    }
  });

  it("does not repeat a code, within a set or across sets", () => {
    const codes = [
      ...generateRecoveryCodes(),
      ...generateRecoveryCodes(),
      ...generateRecoveryCodes(),
    ];
    assert.equal(new Set(codes).size, codes.length);
  });

  it("normalises the way a user actually types one back", () => {
    const canonical = normaliseRecoveryCode("ABCDE-FGHIJ");
    for (const typed of ["ABCDE-FGHIJ", "abcde-fghij", "ABCDE FGHIJ", "ABCDEFGHIJ", " abcdefghij "]) {
      assert.equal(normaliseRecoveryCode(typed), canonical, typed);
    }
  });

  it("recognises a well-formed code and rejects the wrong shape", () => {
    assert.ok(looksLikeRecoveryCode(generateRecoveryCodes(1)[0]));
    for (const bad of ["", "ABCDE", "ABCDE-FGHIJK", "ABCD0-FGHIJ", "abcde-fghi!"]) {
      assert.equal(looksLikeRecoveryCode(bad), false, bad);
    }
  });

  it("is only a shape filter, and does not pretend otherwise", () => {
    // "helloworld" happens to be ten base32 characters, so it passes. That is
    // correct: this function exists to reject obvious junk before spending a
    // scrypt verification, not to decide whether a code is real.
    assert.equal(looksLikeRecoveryCode("hello world"), true);
  });
});
