/**
 * TOTP, checked against the official vectors first.
 *
 * An OTP implementation that is subtly wrong still produces plausible
 * six-digit numbers, and the bug only shows up as "some users cannot log in"
 * once it is in production. The RFC's own test table is the only way to know
 * the arithmetic is right, so it leads.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  DEFAULT_PERIOD_SECONDS,
  base32Encode,
  generateSecret,
  hotp,
  otpauthUri,
  secondsRemaining,
  stepFor,
  totp,
  verifyTotp,
} from "../src/index.ts";

/** RFC 6238's seed is the ASCII string "12345678901234567890". */
const RFC_SECRET = base32Encode(new TextEncoder().encode("12345678901234567890"));

describe("RFC 6238 test vectors", () => {
  // Appendix B, the SHA-1 rows, verbatim at 8 digits. These are the whole
  // reason to trust the rest.
  const vectors: Array<[seconds: number, code: string]> = [
    [59, "94287082"],
    [1_111_111_109, "07081804"],
    [1_111_111_111, "14050471"],
    [1_234_567_890, "89005924"],
    [2_000_000_000, "69279037"],
    [20_000_000_000, "65353130"],
  ];

  for (const [seconds, expected] of vectors) {
    it(`produces ${expected} at t=${seconds}`, async () => {
      const code = await totp(RFC_SECRET, { now: seconds * 1000, digits: 8 });
      assert.equal(code, expected);
    });
  }

  it("truncates to the low six digits, which is what the apps show", async () => {
    for (const [seconds, eight] of vectors) {
      const six = await totp(RFC_SECRET, { now: seconds * 1000 });
      assert.equal(six, eight.slice(-6), `t=${seconds}`);
    }
  });
});

describe("RFC 4226 HOTP vectors", () => {
  // Appendix D. Same seed, counters 0..9.
  const expected = [
    "755224", "287082", "359152", "969429", "338314",
    "254676", "287922", "162583", "399871", "520489",
  ];

  for (const [counter, code] of expected.entries()) {
    it(`counter ${counter} -> ${code}`, async () => {
      assert.equal(await hotp(RFC_SECRET, counter), code);
    });
  }
});

describe("stepFor", () => {
  it("advances once per period", () => {
    assert.equal(stepFor(0), 0);
    assert.equal(stepFor(29_999), 0);
    assert.equal(stepFor(30_000), 1);
    assert.equal(stepFor(59_999), 1);
    assert.equal(stepFor(60_000), 2);
  });
});

describe("secondsRemaining", () => {
  it("counts down to the rollover", () => {
    assert.equal(secondsRemaining(0), 30);
    assert.equal(secondsRemaining(1_000), 29);
    assert.equal(secondsRemaining(29_000), 1);
    assert.equal(secondsRemaining(30_000), 30);
  });

  it("never returns zero, so the ring never shows an empty state", () => {
    for (let second = 0; second < 120; second++) {
      const remaining = secondsRemaining(second * 1000);
      assert.ok(remaining >= 1 && remaining <= DEFAULT_PERIOD_SECONDS, `t=${second}: ${remaining}`);
    }
  });
});

describe("generateSecret", () => {
  it("produces a 160-bit base32 secret by default", () => {
    const secret = generateSecret();
    assert.equal(secret.length, 32); // 20 bytes -> 32 base32 chars
    assert.match(secret, /^[A-Z2-7]+$/);
  });

  it("does not repeat itself", () => {
    const seen = new Set(Array.from({ length: 50 }, () => generateSecret()));
    assert.equal(seen.size, 50);
  });
});

describe("verifyTotp", () => {
  const now = 1_700_000_000_000;

  it("accepts the current code", async () => {
    const code = await totp(RFC_SECRET, { now });
    const result = await verifyTotp(RFC_SECRET, code, { now });

    assert.equal(result.ok, true);
    assert.equal(result.step, stepFor(now));
  });

  it("accepts one step late, for a user who typed slowly", async () => {
    const code = await totp(RFC_SECRET, { now: now - 30_000 });
    assert.equal((await verifyTotp(RFC_SECRET, code, { now })).ok, true);
  });

  it("accepts one step early, for a phone whose clock runs fast", async () => {
    const code = await totp(RFC_SECRET, { now: now + 30_000 });
    assert.equal((await verifyTotp(RFC_SECRET, code, { now })).ok, true);
  });

  it("refuses two steps out, which is drift we will not absorb", async () => {
    for (const offset of [-60_000, 60_000]) {
      const code = await totp(RFC_SECRET, { now: now + offset });
      const result = await verifyTotp(RFC_SECRET, code, { now });
      assert.equal(result.ok, false, `offset ${offset} should not verify`);
      assert.equal(result.reason, "mismatch");
    }
  });

  it("refuses a code from a different secret", async () => {
    const code = await totp(generateSecret(), { now });
    assert.equal((await verifyTotp(RFC_SECRET, code, { now })).ok, false);
  });

  it("tolerates the spaces and separators phones display", async () => {
    const code = await totp(RFC_SECRET, { now });
    const spaced = `${code.slice(0, 3)} ${code.slice(3)}`;
    assert.equal((await verifyTotp(RFC_SECRET, spaced, { now })).ok, true);
  });

  it("rejects anything that is not six digits as malformed", async () => {
    for (const bad of ["", "12345", "1234567", "abcdef", "   "]) {
      const result = await verifyTotp(RFC_SECRET, bad, { now });
      assert.equal(result.ok, false);
      assert.equal(result.reason, "malformed", `"${bad}"`);
    }
  });

  describe("replay prevention", () => {
    it("refuses a code whose step was already spent", async () => {
      const code = await totp(RFC_SECRET, { now });
      const first = await verifyTotp(RFC_SECRET, code, { now });
      assert.equal(first.ok, true);

      // A code stays valid for 90 seconds across the window, which is plenty
      // of time for someone watching the screen to reuse it.
      const second = await verifyTotp(RFC_SECRET, code, { now, lastUsedStep: first.step });
      assert.equal(second.ok, false);
      assert.equal(second.reason, "replayed");
    });

    it("refuses an older code once a newer one has been used", async () => {
      const older = await totp(RFC_SECRET, { now: now - 30_000 });
      const current = stepFor(now);

      const result = await verifyTotp(RFC_SECRET, older, { now, lastUsedStep: current });
      assert.equal(result.ok, false);
      assert.equal(result.reason, "replayed");
    });

    it("still accepts the next step after one is spent", async () => {
      const spent = stepFor(now);
      const next = await totp(RFC_SECRET, { now: now + 30_000 });

      const result = await verifyTotp(RFC_SECRET, next, {
        now: now + 30_000,
        lastUsedStep: spent,
      });
      assert.equal(result.ok, true);
      assert.equal(result.step, spent + 1);
    });

    it("treats a null lastUsedStep as 'nothing spent yet'", async () => {
      const code = await totp(RFC_SECRET, { now });
      assert.equal((await verifyTotp(RFC_SECRET, code, { now, lastUsedStep: null })).ok, true);
    });
  });

  it("reports the matched step so the caller can persist it", async () => {
    const code = await totp(RFC_SECRET, { now: now - 30_000 });
    const result = await verifyTotp(RFC_SECRET, code, { now });
    assert.equal(result.step, stepFor(now) - 1);
  });
});

describe("otpauthUri", () => {
  it("builds a URI an authenticator app will parse", () => {
    const uri = otpauthUri({ secret: "JBSWY3DPEHPK3PXP", account: "ada@example.com" });

    const parsed = new URL(uri);
    assert.equal(parsed.protocol, "otpauth:");
    assert.equal(parsed.host, "totp");
    assert.equal(decodeURIComponent(parsed.pathname.slice(1)), "Vaultify:ada@example.com");
    assert.equal(parsed.searchParams.get("secret"), "JBSWY3DPEHPK3PXP");
    assert.equal(parsed.searchParams.get("issuer"), "Vaultify");
    assert.equal(parsed.searchParams.get("algorithm"), "SHA1");
    assert.equal(parsed.searchParams.get("digits"), "6");
    assert.equal(parsed.searchParams.get("period"), "30");
  });

  it("escapes the @ in the label but keeps the issuer colon", () => {
    const uri = otpauthUri({ secret: "AAAA", account: "a b@c.test" });
    assert.ok(uri.includes("Vaultify%3Aa%20b%40c.test"));
  });

  it("round-trips through the secret it advertises", async () => {
    const secret = generateSecret();
    const uri = otpauthUri({ secret, account: "ada@example.com" });
    const advertised = new URL(uri).searchParams.get("secret");

    assert.equal(advertised, secret);
    assert.equal(await totp(advertised!, { now: 0 }), await totp(secret, { now: 0 }));
  });
});
