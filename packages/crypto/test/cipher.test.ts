import { test, describe, before } from "node:test";
import assert from "node:assert/strict";

import {
  DecryptionError,
  decryptBytes,
  decryptString,
  deserialize,
  encryptBytes,
  encryptString,
  serialize,
} from "../src/cipher.ts";
import { base64ToBytes, utf8ToBytes } from "../src/encoding.ts";
import { tamper } from "./helpers.ts";

let key: CryptoKey;
let otherKey: CryptoKey;

before(async () => {
  const fresh = () =>
    crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  key = await fresh();
  otherKey = await fresh();
});

describe("round trip", () => {
  test("recovers the original string", async () => {
    const envelope = await encryptString(key, "hunter2");
    assert.equal(await decryptString(key, envelope), "hunter2");
  });

  test("handles unicode and an empty payload", async () => {
    for (const value of ["", "pasword with emoji \u{1F510} and accents: naive", "a".repeat(10_000)]) {
      const envelope = await encryptString(key, value);
      assert.equal(await decryptString(key, envelope), value);
    }
  });

  test("recovers arbitrary bytes", async () => {
    const plaintext = crypto.getRandomValues(new Uint8Array(257));
    const envelope = await encryptBytes(key, plaintext);
    assert.deepEqual([...(await decryptBytes(key, envelope))], [...plaintext]);
  });
});

describe("envelope shape", () => {
  test("stamps version and algorithm", async () => {
    const envelope = await encryptString(key, "x");
    assert.equal(envelope.v, 1);
    assert.equal(envelope.alg, "AES-256-GCM");
  });

  test("uses a fresh 96-bit IV every time", async () => {
    const seen = new Set<string>();
    for (let i = 0; i < 200; i++) {
      const envelope = await encryptString(key, "same plaintext every time");
      assert.equal(base64ToBytes(envelope.iv).length, 12);
      seen.add(envelope.iv);
    }
    // IV reuse under GCM is catastrophic, not merely untidy: it leaks the XOR of
    // the plaintexts and can expose the authentication subkey.
    assert.equal(seen.size, 200, "IV was reused");
  });

  test("the same plaintext encrypts to different ciphertext each time", async () => {
    const a = await encryptString(key, "repeat");
    const b = await encryptString(key, "repeat");
    assert.notEqual(a.ct, b.ct);
  });

  test("appends a 128-bit tag", async () => {
    const plaintext = utf8ToBytes("12345678");
    const envelope = await encryptBytes(key, plaintext);
    assert.equal(base64ToBytes(envelope.ct).length, plaintext.length + 16);
  });
});

describe("integrity", () => {
  test("rejects a flipped ciphertext bit", async () => {
    const envelope = await encryptString(key, "sensitive");
    await assert.rejects(() => decryptString(key, tamper(envelope)), DecryptionError);
  });

  test("rejects a modified IV", async () => {
    const envelope = await encryptString(key, "sensitive");
    const iv = base64ToBytes(envelope.iv);
    iv[0] ^= 0xff;
    await assert.rejects(
      () => decryptString(key, { ...envelope, iv: Buffer.from(iv).toString("base64") }),
      DecryptionError,
    );
  });

  test("rejects the wrong key", async () => {
    const envelope = await encryptString(key, "sensitive");
    await assert.rejects(() => decryptString(otherKey, envelope), DecryptionError);
  });

  test("rejects a mismatched context", async () => {
    const envelope = await encryptString(key, "sensitive", "account:ada|vault");
    await assert.rejects(
      () => decryptString(key, envelope, "account:grace|vault"),
      DecryptionError,
    );
    await assert.rejects(() => decryptString(key, envelope), DecryptionError);
  });

  test("rejects a downgraded version header", async () => {
    const envelope = await encryptString(key, "sensitive");
    await assert.rejects(
      () => decryptString(key, { ...envelope, v: 0 }),
      /Unsupported envelope/,
    );
  });

  test("every failure reports the same message", async () => {
    // An attacker must not be able to distinguish "wrong key" from "tampered".
    const envelope = await encryptString(key, "sensitive");
    const wrongKey = await decryptString(otherKey, envelope).catch((e) => e.message);
    const tampered = await decryptString(key, tamper(envelope)).catch((e) => e.message);
    assert.equal(wrongKey, tampered);
  });
});

describe("wire format", () => {
  test("survives serialize/deserialize", async () => {
    const envelope = await encryptString(key, "round trip");
    const restored = deserialize(serialize(envelope));
    assert.deepEqual(restored, envelope);
    assert.equal(await decryptString(key, restored), "round trip");
  });

  test("rejects a malformed string", () => {
    assert.throws(() => deserialize("not-an-envelope"), /Malformed envelope/);
  });

  test("rejects an unknown algorithm", async () => {
    const envelope = await encryptString(key, "x");
    assert.throws(() => deserialize(serialize({ ...envelope, alg: "ROT13" as never })), /Unsupported/);
  });
});
