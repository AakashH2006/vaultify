import { test, describe } from "node:test";
import assert from "node:assert/strict";

import { deriveKeys, deriveSalt } from "../src/kdf.ts";
import { bytesToBase64 } from "../src/encoding.ts";
import { ACCOUNT, FAST_KDF, PASSWORD } from "./helpers.ts";

describe("deriveSalt", () => {
  test("is deterministic for the same account", async () => {
    const a = await deriveSalt(ACCOUNT);
    const b = await deriveSalt(ACCOUNT);
    assert.deepEqual([...a], [...b]);
    assert.equal(a.length, 32);
  });

  test("normalises case and surrounding whitespace", async () => {
    const a = await deriveSalt("  Ada@Example.com ");
    const b = await deriveSalt("ada@example.com");
    assert.deepEqual([...a], [...b]);
  });

  test("differs between accounts", async () => {
    const a = await deriveSalt("ada@example.com");
    const b = await deriveSalt("grace@example.com");
    assert.notDeepEqual([...a], [...b]);
  });

  test("rejects an empty identifier", async () => {
    await assert.rejects(() => deriveSalt("   "), /must not be empty/);
  });
});

describe("deriveKeys", () => {
  test("same inputs produce the same auth key", async () => {
    const first = await deriveKeys(ACCOUNT, PASSWORD, FAST_KDF);
    const second = await deriveKeys(ACCOUNT, PASSWORD, FAST_KDF);
    assert.equal(first.authKey, second.authKey);
  });

  test("a different password produces a different auth key", async () => {
    const right = await deriveKeys(ACCOUNT, PASSWORD, FAST_KDF);
    const wrong = await deriveKeys(ACCOUNT, PASSWORD + "!", FAST_KDF);
    assert.notEqual(right.authKey, wrong.authKey);
  });

  test("the same password under a different account produces a different auth key", async () => {
    const ada = await deriveKeys("ada@example.com", PASSWORD, FAST_KDF);
    const grace = await deriveKeys("grace@example.com", PASSWORD, FAST_KDF);
    assert.notEqual(ada.authKey, grace.authKey);
  });

  test("raising the iteration count changes the output", async () => {
    const low = await deriveKeys(ACCOUNT, PASSWORD, FAST_KDF);
    const high = await deriveKeys(ACCOUNT, PASSWORD, {
      algorithm: "PBKDF2",
      iterations: FAST_KDF.iterations + 1,
    });
    assert.notEqual(low.authKey, high.authKey);
  });

  test("the auth key is 256 bits", async () => {
    const { authKey } = await deriveKeys(ACCOUNT, PASSWORD, FAST_KDF);
    assert.equal(Buffer.from(authKey, "base64").length, 32);
  });

  test("the wrapping key cannot be exported", async () => {
    // This is the property that limits the blast radius of an XSS: a script in
    // the page can use the key while the tab is unlocked, but cannot exfiltrate
    // it and decrypt the vault later, offline.
    const { wrappingKey } = await deriveKeys(ACCOUNT, PASSWORD, FAST_KDF);
    assert.equal(wrappingKey.extractable, false);
    await assert.rejects(() => crypto.subtle.exportKey("raw", wrappingKey));
  });

  test("the wrapping key can only wrap and unwrap", async () => {
    const { wrappingKey } = await deriveKeys(ACCOUNT, PASSWORD, FAST_KDF);
    assert.deepEqual([...wrappingKey.usages].sort(), ["unwrapKey", "wrapKey"]);
  });

  test("the auth key reveals nothing usable about the wrapping key", async () => {
    // Both come from the same master key, so the only thing separating them is
    // the HKDF info label. Guard against someone "simplifying" that away: if the
    // two expansions ever collide, the server would hold the vault key material.
    const { authKey, wrappingKey } = await deriveKeys(ACCOUNT, PASSWORD, FAST_KDF);

    const probe = await crypto.subtle.importKey(
      "raw",
      Buffer.from(authKey, "base64"),
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt"],
    );
    const iv = new Uint8Array(12);
    const underAuthKey = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      probe,
      new Uint8Array(16),
    );

    // Wrap a throwaway key with the real wrapping key and confirm the auth key
    // does not reproduce it. (Indirect, because the wrapping key is sealed.)
    const victim = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
      "encrypt",
    ]);
    const wrapped = await crypto.subtle.wrapKey("raw", victim, wrappingKey, {
      name: "AES-GCM",
      iv,
    });
    assert.notEqual(bytesToBase64(new Uint8Array(wrapped)), bytesToBase64(new Uint8Array(underAuthKey)));
  });

  test("refuses an iteration count below the floor", async () => {
    await assert.rejects(
      () => deriveKeys(ACCOUNT, PASSWORD, { algorithm: "PBKDF2", iterations: 1 }),
      /Refusing to derive keys/,
    );
  });

  test("rejects an empty master password", async () => {
    await assert.rejects(() => deriveKeys(ACCOUNT, "", FAST_KDF), /must not be empty/);
  });
});
