/**
 * Tests for the QR encoder.
 *
 * Asserting "it produced a grid" would be worthless -- a QR code with the
 * data bits placed one column out still looks exactly like a QR code. So
 * these tests carry a **reader**: it undoes the mask, walks the placement in
 * reverse, de-interleaves the blocks and parses the byte-mode header back
 * into the original string.
 *
 * That reader is deliberately written from the specification rather than
 * derived from the encoder's own code paths, so the two agreeing is real
 * evidence. It does no error correction -- it does not need to, since the
 * input is undamaged, and a reader that could repair errors would hide
 * exactly the small placement bugs this is meant to catch.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import { MAX_BYTES, QrError, encodeQr, type QrCode } from "../src/qr.ts";

// ---------------------------------------------------------------------------
// A minimal reader, written against the spec
// ---------------------------------------------------------------------------

const MASKS: Array<(row: number, col: number) => boolean> = [
  (r, c) => (r + c) % 2 === 0,
  (r) => r % 2 === 0,
  (_r, c) => c % 3 === 0,
  (r, c) => (r + c) % 3 === 0,
  (r, c) => (Math.floor(r / 2) + Math.floor(c / 3)) % 2 === 0,
  (r, c) => ((r * c) % 2) + ((r * c) % 3) === 0,
  (r, c) => (((r * c) % 2) + ((r * c) % 3)) % 2 === 0,
  (r, c) => (((r + c) % 2) + ((r * c) % 3)) % 2 === 0,
];

const ALIGNMENT: Record<number, readonly number[]> = {
  1: [], 2: [6, 18], 3: [6, 22], 4: [6, 26], 5: [6, 30],
  6: [6, 34], 7: [6, 22, 38], 8: [6, 24, 42], 9: [6, 26, 46], 10: [6, 28, 50],
};

const GROUPS: Record<number, ReadonlyArray<readonly [number, number]>> = {
  1: [[1, 16]], 2: [[1, 28]], 3: [[1, 44]], 4: [[2, 32]], 5: [[2, 43]],
  6: [[4, 27]], 7: [[4, 31]], 8: [[2, 38], [2, 39]], 9: [[3, 36], [2, 37]],
  10: [[4, 43], [1, 44]],
};

const EC_PER_BLOCK: Record<number, number> = {
  1: 10, 2: 16, 3: 26, 4: 18, 5: 24, 6: 16, 7: 18, 8: 22, 9: 22, 10: 26,
};

/** Rebuild the "is a function pattern" map independently of the encoder. */
function reservedMap(version: number, size: number): boolean[][] {
  const reserved = Array.from({ length: size }, () => new Array<boolean>(size).fill(false));
  const mark = (r: number, c: number) => {
    if (r >= 0 && r < size && c >= 0 && c < size) reserved[r][c] = true;
  };

  for (const [row, col] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
    for (let r = -1; r <= 7; r++) for (let c = -1; c <= 7; c++) mark(row + r, col + c);
  }
  for (let i = 0; i < size; i++) {
    mark(6, i);
    mark(i, 6);
  }
  const centres = ALIGNMENT[version];
  for (const row of centres) {
    for (const col of centres) {
      const onFinder =
        (row === 6 && col === 6) ||
        (row === 6 && col === size - 7) ||
        (row === size - 7 && col === 6);
      if (onFinder) continue;
      for (let r = -2; r <= 2; r++) for (let c = -2; c <= 2; c++) mark(row + r, col + c);
    }
  }
  for (let i = 0; i < 9; i++) {
    mark(8, i);
    mark(i, 8);
  }
  for (let i = 0; i < 8; i++) {
    mark(8, size - 1 - i);
    mark(size - 1 - i, 8);
  }
  if (version >= 7) {
    for (let i = 0; i < 18; i++) {
      const r = Math.floor(i / 3);
      const c = size - 11 + (i % 3);
      mark(r, c);
      mark(c, r);
    }
  }
  return reserved;
}

/** Undo mask + placement + interleaving and parse the byte-mode payload. */
function decodeQr(code: QrCode): string {
  const { size, version, mask, modules } = code;
  const reserved = reservedMap(version, size);

  // 1. Unmask.
  const grid = modules.map((row, r) =>
    row.map((cell, c) => (reserved[r][c] ? cell : cell !== MASKS[mask](r, c))),
  );

  // 2. Walk the zig-zag in the same order the encoder wrote it.
  const bits: number[] = [];
  let upward = true;
  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (let step = 0; step < size; step++) {
      const row = upward ? size - 1 - step : step;
      for (const col of [right, right - 1]) {
        if (reserved[row][col]) continue;
        bits.push(grid[row][col] ? 1 : 0);
      }
    }
    upward = !upward;
  }

  const all = new Uint8Array(bits.length >> 3);
  for (let i = 0; i < all.length * 8; i++) {
    if (bits[i]) all[i >> 3] |= 0x80 >> (i & 7);
  }

  // 3. De-interleave back into data blocks, discarding the EC codewords.
  const sizes: number[] = [];
  for (const [count, blockSize] of GROUPS[version]) {
    for (let i = 0; i < count; i++) sizes.push(blockSize);
  }
  const blocks: number[][] = sizes.map(() => []);
  const longest = Math.max(...sizes);

  let index = 0;
  for (let i = 0; i < longest; i++) {
    for (let b = 0; b < sizes.length; b++) {
      if (i < sizes[b]) blocks[b].push(all[index++]);
    }
  }
  void EC_PER_BLOCK; // the EC codewords follow; the reader does not need them

  const data = Uint8Array.from(blocks.flat());

  // 4. Parse the byte-mode header.
  const readBits = (offset: number, length: number): number => {
    let value = 0;
    for (let i = 0; i < length; i++) {
      const bit = (data[(offset + i) >> 3] >> (7 - ((offset + i) & 7))) & 1;
      value = (value << 1) | bit;
    }
    return value;
  };

  const mode = readBits(0, 4);
  assert.equal(mode, 0b0100, "not byte mode");

  const lengthBits = version < 10 ? 8 : 16;
  const byteLength = readBits(4, lengthBits);

  const payload = new Uint8Array(byteLength);
  for (let i = 0; i < byteLength; i++) {
    payload[i] = readBits(4 + lengthBits + i * 8, 8);
  }
  return new TextDecoder().decode(payload);
}

// ---------------------------------------------------------------------------

describe("encodeQr", () => {
  it("round-trips a short string", () => {
    const code = encodeQr("HELLO");
    assert.equal(decodeQr(code), "HELLO");
  });

  it("round-trips a real otpauth URI, which is the only payload we ship", () => {
    const uri =
      "otpauth://totp/Vaultify%3Aada%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP" +
      "&issuer=Vaultify&algorithm=SHA1&digits=6&period=30";

    const code = encodeQr(uri);
    assert.equal(decodeQr(code), uri);
  });

  it("round-trips at every version boundary", () => {
    // Each version has a different block layout, and versions 7+ add the
    // version-information blocks. Crossing each boundary exercises all of it.
    for (const length of [1, 14, 15, 26, 27, 42, 43, 62, 63, 84, 85, 106, 107, 122, 123, 152, 180, 213]) {
      if (length > MAX_BYTES) continue;
      const text = "x".repeat(length);
      const code = encodeQr(text);
      assert.equal(decodeQr(code), text, `length ${length} (version ${code.version})`);
    }
  });

  it("round-trips multi-byte UTF-8", () => {
    const text = "Vaultify — Αθήνα — 東京";
    assert.equal(decodeQr(encodeQr(text)), text);
  });

  it("picks the smallest version that fits", () => {
    assert.equal(encodeQr("x".repeat(14)).version, 1);
    assert.equal(encodeQr("x".repeat(15)).version, 2);
    assert.equal(encodeQr("x".repeat(26)).version, 2);
    assert.equal(encodeQr("x".repeat(27)).version, 3);
  });

  it("sizes the grid as 4 x version + 17", () => {
    for (let version = 1; version <= 10; version++) {
      const code = encodeQr("x".repeat(VERSION_FILL[version]));
      assert.equal(code.size, code.version * 4 + 17);
    }
  });

  it("refuses a payload beyond its range rather than truncating it", () => {
    assert.throws(() => encodeQr("x".repeat(MAX_BYTES + 1)), QrError);
    // Truncation would be the dangerous failure: a scannable QR code
    // containing half a secret, with nothing to indicate it is wrong.
  });

  it("places the three finder patterns", () => {
    const { modules, size } = encodeQr("finder");

    for (const [row, col] of [[0, 0], [0, size - 7], [size - 7, 0]]) {
      // The 7x7 finder is a dark ring with a 3x3 dark core.
      assert.equal(modules[row][col], true);
      assert.equal(modules[row + 1][col + 1], false);
      assert.equal(modules[row + 3][col + 3], true);
      assert.equal(modules[row + 6][col + 6], true);
    }
  });

  it("places the timing patterns", () => {
    const { modules, size } = encodeQr("timing");
    for (let i = 8; i < size - 8; i++) {
      assert.equal(modules[6][i], i % 2 === 0, `row 6, col ${i}`);
      assert.equal(modules[i][6], i % 2 === 0, `col 6, row ${i}`);
    }
  });

  it("sets the module the spec requires to always be dark", () => {
    const { modules, size } = encodeQr("dark");
    assert.equal(modules[size - 8][8], true);
  });

  it("chooses a mask from the eight the spec defines", () => {
    const code = encodeQr("mask");
    assert.ok(code.mask >= 0 && code.mask <= 7);
  });

  it("produces a different mask choice for different content", () => {
    // Not a correctness requirement, but if every input picked mask 0 the
    // penalty scoring would not be running at all.
    const masks = new Set(
      Array.from({ length: 20 }, (_, i) => encodeQr(`payload-number-${i}`).mask),
    );
    assert.ok(masks.size > 1, "the mask is never changing; penalty scoring is not working");
  });

  it("is deterministic", () => {
    const a = encodeQr("same input");
    const b = encodeQr("same input");
    assert.equal(a.mask, b.mask);
    assert.deepEqual(a.modules, b.modules);
  });

  it("is not blank or solid", () => {
    const { modules, size } = encodeQr("balance");
    const dark = modules.flat().filter(Boolean).length;
    const ratio = dark / (size * size);
    assert.ok(ratio > 0.3 && ratio < 0.7, `dark ratio ${ratio}`);
  });
});

/** A payload length that lands in each version, for the sizing test. */
const VERSION_FILL: Record<number, number> = {
  1: 10, 2: 20, 3: 35, 4: 55, 5: 75, 6: 95, 7: 115, 8: 140, 9: 170, 10: 200,
};
