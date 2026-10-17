/**
 * A QR encoder, because the alternative was a dependency.
 *
 * Enrolling an authenticator without a QR code means asking the user to type
 * 32 base32 characters into a phone, which they will get wrong. So the client
 * needs an encoder; and the project's whole security argument is that the
 * bundle is small enough to read, so pulling in someone else's is the one
 * thing we should not do. This file is the price of that position: about 370
 * lines of ISO/IEC 18004, implemented narrowly.
 *
 * Narrowly means:
 *   - **Byte mode only.** An otpauth URI is mixed case with punctuation, so
 *     numeric and alphanumeric modes would never be selected anyway.
 *   - **Error correction level M** (~15% recovery). The usual choice for a
 *     code displayed on a screen rather than printed on a box.
 *   - **Versions 1-10**, which covers up to 213 bytes. An otpauth URI is
 *     around 135.
 *
 * Nothing here is a security control -- it is a drawing routine. It is
 * included in the audit surface only because every byte on this origin is.
 *
 * `test/qr.test.ts` round-trips the output through a reader that undoes the
 * placement, the mask and the interleaving, which is what makes it possible
 * to trust this at all without a camera.
 */

// ---------------------------------------------------------------------------
// GF(256) -- the field Reed-Solomon works in
// ---------------------------------------------------------------------------

/**
 * Log and antilog tables for GF(2^8) with the QR primitive polynomial
 * 0x11d. Multiplication becomes addition of logarithms, which turns the
 * error-correction maths into table lookups.
 */
const EXP = new Uint8Array(512);
const LOG = new Uint8Array(256);

(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    EXP[i] = x;
    LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d; // reduce by the primitive polynomial
  }
  for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return EXP[LOG[a] + LOG[b]];
}

/** Generator polynomial for `degree` error-correction codewords. */
function generatorPoly(degree: number): Uint8Array {
  let poly = Uint8Array.of(1);
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= poly[j];
      next[j + 1] ^= gfMul(poly[j], EXP[i]);
    }
    poly = next;
  }
  return poly;
}

/** Polynomial long division; the remainder is the EC codewords. */
function errorCorrection(data: Uint8Array, count: number): Uint8Array {
  const generator = generatorPoly(count);
  const remainder = new Uint8Array(count);

  for (const byte of data) {
    const factor = byte ^ remainder[0];
    remainder.copyWithin(0, 1);
    remainder[count - 1] = 0;
    for (let i = 0; i < count; i++) {
      remainder[i] ^= gfMul(generator[i + 1], factor);
    }
  }
  return remainder;
}

// ---------------------------------------------------------------------------
// Version tables (error correction level M only)
// ---------------------------------------------------------------------------

interface VersionSpec {
  /** Total data codewords available at level M. */
  readonly dataCodewords: number;
  /** EC codewords per block. */
  readonly ecPerBlock: number;
  /** [count, dataCodewords] for each block group. */
  readonly groups: ReadonlyArray<readonly [number, number]>;
}

/** Versions 1-10 at level M. Straight from ISO/IEC 18004 table 9. */
const VERSIONS: Record<number, VersionSpec> = {
  1: { dataCodewords: 16, ecPerBlock: 10, groups: [[1, 16]] },
  2: { dataCodewords: 28, ecPerBlock: 16, groups: [[1, 28]] },
  3: { dataCodewords: 44, ecPerBlock: 26, groups: [[1, 44]] },
  4: { dataCodewords: 64, ecPerBlock: 18, groups: [[2, 32]] },
  5: { dataCodewords: 86, ecPerBlock: 24, groups: [[2, 43]] },
  6: { dataCodewords: 108, ecPerBlock: 16, groups: [[4, 27]] },
  7: { dataCodewords: 124, ecPerBlock: 18, groups: [[4, 31]] },
  8: { dataCodewords: 154, ecPerBlock: 22, groups: [[2, 38], [2, 39]] },
  9: { dataCodewords: 182, ecPerBlock: 22, groups: [[3, 36], [2, 37]] },
  10: { dataCodewords: 216, ecPerBlock: 26, groups: [[4, 43], [1, 44]] },
};

/** Row/column centres of the alignment patterns, by version. */
const ALIGNMENT: Record<number, readonly number[]> = {
  1: [],
  2: [6, 18],
  3: [6, 22],
  4: [6, 26],
  5: [6, 30],
  6: [6, 34],
  7: [6, 22, 38],
  8: [6, 24, 42],
  9: [6, 26, 46],
  10: [6, 28, 50],
};

export const MAX_VERSION = 10;
/** Largest payload this encoder will take, in bytes. */
export const MAX_BYTES = VERSIONS[MAX_VERSION].dataCodewords - 2;

export class QrError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "QrError";
  }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/** Smallest version that fits `byteLength` bytes in byte mode at level M. */
function chooseVersion(byteLength: number): number {
  for (let version = 1; version <= MAX_VERSION; version++) {
    // 4 bits mode + 8 or 16 bits length, rounded up to whole codewords.
    const headerBits = 4 + (version < 10 ? 8 : 16);
    const capacity = VERSIONS[version].dataCodewords * 8;
    if (headerBits + byteLength * 8 <= capacity) return version;
  }
  throw new QrError(
    `${byteLength} bytes is more than this encoder handles (limit ${MAX_BYTES}).`,
  );
}

class BitWriter {
  readonly bits: number[] = [];

  push(value: number, length: number): void {
    for (let i = length - 1; i >= 0; i--) this.bits.push((value >>> i) & 1);
  }

  get length(): number {
    return this.bits.length;
  }

  toCodewords(count: number): Uint8Array {
    const out = new Uint8Array(count);
    for (let i = 0; i < this.bits.length; i++) {
      if (this.bits[i]) out[i >> 3] |= 0x80 >> (i & 7);
    }
    return out;
  }
}

function encodeData(bytes: Uint8Array, version: number): Uint8Array {
  const spec = VERSIONS[version];
  const capacityBits = spec.dataCodewords * 8;

  const writer = new BitWriter();
  writer.push(0b0100, 4); // byte mode
  writer.push(bytes.length, version < 10 ? 8 : 16);
  for (const byte of bytes) writer.push(byte, 8);

  // Terminator: up to four zero bits, truncated if the capacity is tight.
  writer.push(0, Math.min(4, capacityBits - writer.length));
  // Pad to a byte boundary.
  if (writer.length % 8 !== 0) writer.push(0, 8 - (writer.length % 8));

  const codewords = writer.toCodewords(spec.dataCodewords);

  // Fill the remainder with the alternating pad bytes the spec mandates.
  const used = writer.length / 8;
  const PADS = [0xec, 0x11];
  for (let i = used; i < spec.dataCodewords; i++) PADS[(i - used) % 2];
  for (let i = used, p = 0; i < spec.dataCodewords; i++, p++) codewords[i] = PADS[p % 2];

  return codewords;
}

/**
 * Split into blocks, compute EC per block, and interleave.
 *
 * The interleaving is what makes the error correction useful: a scratch
 * across the printed code damages a run of adjacent modules, and spreading
 * each block's codewords apart means that run lands in several blocks a
 * little rather than one block fatally.
 */
function buildCodewords(data: Uint8Array, version: number): Uint8Array {
  const spec = VERSIONS[version];

  const dataBlocks: Uint8Array[] = [];
  const ecBlocks: Uint8Array[] = [];
  let offset = 0;

  for (const [count, size] of spec.groups) {
    for (let i = 0; i < count; i++) {
      const block = data.subarray(offset, offset + size);
      offset += size;
      dataBlocks.push(block);
      ecBlocks.push(errorCorrection(block, spec.ecPerBlock));
    }
  }

  const result: number[] = [];
  const longest = Math.max(...dataBlocks.map((block) => block.length));
  for (let i = 0; i < longest; i++) {
    for (const block of dataBlocks) if (i < block.length) result.push(block[i]);
  }
  for (let i = 0; i < spec.ecPerBlock; i++) {
    for (const block of ecBlocks) result.push(block[i]);
  }

  return Uint8Array.from(result);
}

// ---------------------------------------------------------------------------
// Module placement
// ---------------------------------------------------------------------------

type Grid = Int8Array[]; // -1 = free, 0 = light, 1 = dark

function emptyGrid(size: number): Grid {
  return Array.from({ length: size }, () => new Int8Array(size).fill(-1));
}

function placeFinder(grid: Grid, row: number, col: number): void {
  for (let r = -1; r <= 7; r++) {
    for (let c = -1; c <= 7; c++) {
      const y = row + r;
      const x = col + c;
      if (y < 0 || y >= grid.length || x < 0 || x >= grid.length) continue;
      const inRing = (r >= 0 && r <= 6 && (c === 0 || c === 6)) ||
        (c >= 0 && c <= 6 && (r === 0 || r === 6));
      const inCore = r >= 2 && r <= 4 && c >= 2 && c <= 4;
      grid[y][x] = inRing || inCore ? 1 : 0;
    }
  }
}

function placeFunctionPatterns(grid: Grid, version: number): void {
  const size = grid.length;

  placeFinder(grid, 0, 0);
  placeFinder(grid, 0, size - 7);
  placeFinder(grid, size - 7, 0);

  // Timing patterns: alternating modules joining the finders.
  for (let i = 8; i < size - 8; i++) {
    const value = i % 2 === 0 ? 1 : 0;
    grid[6][i] = value;
    grid[i][6] = value;
  }

  // Alignment patterns, skipping the three that would sit on a finder.
  const centres = ALIGNMENT[version];
  for (const row of centres) {
    for (const col of centres) {
      const onFinder =
        (row === 6 && col === 6) ||
        (row === 6 && col === size - 7) ||
        (row === size - 7 && col === 6);
      if (onFinder) continue;
      for (let r = -2; r <= 2; r++) {
        for (let c = -2; c <= 2; c++) {
          const ring = Math.max(Math.abs(r), Math.abs(c));
          grid[row + r][col + c] = ring === 1 ? 0 : 1;
        }
      }
    }
  }

  // Always dark, for reasons the spec does not justify either.
  grid[size - 8][8] = 1;

  // Reserve the format-information areas so the data walk skips them.
  for (let i = 0; i < 9; i++) {
    if (grid[8][i] === -1) grid[8][i] = 0;
    if (grid[i][8] === -1) grid[i][8] = 0;
  }
  for (let i = 0; i < 8; i++) {
    if (grid[8][size - 1 - i] === -1) grid[8][size - 1 - i] = 0;
    if (grid[size - 1 - i][8] === -1) grid[size - 1 - i][8] = 0;
  }

  // Version information, for version 7 and up.
  if (version >= 7) {
    const bits = versionBits(version);
    for (let i = 0; i < 18; i++) {
      const bit = (bits >> i) & 1;
      const r = Math.floor(i / 3);
      const c = size - 11 + (i % 3);
      grid[r][c] = bit;
      grid[c][r] = bit;
    }
  }
}

/** 6 data bits plus 12 bits of BCH(18,6) error correction. */
function versionBits(version: number): number {
  let remainder = version << 12;
  for (let i = 0; i < 12; i++) {
    if ((remainder >> (17 - i)) & 1) remainder ^= 0x1f25 << (5 - i);
  }
  return (version << 12) | (remainder & 0xfff);
}

/** 5 data bits (EC level + mask) plus BCH(15,5), XORed with the spec mask. */
function formatBits(mask: number): number {
  const ecLevelM = 0b00; // level M
  const data = (ecLevelM << 3) | mask;
  let remainder = data << 10;
  for (let i = 0; i < 10; i++) {
    if ((remainder >> (14 - i)) & 1) remainder ^= 0x537 << (4 - i);
  }
  return ((data << 10) | (remainder & 0x3ff)) ^ 0x5412;
}

function placeFormat(grid: Grid, mask: number): void {
  const size = grid.length;
  const bits = formatBits(mask);

  for (let i = 0; i < 15; i++) {
    const bit = (bits >> i) & 1;

    // Copy one: around the top-left finder.
    if (i < 6) grid[8][i] = bit;
    else if (i === 6) grid[8][7] = bit;
    else if (i === 7) grid[8][8] = bit;
    else if (i === 8) grid[7][8] = bit;
    else grid[14 - i][8] = bit;

    // Copy two: split between the other two finders, so the format survives
    // damage to any one corner. Bits 0-6 run up the left edge and bits 7-14
    // along the top -- the boundary is 7, not 8, because grid[size - 8][8] is
    // the always-dark module and is not part of the format area. Writing a
    // format bit there produces a code that still scans (the first copy is
    // intact) but violates the spec, so only a conformance check catches it.
    if (i < 7) grid[size - 1 - i][8] = bit;
    else grid[8][size - 15 + i] = bit;
  }
}

/** The zig-zag walk: two columns at a time, right to left, alternating up and
 *  down, skipping the vertical timing column. */
function placeData(grid: Grid, codewords: Uint8Array): void {
  const size = grid.length;
  let bitIndex = 0;
  let upward = true;

  for (let right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5; // the timing column is not part of the walk

    for (let step = 0; step < size; step++) {
      const row = upward ? size - 1 - step : step;
      for (const col of [right, right - 1]) {
        if (grid[row][col] !== -1) continue;
        const bit =
          bitIndex < codewords.length * 8
            ? (codewords[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1
            : 0;
        grid[row][col] = bit;
        bitIndex++;
      }
    }
    upward = !upward;
  }
}

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

/** Which modules are function patterns, and so must not be masked. */
function functionMask(version: number, size: number): boolean[][] {
  const probe = emptyGrid(size);
  placeFunctionPatterns(probe, version);
  return probe.map((row) => Array.from(row, (cell) => cell !== -1));
}

/**
 * Penalty scoring from the spec. Lower is better.
 *
 * The point is readability, not security: a mask that happens to produce
 * long uniform runs, large blocks, or something that looks like a finder
 * pattern will confuse a scanner, so all eight are tried and the least bad
 * wins.
 */
function penalty(grid: Grid): number {
  const size = grid.length;
  let score = 0;

  // Rule 1: runs of five or more identical modules in a row or column.
  for (let i = 0; i < size; i++) {
    for (const line of [
      Array.from({ length: size }, (_, j) => grid[i][j]),
      Array.from({ length: size }, (_, j) => grid[j][i]),
    ]) {
      let run = 1;
      for (let j = 1; j < size; j++) {
        if (line[j] === line[j - 1]) {
          run++;
          if (run === 5) score += 3;
          else if (run > 5) score += 1;
        } else run = 1;
      }
    }
  }

  // Rule 2: 2x2 blocks of one colour.
  for (let r = 0; r < size - 1; r++) {
    for (let c = 0; c < size - 1; c++) {
      const v = grid[r][c];
      if (v === grid[r][c + 1] && v === grid[r + 1][c] && v === grid[r + 1][c + 1]) score += 3;
    }
  }

  // Rule 3: the 1:1:3:1:1 finder-like pattern anywhere else.
  const finder = [1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 0];
  const reversed = [...finder].reverse();
  for (let i = 0; i < size; i++) {
    for (let j = 0; j <= size - 11; j++) {
      const row = Array.from({ length: 11 }, (_, k) => grid[i][j + k]);
      const col = Array.from({ length: 11 }, (_, k) => grid[j + k][i]);
      for (const line of [row, col]) {
        if (line.every((v, k) => v === finder[k]) || line.every((v, k) => v === reversed[k])) {
          score += 40;
        }
      }
    }
  }

  // Rule 4: deviation from a 50/50 light/dark balance.
  let dark = 0;
  for (const row of grid) for (const cell of row) if (cell === 1) dark++;
  const percent = (dark * 100) / (size * size);
  score += Math.floor(Math.abs(percent - 50) / 5) * 10;

  return score;
}

export interface QrCode {
  readonly size: number;
  readonly version: number;
  readonly mask: number;
  /** `true` is a dark module. */
  readonly modules: boolean[][];
}

/** Encode text (UTF-8) into a QR matrix. */
export function encodeQr(text: string): QrCode {
  const bytes = new TextEncoder().encode(text);
  const version = chooseVersion(bytes.length);
  const size = version * 4 + 17;

  const codewords = buildCodewords(encodeData(bytes, version), version);
  const reserved = functionMask(version, size);

  let best: { grid: Grid; mask: number; score: number } | null = null;

  for (let mask = 0; mask < 8; mask++) {
    const grid = emptyGrid(size);
    placeFunctionPatterns(grid, version);
    placeData(grid, codewords);

    for (let r = 0; r < size; r++) {
      for (let c = 0; c < size; c++) {
        if (!reserved[r][c] && MASKS[mask](r, c)) grid[r][c] ^= 1;
      }
    }
    placeFormat(grid, mask);

    const score = penalty(grid);
    if (!best || score < best.score) best = { grid, mask, score };
  }

  const chosen = best!;
  return {
    size,
    version,
    mask: chosen.mask,
    modules: chosen.grid.map((row) => Array.from(row, (cell) => cell === 1)),
  };
}

/**
 * Render as SVG.
 *
 * One `<path>` of rectangles rather than a node per module: a version-8 code
 * is 2,209 modules, and that many DOM elements is slow to build and slower to
 * repaint. The quiet zone is mandatory -- scanners need it to find the code.
 */
export function qrToSvg(code: QrCode, options: { quietZone?: number } = {}): SVGSVGElement {
  const quiet = options.quietZone ?? 4;
  const total = code.size + quiet * 2;

  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", `0 0 ${total} ${total}`);
  svg.setAttribute("shape-rendering", "crispEdges");
  svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", "QR code for your authenticator app");

  const background = document.createElementNS("http://www.w3.org/2000/svg", "rect");
  background.setAttribute("width", String(total));
  background.setAttribute("height", String(total));
  // Always white, never the theme background: a scanner needs the contrast,
  // and a dark-mode QR code on a dark card does not scan.
  background.setAttribute("fill", "#ffffff");
  svg.appendChild(background);

  let path = "";
  for (let r = 0; r < code.size; r++) {
    for (let c = 0; c < code.size; c++) {
      if (code.modules[r][c]) path += `M${c + quiet} ${r + quiet}h1v1h-1z`;
    }
  }

  const node = document.createElementNS("http://www.w3.org/2000/svg", "path");
  node.setAttribute("d", path);
  node.setAttribute("fill", "#000000");
  svg.appendChild(node);

  return svg;
}
