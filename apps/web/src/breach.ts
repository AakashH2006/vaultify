/**
 * Breach checking against Have I Been Pwned, using k-anonymity.
 *
 * The obvious way to do this would send each password, or its hash, to a
 * third party. Both are unacceptable for a product whose entire claim is that
 * passwords do not leave the tab. The k-anonymity range API avoids it:
 *
 *   1. SHA-1 the password locally.            e.g. 5BAA6 1E4C9B93F3F...
 *   2. Send only the first five hex digits.   GET /range/5BAA6
 *   3. Receive ~800 hash suffixes that share that prefix.
 *   4. Compare locally.
 *
 * The server learns that someone asked about one of roughly 800 passwords. It
 * does not learn which, and it never sees the password or its full hash. Even
 * so, this is the one feature in Vaultify that talks to anyone but our own
 * API, so it is **opt-in and per-run** -- never a background task, never on by
 * default, and the UI says plainly what gets sent before anything is sent.
 *
 * SHA-1 is required by the API and is correct here for the same reason it is
 * correct in TOTP: this is a lookup key in a published corpus, not a
 * signature. Collision resistance is irrelevant to it.
 */

/** The published range endpoint. Must also appear in the CSP's connect-src. */
export const HIBP_RANGE_URL = "https://api.pwnedpasswords.com/range/";

export interface BreachResult {
  /** Times this password appears in the corpus. 0 means not found. */
  readonly count: number;
}

export class BreachCheckError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BreachCheckError";
  }
}

async function sha1Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

/**
 * Check one password.
 *
 * `fetchImpl` is injectable so the tests can assert exactly what crosses the
 * network -- which, for this function, is the whole point.
 */
export async function checkPassword(
  password: string,
  fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis),
): Promise<BreachResult> {
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);

  let response: Response;
  try {
    response = await fetchImpl(HIBP_RANGE_URL + prefix, {
      // No credentials, no referrer, and nothing of ours in a header. The
      // request should be indistinguishable from any other client's.
      credentials: "omit",
      referrerPolicy: "no-referrer",
      headers: { "Add-Padding": "true" },
    });
  } catch {
    throw new BreachCheckError("Could not reach the breach database.");
  }

  if (!response.ok) {
    throw new BreachCheckError(`The breach database replied with ${response.status}.`);
  }

  return { count: countIn(await response.text(), suffix) };
}

/**
 * Find our suffix in the range response.
 *
 * The padding entries the API adds when asked all carry a count of 0, so they
 * fall out naturally without special handling.
 */
export function countIn(body: string, suffix: string): number {
  for (const line of body.split("\n")) {
    const separator = line.indexOf(":");
    if (separator === -1) continue;
    if (line.slice(0, separator).trim().toUpperCase() !== suffix) continue;
    const count = Number.parseInt(line.slice(separator + 1).trim(), 10);
    return Number.isFinite(count) ? count : 0;
  }
  return 0;
}

/**
 * Check many passwords, de-duplicating by prefix.
 *
 * Two benefits, and the second is the one that matters: fewer requests, and
 * **fewer observations for the far end**. A vault with 60 entries that reuses
 * a password across 10 of them should not produce 10 identical lookups --
 * that pattern is itself information.
 *
 * `onProgress` exists because this is a visible, interruptible operation the
 * user explicitly asked for, and it should look like one.
 */
export async function checkPasswords(
  passwords: readonly string[],
  options: {
    fetchImpl?: typeof fetch;
    onProgress?: (done: number, total: number) => void;
    signal?: AbortSignal;
  } = {},
): Promise<Map<string, number>> {
  const unique = [...new Set(passwords)];
  const results = new Map<string, number>();

  // Group by prefix so one request answers for every password sharing it.
  const hashes = await Promise.all(
    unique.map(async (password) => [password, await sha1Hex(password)] as const),
  );

  const byPrefix = new Map<string, Array<readonly [string, string]>>();
  for (const entry of hashes) {
    const prefix = entry[1].slice(0, 5);
    const bucket = byPrefix.get(prefix);
    if (bucket) bucket.push(entry);
    else byPrefix.set(prefix, [entry]);
  }

  const fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis);
  let done = 0;
  const total = byPrefix.size;

  for (const [prefix, entries] of byPrefix) {
    if (options.signal?.aborted) break;

    try {
      const response = await fetchImpl(HIBP_RANGE_URL + prefix, {
        credentials: "omit",
        referrerPolicy: "no-referrer",
        headers: { "Add-Padding": "true" },
        signal: options.signal,
      });
      if (response.ok) {
        const body = await response.text();
        for (const [password, hash] of entries) {
          results.set(password, countIn(body, hash.slice(5)));
        }
      }
    } catch {
      // One failed range leaves those passwords unreported rather than
      // reported as safe. `results` not having a key means "unknown", and the
      // UI distinguishes that from "clean" -- telling a user a password is
      // fine because the network hiccupped would be worse than saying nothing.
    }

    options.onProgress?.(++done, total);
  }

  return results;
}
