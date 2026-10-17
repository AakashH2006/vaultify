/**
 * The breach check.
 *
 * The tests that matter here are about what crosses the network. This is the
 * only feature in Vaultify that contacts anyone but our own API, so "the
 * password is never sent, and neither is its full hash" is a property worth
 * asserting mechanically rather than trusting to review.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";

import {
  BreachCheckError,
  HIBP_RANGE_URL,
  checkPassword,
  checkPasswords,
  countIn,
} from "../src/breach.ts";
import { buildHealthReport, STALE_DAYS, summarise } from "../src/health.ts";
import type { VaultEntry } from "@vaultify/crypto";

/** SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 */
const PASSWORD_PREFIX = "5BAA6";
const PASSWORD_SUFFIX = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

/** A fake range endpoint that records every URL it is asked for. */
function fakeHibp(body: string) {
  const calls: string[] = [];
  const impl: typeof fetch = async (input) => {
    calls.push(String(input));
    return new Response(body, { status: 200 });
  };
  return { calls, fetch: impl };
}

describe("countIn", () => {
  it("finds a suffix and returns its count", () => {
    const body = ["0018A45C4D1DEF81644B54AB7F969B88D65:1", `${PASSWORD_SUFFIX}:12345`].join("\r\n");
    assert.equal(countIn(body, PASSWORD_SUFFIX), 12345);
  });

  it("returns 0 for a suffix that is not listed", () => {
    assert.equal(countIn("ABCDEF:1\r\n012345:2", PASSWORD_SUFFIX), 0);
  });

  it("ignores the zero-count padding entries the API adds", () => {
    const body = ["0000000000000000000000000000000000A:0", `${PASSWORD_SUFFIX}:7`].join("\r\n");
    assert.equal(countIn(body, PASSWORD_SUFFIX), 7);
  });

  it("is case-insensitive about the suffix", () => {
    assert.equal(countIn(`${PASSWORD_SUFFIX.toLowerCase()}:9`, PASSWORD_SUFFIX), 9);
  });

  it("survives a malformed line rather than throwing", () => {
    const body = ["garbage", "", `${PASSWORD_SUFFIX}:3`].join("\n");
    assert.equal(countIn(body, PASSWORD_SUFFIX), 3);
  });
});

describe("checkPassword", () => {
  it("sends only the first five hex digits of the hash", async () => {
    const hibp = fakeHibp(`${PASSWORD_SUFFIX}:12345`);

    const result = await checkPassword("password", hibp.fetch);

    assert.equal(result.count, 12345);
    assert.deepEqual(hibp.calls, [HIBP_RANGE_URL + PASSWORD_PREFIX]);
  });

  it("never puts the password or its full hash on the wire", async () => {
    const hibp = fakeHibp("");
    await checkPassword("correct horse battery staple", hibp.fetch);

    const sent = hibp.calls.join(" ");
    assert.ok(!sent.includes("correct"));
    assert.ok(!sent.includes("horse"));
    // The prefix is 5 characters; the remaining 35 must not appear anywhere.
    assert.equal(sent.replace(HIBP_RANGE_URL, "").length, 5);
  });

  it("reports a clean password as count 0", async () => {
    const hibp = fakeHibp("0000000000000000000000000000000000A:0");
    assert.equal((await checkPassword("password", hibp.fetch)).count, 0);
  });

  it("requests padding, so the response size leaks nothing", async () => {
    let headers: Headers | undefined;
    const impl: typeof fetch = async (_input, init) => {
      headers = new Headers(init?.headers);
      return new Response("", { status: 200 });
    };

    await checkPassword("password", impl);
    assert.equal(headers?.get("add-padding"), "true");
  });

  it("sends no credentials and no referrer", async () => {
    let init: RequestInit | undefined;
    const impl: typeof fetch = async (_input, options) => {
      init = options;
      return new Response("", { status: 200 });
    };

    await checkPassword("password", impl);
    assert.equal(init?.credentials, "omit");
    assert.equal(init?.referrerPolicy, "no-referrer");
  });

  it("raises a clear error when the service is unreachable", async () => {
    const impl: typeof fetch = () => Promise.reject(new Error("offline"));
    await assert.rejects(() => checkPassword("password", impl), BreachCheckError);
  });

  it("raises on a non-OK response rather than reporting the password clean", async () => {
    const impl: typeof fetch = async () => new Response("rate limited", { status: 429 });
    await assert.rejects(() => checkPassword("password", impl), BreachCheckError);
  });
});

describe("checkPasswords", () => {
  it("makes one request per distinct prefix, not per password", async () => {
    const hibp = fakeHibp("");

    // The same password ten times is one lookup -- both for speed and so the
    // reuse pattern is not itself disclosed.
    await checkPasswords(Array<string>(10).fill("password"), { fetchImpl: hibp.fetch });

    assert.equal(hibp.calls.length, 1);
  });

  it("reports a result for every distinct password", async () => {
    const hibp = fakeHibp(`${PASSWORD_SUFFIX}:5`);
    const results = await checkPasswords(["password", "password"], { fetchImpl: hibp.fetch });

    assert.equal(results.size, 1);
    assert.equal(results.get("password"), 5);
  });

  it("leaves a failed lookup absent rather than recording it as clean", async () => {
    // "Unknown" and "safe" must not be confused: telling someone their
    // password is fine because the network hiccupped is worse than silence.
    const impl: typeof fetch = () => Promise.reject(new Error("offline"));
    const results = await checkPasswords(["password"], { fetchImpl: impl });

    assert.equal(results.size, 0);
    assert.equal(results.has("password"), false);
  });

  it("reports progress per request", async () => {
    const hibp = fakeHibp("");
    const seen: Array<[number, number]> = [];

    await checkPasswords(["a", "b", "c"], {
      fetchImpl: hibp.fetch,
      onProgress: (done, total) => seen.push([done, total]),
    });

    assert.equal(seen.length, hibp.calls.length);
    assert.deepEqual(seen.at(-1), [hibp.calls.length, hibp.calls.length]);
  });

  it("stops when aborted", async () => {
    const controller = new AbortController();
    const hibp = fakeHibp("");

    const passwords = Array.from({ length: 20 }, (_, i) => `password-${i}`);
    const promise = checkPasswords(passwords, {
      fetchImpl: hibp.fetch,
      signal: controller.signal,
      onProgress: (done) => {
        if (done === 2) controller.abort();
      },
    });

    await promise;
    assert.ok(hibp.calls.length < passwords.length, `made ${hibp.calls.length} calls`);
  });
});

// ---------------------------------------------------------------------------

const DAY = 86_400_000;
const NOW = Date.UTC(2026, 9, 14);

function entry(overrides: Partial<VaultEntry> & { id: string }): VaultEntry {
  return {
    name: overrides.id,
    username: "ada",
    password: "ledger marble quartz tunnel",
    createdAt: new Date(NOW).toISOString(),
    updatedAt: new Date(NOW).toISOString(),
    ...overrides,
  };
}

describe("buildHealthReport", () => {
  it("reports a clean vault as clean", () => {
    const report = buildHealthReport(
      [entry({ id: "a" }), entry({ id: "b", password: "cobalt lantern ribbon pasture" })],
      { now: NOW },
    );

    assert.deepEqual(report.findings, []);
    assert.equal(report.healthy, 2);
    assert.equal(report.checked, 2);
  });

  it("flags a password used on more than one entry", () => {
    const report = buildHealthReport(
      [
        entry({ id: "a", name: "Bank", password: "shared-one" }),
        entry({ id: "b", name: "Mail", password: "shared-one" }),
        entry({ id: "c", name: "Other" }),
      ],
      { now: NOW },
    );

    const reused = report.findings.filter((finding) => finding.kind === "reused");
    assert.equal(reused.length, 2);
    assert.match(reused[0].detail, /Used on 2 entries/);
  });

  it("flags a weak password", () => {
    const report = buildHealthReport([entry({ id: "a", password: "hunter2" })], { now: NOW });
    assert.equal(report.counts.weak, 1);
  });

  it("flags a breached password, with the count", () => {
    const report = buildHealthReport([entry({ id: "a", password: "pw" })], {
      now: NOW,
      breaches: new Map([["pw", 2_400_000]]),
    });

    const breached = report.findings.find((finding) => finding.kind === "breached");
    assert.ok(breached);
    assert.match(breached.detail, /2\.4 million/);
  });

  it("does not flag a password the breach check reported as clean", () => {
    const report = buildHealthReport(
      [entry({ id: "a", password: "cobalt lantern ribbon pasture" })],
      { now: NOW, breaches: new Map([["cobalt lantern ribbon pasture", 0]]) },
    );
    assert.equal(report.counts.breached, 0);
  });

  it("does not flag a password that was never looked up", () => {
    // An empty map means "we did not check", not "everything is fine".
    const report = buildHealthReport([entry({ id: "a" })], { now: NOW, breaches: new Map() });
    assert.equal(report.counts.breached, 0);
    assert.equal(report.breachChecked, false);
  });

  it("flags an entry untouched for more than a year", () => {
    const old = new Date(NOW - (STALE_DAYS + 30) * DAY).toISOString();
    const report = buildHealthReport([entry({ id: "a", updatedAt: old })], { now: NOW });

    assert.equal(report.counts.stale, 1);
    assert.match(report.findings[0].detail, /Unchanged for 1 year/);
  });

  it("does not flag something changed last week", () => {
    const recent = new Date(NOW - 7 * DAY).toISOString();
    const report = buildHealthReport([entry({ id: "a", updatedAt: recent })], { now: NOW });
    assert.equal(report.counts.stale, 0);
  });

  it("orders breached before reused before weak before stale", () => {
    const old = new Date(NOW - 800 * DAY).toISOString();
    const report = buildHealthReport(
      [
        entry({ id: "stale", name: "Stale", password: "quartz tunnel ledger marble", updatedAt: old }),
        entry({ id: "weak", name: "Weak", password: "abc12" }),
        entry({ id: "r1", name: "Reused A", password: "shared-strong-9!Xp" }),
        entry({ id: "r2", name: "Reused B", password: "shared-strong-9!Xp" }),
        entry({ id: "pwned", name: "Pwned", password: "breached-one" }),
      ],
      { now: NOW, breaches: new Map([["breached-one", 99]]) },
    );

    assert.equal(report.findings[0].kind, "breached");
    const kinds = report.findings.map((finding) => finding.kind);
    assert.deepEqual(
      [...kinds].sort((a, b) => kinds.indexOf(a) - kinds.indexOf(b)),
      kinds,
      "findings are not in severity order",
    );
    assert.equal(kinds.at(-1), "stale");
  });

  it("counts an entry with several problems once as unhealthy", () => {
    const report = buildHealthReport(
      [
        entry({ id: "a", password: "abc12" }),
        entry({ id: "b", password: "abc12" }),
      ],
      { now: NOW, breaches: new Map([["abc12", 500]]) },
    );

    assert.equal(report.healthy, 0);
    assert.equal(report.checked, 2);
    assert.ok(report.findings.length > 2, "expected several findings across two entries");
  });

  it("skips an entry with no password at all", () => {
    const report = buildHealthReport([entry({ id: "a", password: "" })], { now: NOW });
    assert.deepEqual(report.findings, []);
  });
});

describe("summarise", () => {
  it("says so when there is nothing to check", () => {
    assert.match(summarise(buildHealthReport([], { now: NOW })), /Nothing to check/);
  });

  it("distinguishes a clean report from a clean-and-breach-checked one", () => {
    const entries = [entry({ id: "a" })];

    const offline = summarise(buildHealthReport(entries, { now: NOW }));
    const checked = summarise(
      buildHealthReport(entries, {
        now: NOW,
        breaches: new Map([["ledger marble quartz tunnel", 0]]),
      }),
    );

    assert.match(offline, /No reused or weak passwords/);
    assert.match(checked, /known breach/);
  });

  it("lists the counts it found", () => {
    const report = buildHealthReport(
      [entry({ id: "a", password: "abc12" }), entry({ id: "b", password: "abc12" })],
      { now: NOW },
    );
    const summary = summarise(report);

    assert.match(summary, /2 reused/);
    assert.match(summary, /2 weak/);
  });
});
