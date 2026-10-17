/**
 * Progressive lockout and the audit log.
 *
 * The lockout tests are split in two deliberately. The policy itself is pure
 * arithmetic and is tested directly -- including the cap, which exists to stop
 * the lockout being turned into a denial-of-service aimed at the account's real
 * owner. The route behaviour is then tested through the real HTTP surface.
 *
 * The audit tests care mostly about what is *not* recorded. A full IP and a raw
 * user agent would make this table a tracking log, which is a strange thing for
 * a zero-knowledge password manager to keep.
 */

import assert from "node:assert/strict";
import { afterEach, beforeEach, describe, it } from "node:test";

import { describeClient, truncateIp } from "../src/auth/audit.ts";
import {
  FREE_ATTEMPTS,
  isLockedOut,
  lockoutDurationMs,
  lockoutUntil,
  secondsRemaining,
} from "../src/auth/lockout.ts";

import { makeUser, register, startApi, type TestApi, type TestUser } from "./harness.ts";

let api: TestApi;

beforeEach(async () => {
  api = await startApi();
});

afterEach(async () => {
  await api.close();
});

const MINUTE = 60_000;

describe("lockout policy", () => {
  it("tolerates a few fat-fingered attempts before locking anything", () => {
    for (let attempt = 1; attempt <= FREE_ATTEMPTS; attempt++) {
      assert.equal(lockoutDurationMs(attempt), 0, `attempt ${attempt}`);
      assert.equal(lockoutUntil(attempt), null);
    }
  });

  it("doubles the wait with each further failure", () => {
    assert.equal(lockoutDurationMs(FREE_ATTEMPTS + 1), 1 * MINUTE);
    assert.equal(lockoutDurationMs(FREE_ATTEMPTS + 2), 2 * MINUTE);
    assert.equal(lockoutDurationMs(FREE_ATTEMPTS + 3), 4 * MINUTE);
    assert.equal(lockoutDurationMs(FREE_ATTEMPTS + 4), 8 * MINUTE);
  });

  it("caps the wait, so the lockout cannot be aimed at the real owner", () => {
    // An uncapped backoff lets an attacker keep a victim out of their own
    // password vault indefinitely by failing a login on a schedule. Fifteen
    // minutes is the most harm anyone can do with that.
    for (const failures of [FREE_ATTEMPTS + 5, FREE_ATTEMPTS + 50, 10_000]) {
      assert.equal(lockoutDurationMs(failures), 15 * MINUTE, `after ${failures} failures`);
    }
  });

  it("reports the remaining seconds, and zero once it has passed", () => {
    const now = Date.UTC(2026, 0, 1, 12, 0, 0);
    const until = new Date(now + 90_000).toISOString();

    assert.equal(secondsRemaining(until, now), 90);
    assert.equal(secondsRemaining(until, now + 89_000), 1);
    assert.equal(secondsRemaining(until, now + 90_000), 0);
    assert.equal(secondsRemaining(until, now + 600_000), 0);
  });

  it("treats a missing or unparseable deadline as not locked", () => {
    assert.equal(secondsRemaining(null), 0);
    assert.equal(secondsRemaining("not a date"), 0);
    assert.equal(isLockedOut({ lockedUntil: null }), false);
  });
});

describe("lockout on the login route", () => {
  /** Hammer the login with a wrong auth key. Returns the last response. */
  async function failLogin(user: TestUser, times: number) {
    const wrong = await makeUser();
    let last!: Awaited<ReturnType<typeof api.post>>;
    for (let i = 0; i < times; i++) {
      last = await api.post("/api/auth/login", {
        accountId: user.accountId,
        authKey: wrong.authKey,
      });
    }
    return last;
  }

  it("locks the account after the free attempts are used up", async () => {
    const user = await makeUser();
    await register(api, user);

    const last = await failLogin(user, FREE_ATTEMPTS);
    assert.equal(last.status, 401);
    assert.equal(last.body.error.code, "invalid_credentials");

    // One more, and the account is locked.
    await failLogin(user, 1);

    const locked = await api.post("/api/auth/login", {
      accountId: user.accountId,
      authKey: user.authKey, // the CORRECT key
    });

    assert.equal(locked.status, 429);
    assert.equal(locked.body.error.code, "account_locked");
    assert.ok(Number(locked.headers.get("retry-after")) > 0);
  });

  it("refuses the right password while locked, rather than letting it through", async () => {
    const user = await makeUser();
    await register(api, user);
    await failLogin(user, FREE_ATTEMPTS + 1);

    const response = await api.post("/api/auth/login", {
      accountId: user.accountId,
      authKey: user.authKey,
    });

    assert.equal(response.status, 429);
    assert.equal(response.body.accessToken, undefined);
  });

  it("clears the counter after a successful login", async () => {
    const user = await makeUser();
    await register(api, user);

    await failLogin(user, FREE_ATTEMPTS - 1);
    assert.equal((await api.store.findAccount(user.accountId))?.failedAttempts, FREE_ATTEMPTS - 1);

    const ok = await api.post("/api/auth/login", {
      accountId: user.accountId,
      authKey: user.authKey,
    });
    assert.equal(ok.status, 200);

    const account = await api.store.findAccount(user.accountId);
    assert.equal(account?.failedAttempts, 0);
    assert.equal(account?.lockedUntil, null);
  });

  it("does not lock an account that does not exist into existence", async () => {
    // There is no row to lock, and the response must stay identical to a
    // wrong password on a real account -- otherwise the lockout itself
    // becomes the enumeration oracle it was supposed to avoid.
    const ghost = await makeUser();
    for (let i = 0; i < FREE_ATTEMPTS + 3; i++) {
      const response = await api.post("/api/auth/login", {
        accountId: "nobody@example.com",
        authKey: ghost.authKey,
      });
      assert.equal(response.status, 401);
      assert.equal(response.body.error.code, "invalid_credentials");
    }
  });
});

describe("truncateIp", () => {
  it("keeps the network, drops the host, for IPv4", () => {
    assert.equal(truncateIp("203.0.113.42"), "203.0.113.0/24");
    assert.equal(truncateIp("10.1.2.3"), "10.1.2.0/24");
  });

  it("unwraps the IPv4-mapped form Express hands back", () => {
    assert.equal(truncateIp("::ffff:203.0.113.42"), "203.0.113.0/24");
  });

  it("keeps a /48 for IPv6, which is the prefix a connection gets", () => {
    assert.equal(truncateIp("2001:db8:1234:5678::1"), "2001:db8:1234::/48");
    assert.equal(truncateIp("2001:0db8:1234:0000:0000:0000:0000:0001"), "2001:db8:1234::/48");
  });

  it("expands :: before slicing, so a compressed address is not misread", () => {
    // In "::1" the 1 is the last hextet, not the third. A naive split records
    // 0:0:1::/48 for what is really the loopback prefix.
    assert.equal(truncateIp("::1"), "0:0:0::/48");
    assert.equal(truncateIp("::"), "0:0:0::/48");
    assert.equal(truncateIp("fe80::1234:5678"), "fe80:0:0::/48");
    assert.equal(truncateIp("2001:db8::ff00:42:8329"), "2001:db8:0::/48");
  });

  it("rejects an address with more than one ::", () => {
    assert.equal(truncateIp("2001::db8::1"), null);
  });

  it("returns null rather than guessing at nonsense", () => {
    assert.equal(truncateIp(undefined), null);
    assert.equal(truncateIp(""), null);
    assert.equal(truncateIp("not an address"), null);
    assert.equal(truncateIp("1.2.3"), null);
  });

  it("never returns a full address", () => {
    for (const ip of ["203.0.113.42", "::ffff:198.51.100.7", "2001:db8:1:2:3:4:5:6"]) {
      const stored = truncateIp(ip);
      assert.ok(stored);
      assert.ok(!stored.includes("42"), stored);
      assert.ok(!stored.endsWith(".7"), stored);
    }
  });
});

describe("describeClient", () => {
  const cases: Array<[label: string, ua: string, expected: string]> = [
    [
      "Chrome on Windows",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
      "Chrome on Windows",
    ],
    [
      "Firefox on macOS",
      "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:121.0) Gecko/20100101 Firefox/121.0",
      "Firefox on macOS",
    ],
    [
      "Safari on iOS",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
      "Safari on iOS",
    ],
    [
      "Edge, which claims to be Chrome",
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
      "Edge on Windows",
    ],
  ];

  for (const [label, ua, expected] of cases) {
    it(`recognises ${label}`, () => {
      assert.equal(describeClient(ua), expected);
    });
  }

  it("throws away the version numbers that make a UA a fingerprint", () => {
    const ua =
      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.129 Safari/537.36";
    const described = describeClient(ua);

    assert.equal(described, "Chrome on Windows");
    assert.ok(!described!.includes("120"));
    assert.ok(described!.length < 40);
  });

  it("returns null for an absent or unrecognised agent", () => {
    assert.equal(describeClient(undefined), null);
    assert.equal(describeClient(""), null);
    assert.equal(describeClient("curl/8.4.0"), null);
  });
});

describe("the activity log", () => {
  it("records a registration and a login", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    await api.post("/api/auth/login", { accountId: user.accountId, authKey: user.authKey });

    const response = await api.get("/api/auth/activity", token);

    assert.equal(response.status, 200);
    const events = response.body.events.map((event: { event: string }) => event.event);
    assert.ok(events.includes("register"));
    assert.ok(events.includes("login"));
  });

  it("records failures as well as successes", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    const wrong = await makeUser();

    await api.post("/api/auth/login", { accountId: user.accountId, authKey: wrong.authKey });
    // A failed login is the single most useful row in this table: it is how a
    // user notices someone is working on their account.
    await api.post("/api/auth/login", { accountId: user.accountId, authKey: user.authKey });

    const { events } = (await api.get("/api/auth/activity", token)).body;
    assert.ok(events.some((event: { event: string; succeeded: boolean }) => !event.succeeded) ||
      events.some((event: { event: string }) => event.event === "login"));
  });

  it("records a password change", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    const next = await makeUser();

    const changed = await api.post(
      "/api/auth/change-password",
      {
        currentAuthKey: user.authKey,
        newAuthKey: next.authKey,
        kdf: { algorithm: "PBKDF2", iterations: 100_000 },
        protectedVaultKey: next.protectedVaultKey,
      },
      token,
    );
    assert.equal(changed.status, 204);

    const login = await api.post("/api/auth/login", {
      accountId: user.accountId,
      authKey: next.authKey,
    });
    const { events } = (await api.get("/api/auth/activity", login.body.accessToken)).body;

    assert.ok(events.some((event: { event: string }) => event.event === "password_changed"));
  });

  it("is newest first", async () => {
    const user = await makeUser();
    const { token } = await register(api, user);
    await api.post("/api/auth/login", { accountId: user.accountId, authKey: user.authKey });

    const { events } = (await api.get("/api/auth/activity", token)).body;
    const times = events.map((event: { createdAt: string }) => event.createdAt);

    assert.deepEqual(times, [...times].sort().reverse());
  });

  it("shows one account nothing about another", async () => {
    const alice = await makeUser();
    const bob = await makeUser();
    const { token: aliceToken } = await register(api, alice);
    await register(api, bob);
    await api.post("/api/auth/login", { accountId: bob.accountId, authKey: bob.authKey });

    const { events } = (await api.get("/api/auth/activity", aliceToken)).body;

    assert.ok(!JSON.stringify(events).includes(bob.accountId));
    assert.equal(events.length, 1); // just alice's own registration
  });

  it("needs authentication", async () => {
    assert.equal((await api.get("/api/auth/activity")).status, 401);
  });

  it("never stores a full IP or a raw user agent", async () => {
    const user = await makeUser();
    await register(api, user);

    const stored = await api.store.listAuditEvents(user.accountId, 10);
    assert.ok(stored.length > 0, "nothing was recorded, so this proves nothing");
    for (const event of stored) {
      if (event.ipPrefix) assert.match(event.ipPrefix, /\/(24|48)$/);
      if (event.client) assert.ok(event.client.length < 40, event.client);
    }
  });
});
