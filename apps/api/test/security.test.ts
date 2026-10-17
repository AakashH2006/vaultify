import { test, describe, afterEach } from "node:test";
import assert from "node:assert/strict";
import { SignJWT } from "jose";

import { register, startApi, type TestApi } from "./harness.ts";
import { loadConfig } from "../src/config.ts";

let api: TestApi;
const boot = async (env?: Record<string, string>) => (api = await startApi(env));

const SECRET = "test-secret-that-is-long-enough-to-pass-validation";

afterEach(async () => {
  await api?.close();
});

describe("configuration", () => {
  test("refuses to start without a signing secret", () => {
    assert.throws(() => loadConfig({ NODE_ENV: "test" }), /JWT_SECRET/);
  });

  test("refuses a short signing secret", () => {
    assert.throws(() => loadConfig({ NODE_ENV: "test", JWT_SECRET: "short" }), /at least 32/);
  });

  test("refuses the in-memory store in production", () => {
    assert.throws(
      () => loadConfig({ NODE_ENV: "production", JWT_SECRET: SECRET }),
      /DATABASE_URL is required in production/,
    );
  });

  test("requires HTTPS in production by default", () => {
    const config = loadConfig({
      NODE_ENV: "production",
      JWT_SECRET: SECRET,
      DATABASE_URL: "postgres://localhost/vaultify",
    });
    assert.equal(config.requireHttps, true);
  });

  test("TRUST_PROXY=false is actually false", () => {
    // z.coerce.boolean() would turn the string "false" into true.
    const config = loadConfig({ NODE_ENV: "test", JWT_SECRET: SECRET, TRUST_PROXY: "false" });
    assert.equal(config.TRUST_PROXY, false);
  });
});

describe("response headers", () => {
  test("sets the hardening headers on every response", async () => {
    await boot();
    const response = await api.get("/api/health");

    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.equal(response.headers.get("x-frame-options"), "DENY");
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
    assert.equal(response.headers.get("cache-control"), "no-store");
    assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  });

  test("does not advertise the stack", async () => {
    await boot();
    const response = await api.get("/api/health");
    assert.equal(response.headers.get("x-powered-by"), null);
  });

  test("sends HSTS only when HTTPS is required", async () => {
    await boot();
    assert.equal((await api.get("/api/health")).headers.get("strict-transport-security"), null);
  });

  test("refuses plain HTTP when HTTPS is required", async () => {
    await boot({ REQUIRE_HTTPS: "true" });
    const response = await api.get("/api/health");
    assert.equal(response.status, 403);
    assert.equal(response.body.error.code, "https_required");
    assert.ok(response.headers.get("strict-transport-security"));
  });
});

describe("CORS", () => {
  test("allows the configured origin", async () => {
    await boot({ CORS_ORIGIN: "https://vault.example.com" });
    const response = await api.request("GET", "/api/health", {
      headers: { Origin: "https://vault.example.com" },
    });
    assert.equal(response.headers.get("access-control-allow-origin"), "https://vault.example.com");
  });

  test("does not reflect an arbitrary origin", async () => {
    await boot({ CORS_ORIGIN: "https://vault.example.com" });
    const response = await api.request("GET", "/api/health", {
      headers: { Origin: "https://evil.example.com" },
    });
    assert.equal(response.headers.get("access-control-allow-origin"), null);
    assert.equal(response.headers.get("vary"), "Origin");
  });
});

describe("token handling", () => {
  test("rejects a token signed with a different secret", async () => {
    await boot();
    const forged = await new SignJWT({ sid: crypto.randomUUID() })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject("victim@example.com")
      .setIssuer("vaultify")
      .setAudience("vaultify-api")
      .setExpirationTime("1h")
      .sign(new TextEncoder().encode("a-completely-different-secret-value-x"));

    assert.equal((await api.get("/api/vault", forged)).status, 401);
  });

  test("rejects an unsigned token", async () => {
    await boot();
    const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({
        sub: "victim@example.com",
        sid: crypto.randomUUID(),
        iss: "vaultify",
        aud: "vaultify-api",
        exp: Math.floor(Date.now() / 1000) + 3600,
      }),
    ).toString("base64url");

    assert.equal((await api.get("/api/vault", header + "." + payload + ".")).status, 401);
  });

  test("rejects a valid signature whose session was never created", async () => {
    // Signature alone is not authority: the session must exist in the store.
    await boot();
    const orphan = await new SignJWT({ sid: crypto.randomUUID() })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject("someone@example.com")
      .setIssuer("vaultify")
      .setAudience("vaultify-api")
      .setExpirationTime("1h")
      .sign(new TextEncoder().encode(SECRET));

    assert.equal((await api.get("/api/vault", orphan)).status, 401);
  });

  test("rejects an expired token", async () => {
    await boot({ ACCESS_TOKEN_TTL_SECONDS: "1" });
    const { token } = await register(api);

    await new Promise((resolve) => setTimeout(resolve, 1500));
    assert.equal((await api.get("/api/vault", token)).status, 401);
  });

  test("rejects a malformed Authorization header", async () => {
    await boot();
    const { token } = await register(api);
    for (const header of [token, "Basic " + token, "Bearer", "Bearer "]) {
      const response = await api.request("GET", "/api/vault", { headers: { Authorization: header } });
      assert.equal(response.status, 401, "accepted " + JSON.stringify(header));
    }
  });
});

describe("error responses", () => {
  test("404 for an unknown endpoint", async () => {
    await boot();
    const response = await api.get("/api/nope");
    assert.equal(response.status, 404);
    assert.equal(response.body.error.code, "not_found");
  });

  test("never leaks a stack trace", async () => {
    await boot();
    const { token } = await register(api);
    const response = await api.put("/api/vault", { vault: "bad" }, token);
    const body = JSON.stringify(response.body);
    assert.ok(!body.includes("at "), "stack trace in response body");
    assert.ok(!/node_modules|\.ts:\d+/.test(body), "internal path in response body");
  });

  test("health check needs no authentication", async () => {
    await boot();
    const response = await api.get("/api/health");
    assert.equal(response.status, 200);
    assert.equal(response.body.status, "ok");
  });
});
