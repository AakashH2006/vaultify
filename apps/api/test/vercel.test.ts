/**
 * The serverless adapter.
 *
 * Two things here are worth a test. The 503 path, because a deployment with no
 * database must say so instead of returning an opaque 500 with a stack trace
 * in the platform log. And the body shim, because its failure mode is a
 * request that hangs until the function times out, which is the hardest kind
 * of bug to read from production symptoms.
 */

import assert from "node:assert/strict";
import { once } from "node:events";
import { readFile } from "node:fs/promises";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { afterEach, describe, it } from "node:test";

import { createVercelHandler, type NodeHandler } from "../src/vercel.ts";
import { MemoryStore } from "../src/store/memory.ts";
import type { Store } from "../src/store/types.ts";
import { makeUser, registrationBody, TEST_KDF } from "./harness.ts";

const SECRET = "test-secret-that-is-long-enough-to-pass-validation";

interface Harness {
  url: string;
  close(): Promise<void>;
}

let open: Harness | null = null;

afterEach(async () => {
  await open?.close();
  open = null;
});

/**
 * Serves the handler, optionally pre-reading the body the way Vercel's runtime
 * does -- the condition the shim exists for cannot be reproduced by asking
 * Express nicely.
 */
async function serve(
  handler: NodeHandler,
  prereadBody: "no" | "object" | "buffer" = "no",
): Promise<Harness> {
  const server: Server = createServer((req, res) => {
    if (prereadBody === "no") {
      handler(req, res);
      return;
    }

    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      const raw = Buffer.concat(chunks);
      const carrier = req as typeof req & { body?: unknown };
      carrier.body =
        prereadBody === "buffer"
          ? raw
          : raw.length === 0
            ? undefined
            : JSON.parse(raw.toString("utf8"));
      handler(req, res);
    });
  }).listen(0);

  await once(server, "listening");
  const { port } = server.address() as AddressInfo;

  const harness: Harness = {
    url: `http://127.0.0.1:${port}`,
    async close() {
      server.close();
      await once(server, "close");
    },
  };
  open = harness;
  return harness;
}

function configured(env: Record<string, string> = {}, store?: Store): NodeHandler {
  return createVercelHandler(
    {
      NODE_ENV: "test",
      JWT_SECRET: SECRET,
      DATABASE_URL: "postgres://unused-by-this-test",
      VERCEL_PROJECT_PRODUCTION_URL: "vaultify.example",
      ...env,
    },
    { createStore: () => store ?? new MemoryStore() },
  );
}

/**
 * The in-memory store with a schema step bolted on, so the cold-start
 * migration can be observed without a Postgres to migrate.
 */
class MigratingStore extends MemoryStore {
  calls = 0;
  failures = 0;

  async migrate(): Promise<void> {
    this.calls += 1;
    if (this.failures > 0) {
      this.failures -= 1;
      throw new Error("connect ECONNREFUSED 10.0.0.1:5432");
    }
  }
}

describe("a deployment that is not configured yet", () => {
  it("answers 503 and names the missing variable, never its value", async () => {
    const { url } = await serve(createVercelHandler({ NODE_ENV: "production" }));

    const response = await fetch(`${url}/api/health`);
    assert.equal(response.status, 503);

    const body = await response.json();
    assert.equal(body.error.code, "api_unconfigured");
    assert.match(body.error.message, /JWT_SECRET/);
  });

  it("names the database once the signing secret is there", async () => {
    const { url } = await serve(
      createVercelHandler({ NODE_ENV: "production", JWT_SECRET: SECRET }),
    );

    const response = await fetch(`${url}/api/health`);
    assert.equal(response.status, 503);
    assert.match((await response.json()).error.message, /DATABASE_URL/);
  });

  it("refuses the in-memory store rather than serving one instance's accounts", async () => {
    // Valid config, no database: fine for `npm run dev`, broken on serverless.
    const { url } = await serve(createVercelHandler({ NODE_ENV: "development", JWT_SECRET: SECRET }));

    const response = await fetch(`${url}/api/health`);
    assert.equal(response.status, 503);

    const body = await response.json();
    assert.match(body.error.message, /DATABASE_URL/);
    assert.match(body.error.detail, /in-memory store/);
  });
});

describe("the configured handler", () => {
  it("serves the real routes behind the platform's rewrite", async () => {
    const { url } = await serve(configured());

    const response = await fetch(`${url}/api/health`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), { status: "ok", version: 1 });
  });

  it("trusts the proxy, so an HTTPS-only deployment accepts a forwarded request", async () => {
    const { url } = await serve(configured({ NODE_ENV: "production", REQUIRE_HTTPS: "true" }));

    const forwarded = await fetch(`${url}/api/health`, {
      headers: { "X-Forwarded-Proto": "https" },
    });
    assert.equal(forwarded.status, 200);

    // And still refuses one that arrived in the clear.
    const plain = await fetch(`${url}/api/health`);
    assert.equal(plain.status, 403);
  });

  it("defaults CORS to the deployment's own domain", async () => {
    const { url } = await serve(configured());

    const response = await fetch(`${url}/api/health`, {
      headers: { Origin: "https://vaultify.example" },
    });
    assert.equal(response.headers.get("access-control-allow-origin"), "https://vaultify.example");
  });

  for (const shape of ["object", "buffer"] as const) {
    it(`accepts a POST whose body the platform already read (as ${shape})`, async () => {
      const { url } = await serve(configured(), shape);
      const user = await makeUser();

      // Hangs rather than fails if the shim is wrong, so the test carries its
      // own deadline instead of waiting for the suite's.
      const response = await fetch(`${url}/api/auth/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(registrationBody(user)),
        signal: AbortSignal.timeout(5_000),
      });

      assert.equal(response.status, 201);
      const body = await response.json();
      assert.equal(body.keyRecord.accountId, user.accountId);
      assert.equal(body.keyRecord.kdf.iterations, TEST_KDF.iterations);
    });
  }

  it("serves a readiness check that names where the connection string came from", async () => {
    const { url } = await serve(configured({ DATABASE_URL: "", POSTGRES_URL: "postgres://x" }));

    const response = await fetch(`${url}/api/ready`);
    assert.equal(response.status, 200);
    assert.deepEqual(await response.json(), {
      status: "ready",
      version: 1,
      store: "memory", // the injected test store; a deployment reports postgres
      databaseUrlVariable: "POSTGRES_URL",
    });
  });

  it("rejects a pre-read body that is not JSON, instead of hanging", async () => {
    const { url } = await serve(configured(), "buffer");

    const response = await fetch(`${url}/api/auth/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{not json",
      signal: AbortSignal.timeout(5_000),
    });

    assert.equal(response.status, 400);
    assert.equal((await response.json()).error.code, "invalid_request");
  });
});

describe("a database attached through the platform", () => {
  // Vercel Postgres, Neon and Supabase each inject their own variable names.
  // Reading them is what makes "attach a database" the whole deploy step, so
  // each name is worth a test -- a typo here is a deployment that answers 503
  // with a database sitting right there.
  for (const variable of [
    "POSTGRES_URL",
    "POSTGRES_PRISMA_URL",
    "POSTGRES_URL_NON_POOLING",
    "DATABASE_URL_UNPOOLED",
  ]) {
    it(`is used when it arrives as ${variable}`, async () => {
      const { url } = await serve(
        configured({ NODE_ENV: "production", DATABASE_URL: "", [variable]: "postgres://attached" }),
      );

      const response = await fetch(`${url}/api/health`, {
        headers: { "X-Forwarded-Proto": "https" },
      });
      assert.equal(response.status, 200);
    });
  }

  it("prefers the pooled host over the direct one", async () => {
    // Neon injects both. Opening a pool per instance against the direct host
    // exhausts the database's connections under the load it should survive.
    const { url } = await serve(
      configured({
        DATABASE_URL: "",
        POSTGRES_URL: "postgres://pooled",
        DATABASE_URL_UNPOOLED: "postgres://direct",
      }),
    );

    assert.equal((await (await fetch(`${url}/api/ready`)).json()).databaseUrlVariable, "POSTGRES_URL");
  });

  it("treats a declared-but-empty variable as absent", async () => {
    const { url } = await serve(
      createVercelHandler({ NODE_ENV: "production", JWT_SECRET: SECRET, DATABASE_URL: "" }),
    );

    const response = await fetch(`${url}/api/health`);
    assert.equal(response.status, 503);
    assert.match((await response.json()).error.message, /DATABASE_URL/);
  });
});

describe("the schema on a cold start", () => {
  it("is applied once per instance, not once per request", async () => {
    const store = new MigratingStore();
    const { url } = await serve(configured({}, store));

    for (let i = 0; i < 3; i++) {
      assert.equal((await fetch(`${url}/api/health`)).status, 200);
    }

    assert.equal(store.calls, 1);
  });

  it("answers 503 rather than a broken route when it cannot be applied", async () => {
    const store = new MigratingStore();
    store.failures = 1;
    const { url } = await serve(configured({}, store));

    const failed = await fetch(`${url}/api/health`);
    assert.equal(failed.status, 503);
    assert.equal((await failed.json()).error.code, "store_unreachable");

    // And the failure is not cached: a database that was briefly unreachable
    // must not poison the instance for as long as the platform keeps it warm.
    const recovered = await fetch(`${url}/api/health`);
    assert.equal(recovered.status, 200);
    assert.equal(store.calls, 2);
  });

  it("is left alone when something else owns the schema", async () => {
    const store = new MigratingStore();
    const { url } = await serve(configured({ AUTO_MIGRATE: "false" }, store));

    assert.equal((await fetch(`${url}/api/health`)).status, 200);
    assert.equal(store.calls, 0);
  });
});

describe("the platform configuration", () => {
  // schema.sql is read at runtime through `new URL(..., import.meta.url)`,
  // which a dependency tracer cannot see. If this entry ever goes missing the
  // deploy still succeeds and the first request fails on ENOENT, so the
  // contract between the code and the platform config is asserted here.
  it("ships the schema into the function bundle", async () => {
    const path = fileURLToPath(new URL("../../../vercel.json", import.meta.url));
    const config = JSON.parse(await readFile(path, "utf8")) as {
      functions?: Record<string, { includeFiles?: string }>;
    };

    const included = config.functions?.["api/index.ts"]?.includeFiles;
    assert.ok(included, "api/index.ts needs an includeFiles entry");

    // The entry has to name the file the store actually reads, not merely
    // some file: resolved from the repository root, it must be this one.
    const matched = fileURLToPath(new URL("../../../" + included, import.meta.url));
    assert.equal(matched, fileURLToPath(new URL("../src/store/schema.sql", import.meta.url)));
    await readFile(matched, "utf8");
  });

  /**
   * The platform must not guess what this project is.
   *
   * It guessed once: it found Express in the dependencies, decided this was a
   * Node server, and looked for app.js, index.js or server.js in the output
   * directory -- which holds a static client and never had one. The same guess
   * is what pointed the build at the api workspace. `framework: null` is the
   * supported way to say "no framework", and it overrides the project setting,
   * so the answer lives in the repository rather than in a dashboard nobody
   * can see from here.
   */
  it("pins the framework to none", async () => {
    const path = fileURLToPath(new URL("../../../vercel.json", import.meta.url));
    const config = JSON.parse(await readFile(path, "utf8")) as Record<string, unknown>;

    assert.ok("framework" in config, "vercel.json must state the framework");
    assert.equal(config.framework, null, "the framework must be null, not a preset");
  });

  /**
   * The build command has to name a script npm will actually find.
   *
   * This failed a real deployment. `npm run build:vercel` resolved to the root
   * script locally and to the api workspace on the platform, because npm takes
   * a workspace from `npm_config_workspace` in the environment when the
   * command line does not name one -- and that workspace has no such script.
   * Naming it with `--workspace=` makes it command-line config, which wins.
   */
  it("builds with a script that exists in the workspace it names", async () => {
    const root = new URL("../../../", import.meta.url);
    const config = JSON.parse(
      await readFile(fileURLToPath(new URL("vercel.json", root)), "utf8"),
    ) as { buildCommand?: string };

    const command = config.buildCommand ?? "";
    const script = /^npm run ([\w:.-]+)/.exec(command)?.[1];
    const workspace = /--workspace=(\S+)/.exec(command)?.[1];

    assert.ok(script, `no script name in the build command: ${command}`);
    assert.ok(
      workspace,
      "the build command must name its workspace explicitly, or npm resolves " +
        "it from the environment and picks the wrong package.json",
    );

    // Find that workspace by name rather than by guessing its directory.
    interface Manifest {
      name: string;
      scripts?: Record<string, string>;
    }

    const manifests = ["apps/web", "apps/api", "packages/crypto", "packages/totp"];
    const found: Manifest[] = [];
    for (const dir of manifests) {
      const manifest = JSON.parse(
        await readFile(fileURLToPath(new URL(`${dir}/package.json`, root)), "utf8"),
      ) as Manifest;
      if (manifest.name === workspace) found.push(manifest);
    }

    assert.equal(found.length, 1, `${workspace} is not a workspace of this repository`);
    assert.ok(
      found[0]?.scripts?.[script] !== undefined,
      `${workspace} has no "${script}" script`,
    );
  });
});
