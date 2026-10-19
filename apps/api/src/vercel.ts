/**
 * Serverless adapter.
 *
 * The Express app is unchanged and unaware of the platform; this module is the
 * only thing that knows about Vercel. `api/index.ts` at the repository root is
 * the three lines Vercel's file-based routing requires, and everything it needs
 * is here, where the tests and the typechecker already reach.
 *
 * Four jobs.
 *
 *   1. **Build the app once per instance.** A warm instance reuses the module
 *      across requests, so the config parse, the token service and the Postgres
 *      pool are created once and shared -- the shape `server.ts` has, minus the
 *      listen.
 *
 *   2. **Fill in what the platform knows.** Every request arrives through
 *      Vercel's proxy, which sets X-Forwarded-* itself and does not pass a
 *      client's own copy through, so TRUST_PROXY is on by default here --
 *      without it `req.secure` is false behind TLS termination and the HTTPS
 *      check would reject every request. CORS_ORIGIN defaults to the
 *      deployment's own domain.
 *
 *   3. **Refuse the in-memory store.** It is not a degraded option on
 *      serverless, it is a broken one: the account you just created lives on
 *      one instance and the next request lands on another.
 *
 *   4. **Fail legibly.** `loadConfig` throws by design rather than booting a
 *      password manager with a default signing secret. Thrown at import time
 *      that is an opaque 500 and a stack trace in the runtime log, so it
 *      becomes a 503 naming the variables that are missing -- the names only,
 *      never the values.
 *
 *   5. **Apply the schema once per instance.** So that attaching a database is
 *      the entire deployment procedure. See `ensureSchema` below for why this
 *      is safe here and why `migrate.ts` still exists.
 */

import type { IncomingMessage, ServerResponse } from "node:http";

import { createApp } from "./app.ts";
import { loadConfig } from "./config.ts";
import { PostgresStore } from "./store/postgres.ts";
import type { Store } from "./store/types.ts";

export type NodeHandler = (req: IncomingMessage, res: ServerResponse) => void;

export interface VercelHandlerOptions {
  /** Injected by the tests, which have no Postgres to connect to. */
  createStore?: (databaseUrl: string) => Store;
}

/** `true`/`1`, `false`/`0`, or the fallback when the variable is unset. */
function envFlag(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value === "") return fallback;
  return value === "true" || value === "1";
}

/**
 * A gate the first request waits on while the schema is applied.
 *
 * `server.ts` migrates on boot because it is one process that owns its
 * database. There is no boot here, so the choice is between a deploy step
 * somebody has to remember and a cold start that does it. This does it, and
 * the three reasons it is not the race it looks like:
 *
 *   - `migrate()` takes a Postgres advisory lock, so concurrent cold starts
 *     queue instead of colliding, and `schema.sql` is idempotent, so the ones
 *     that queued do no work.
 *   - The promise is memoized per instance, so a warm instance pays nothing:
 *     one `create table if not exists` pass per cold start, not per request.
 *   - A failure is not cached. A database that was asleep or briefly
 *     unreachable would otherwise poison the instance for as long as the
 *     platform keeps it warm, turning a blip into an outage.
 *
 * `migrate.ts` still exists, and is still the right tool for a schema change
 * you want applied before the deployment that needs it goes live, rather than
 * by whichever request arrives first.
 */
function ensureSchema(store: Store, enabled: boolean): () => Promise<void> {
  if (!enabled || store.migrate === undefined) return () => Promise.resolve();

  const migrate = store.migrate.bind(store);
  let applied: Promise<void> | null = null;

  return () => {
    applied ??= migrate().catch((error: unknown) => {
      applied = null;
      throw error;
    });
    return applied;
  };
}

/** The deployment's own origin, as a browser will see it. */
function selfOrigin(env: NodeJS.ProcessEnv): string | undefined {
  // VERCEL_PROJECT_PRODUCTION_URL is the project's stable production domain;
  // VERCEL_URL is the per-deployment hostname, which is what a preview has.
  const host = env.VERCEL_PROJECT_PRODUCTION_URL ?? env.VERCEL_URL;
  return host === undefined || host === "" ? undefined : `https://${host}`;
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(payload));
}

function unconfigured(missing: readonly string[], detail: string): NodeHandler {
  return (_req, res) => {
    sendJson(res, 503, {
      error: {
        code: "api_unconfigured",
        message:
          "This deployment is serving the client only; its API is not configured yet." +
          (missing.length > 0 ? ` Missing: ${missing.join(", ")}.` : ""),
        detail,
      },
    });
  };
}

/** Variable names out of a `loadConfig` failure, for the 503 body. */
function missingFrom(message: string): string[] {
  return [...message.matchAll(/^ {2}(\w+):/gm)].map((match) => match[1] as string);
}

/**
 * Hands a body the platform already read to `express.json()`.
 *
 * Vercel's Node runtime may consume the request stream and expose the result
 * as `req.body` before the handler runs. By then `express.json()` is waiting
 * for data that will never arrive, and the function sits there until it times
 * out -- a 15-second POST /api/auth/login with nothing in the log to explain
 * it. body-parser skips a request already marked as read, so the parsed body
 * is adopted here instead.
 *
 * Returns false when it has already answered the request.
 */
function adoptParsedBody(req: IncomingMessage, res: ServerResponse): boolean {
  const carrier = req as IncomingMessage & { body?: unknown; _body?: boolean };
  const parsed = carrier.body;

  if (parsed === undefined || parsed === null) return true;

  if (Buffer.isBuffer(parsed) || typeof parsed === "string") {
    const text = Buffer.isBuffer(parsed) ? parsed.toString("utf8") : parsed;
    if (text.length === 0) {
      carrier.body = {};
    } else {
      try {
        carrier.body = JSON.parse(text);
      } catch {
        sendJson(res, 400, {
          error: { code: "invalid_request", message: "Request body is not valid JSON." },
        });
        return false;
      }
    }
  }

  carrier._body = true;
  return true;
}

export function createVercelHandler(
  env: NodeJS.ProcessEnv,
  options: VercelHandlerOptions = {},
): NodeHandler {
  const resolved: NodeJS.ProcessEnv = {
    ...env,
    TRUST_PROXY: env.TRUST_PROXY ?? "true",
    CORS_ORIGIN: env.CORS_ORIGIN ?? selfOrigin(env),
  };

  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig(resolved);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return unconfigured(missingFrom(message), message);
  }

  if (!config.DATABASE_URL) {
    return unconfigured(
      ["DATABASE_URL"],
      "The in-memory store cannot be used on serverless. Attach a Postgres " +
        "database to this project, or set a connection string yourself.",
    );
  }

  const createStore = options.createStore ?? ((url: string) => new PostgresStore(url));
  const store = createStore(config.DATABASE_URL);
  const app = createApp({ config, store });

  // On by default on a deployment, off when something else owns the schema.
  const ready = ensureSchema(store, envFlag(resolved.AUTO_MIGRATE, true));

  return (req, res) => {
    if (!adoptParsedBody(req, res)) return;

    void ready().then(
      () => {
        (app as unknown as NodeHandler)(req, res);
      },
      (error: unknown) => {
        // The schema could not be applied, so no route can work. Logged once
        // per cold start, where a deployment's own logs can carry the detail;
        // the response gets the shape, not the connection string.
        console.error("[vaultify] schema could not be applied:", error);
        sendJson(res, 503, {
          error: {
            code: "store_unreachable",
            message: "The API is running but cannot reach its database.",
          },
        });
      },
    );
  };
}
