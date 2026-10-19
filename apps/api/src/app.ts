/**
 * Express application factory.
 *
 * Takes its store and config as arguments rather than reaching for process.env,
 * so the test suite can run the real app against an in-memory store with no
 * globals to reset between files.
 */

import express, { type Express } from "express";

import type { Config } from "./config.ts";
import type { Store } from "./store/types.ts";
import { TokenService } from "./auth/tokens.ts";
import { errorHandler, notFoundHandler } from "./errors.ts";
import { cors, requireHttps, securityHeaders } from "./middleware/security.ts";
import { authRoutes } from "./routes/auth.ts";
import { vaultRoutes } from "./routes/vault.ts";

export interface AppDeps {
  config: Config;
  store: Store;
}

export function createApp({ config, store }: AppDeps): Express {
  const app = express();
  const tokens = new TokenService(config.JWT_SECRET, config.ACCESS_TOKEN_TTL_SECONDS);

  // Only believe X-Forwarded-* when we are actually behind a proxy. Trusting
  // them unconditionally would let any client spoof its IP and walk past the
  // rate limiter.
  app.set("trust proxy", config.TRUST_PROXY);
  app.disable("x-powered-by");
  app.disable("etag"); // no caching of vault responses, not even conditionally

  app.use(securityHeaders(config));
  app.use(requireHttps(config));
  app.use(cors(config));

  // Headroom over MAX_VAULT_BYTES for base64 expansion and JSON overhead;
  // the vault field itself is checked exactly by the route schema.
  app.use(express.json({ limit: config.MAX_VAULT_BYTES + 64 * 1024 }));

  // Liveness: the function booted and the config parsed. Deliberately touches
  // nothing, so it answers during a database outage too.
  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok", version: 1 });
  });

  // Readiness: the store is reachable. This is the one call that tells a fresh
  // deployment whether it will actually work, which is why it reports the
  // variable the connection string came from -- a deployment configured
  // through a platform integration is otherwise hard to tell apart from one
  // configured by hand, and exactly as hard to debug.
  app.get("/api/ready", async (_req, res) => {
    try {
      await store.ping();
    } catch {
      // The reason is not repeated to the caller: a connection error from pg
      // carries the host, the port and sometimes the user.
      res.status(503).json({
        error: {
          code: "store_unreachable",
          message: "The API is running but cannot reach its database.",
          store: store.kind,
          databaseUrlVariable: config.databaseUrlVariable,
        },
      });
      return;
    }

    res.json({
      status: "ready",
      version: 1,
      store: store.kind,
      databaseUrlVariable: config.databaseUrlVariable,
    });
  });

  app.use("/api/auth", authRoutes({ store, tokens, config }));
  app.use("/api/vault", vaultRoutes({ store, tokens, config }));

  app.use(notFoundHandler);
  app.use(errorHandler);

  return app;
}
