/**
 * Entry point. Loads config, picks a store, listens, and shuts down cleanly.
 */

import { createApp } from "./app.ts";
import { loadConfig } from "./config.ts";
import { MemoryStore } from "./store/memory.ts";
import { PostgresStore } from "./store/postgres.ts";
import type { Store } from "./store/types.ts";

const config = loadConfig();

let store: Store;

if (config.DATABASE_URL) {
  const postgres = new PostgresStore(config.DATABASE_URL);
  await postgres.migrate();
  await postgres.pruneExpiredSessions();
  store = postgres;
  console.log("[vaultify] store: postgres");
} else {
  // loadConfig already refuses this combination in production.
  store = new MemoryStore();
  console.warn("[vaultify] store: in-memory -- all data is lost on restart");
}

const server = createApp({ config, store }).listen(config.PORT, () => {
  console.log(
    "[vaultify] listening on :" +
      config.PORT +
      " (" +
      config.NODE_ENV +
      (config.requireHttps ? ", https required" : "") +
      ")",
  );
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    console.log("\n[vaultify] " + signal + " received, shutting down");
    server.close(async () => {
      await store.close();
      process.exit(0);
    });
  });
}
