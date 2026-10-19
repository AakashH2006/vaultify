/**
 * Applies the schema to the database named by DATABASE_URL, then exits.
 *
 * `server.ts` migrates on boot, which is right for a long-lived process that
 * owns its database. A serverless deployment has no boot: there are many
 * short-lived instances, any number of them cold at once, and having each
 * apply DDL on its first request is a race for no benefit. So the schema is
 * applied here, deliberately, as a deploy step:
 *
 *   DATABASE_URL=postgres://... npm run migrate --workspace @vaultify/api
 *
 * schema.sql is idempotent, so running this again after a deploy that did not
 * change it is a no-op.
 */

import { resolveDatabaseUrl } from "./src/config.ts";
import { PostgresStore } from "./src/store/postgres.ts";

// Same resolution the API uses, so `vercel env pull` followed by this command
// touches the database the deployment talks to rather than a different one.
const resolved = resolveDatabaseUrl(process.env);

if (resolved === null) {
  console.error(
    "No connection string in the environment. Pass the database to migrate:\n" +
      "  DATABASE_URL=postgres://user:pass@host/db npm run migrate --workspace @vaultify/api",
  );
  process.exit(1);
}

const { url, variable } = resolved;
const store = new PostgresStore(url);

try {
  await store.migrate();
  // The host is worth printing -- applying the schema to the wrong database is
  // an easy mistake with two connection strings on the clipboard -- but the
  // credentials in the string are not.
  console.log(`[vaultify] schema applied to ${new URL(url).host} (from ${variable})`);
} finally {
  await store.close();
}
