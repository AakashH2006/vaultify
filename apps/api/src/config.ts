/**
 * Configuration, validated once at boot.
 *
 * The API refuses to start on bad config rather than discovering it at the
 * first request. Several of the checks below are deliberately strict in
 * production -- a password manager that silently falls back to in-memory
 * storage, or boots with a default signing secret, is worse than one that
 * refuses to run.
 */

import { z } from "zod";

/**
 * Boolean from an environment string.
 *
 * Two traps avoided here. `z.coerce.boolean()` treats the string "false" as
 * true, since any non-empty string is truthy. And in Zod 4 `.default()` applies
 * to the *output* of a transform, so `.transform(...).default("false")` would
 * hand back the literal string "false" instead of a boolean -- which Express
 * then tries to parse as an IP range. Defaulting inside the transform keeps the
 * output type honest.
 */
const envBoolean = (fallback: boolean) =>
  z
    .enum(["true", "false", "1", "0"])
    .optional()
    .transform((value) => (value === undefined ? fallback : value === "true" || value === "1"));

/**
 * Where a connection string may arrive from, most specific first.
 *
 * `DATABASE_URL` is what this project asks for and what the docs name. The
 * rest are not aliases we invented: a managed Postgres attached to a hosting
 * project injects its own names, and which ones you get depends on the
 * provider rather than on anything in this repository. Vercel Postgres and
 * Neon both set `POSTGRES_URL`; Neon adds the `*_UNPOOLED` pair; Supabase sets
 * `POSTGRES_URL` only.
 *
 * Reading them here means attaching a database is the whole job -- there is no
 * second step where you copy a connection string the platform already knows
 * into a variable of our choosing, and so no way to leave the two disagreeing.
 *
 * Pooled hosts come first deliberately. A serverless deployment opens a pool
 * per instance and runs many instances warm at once, so a direct connection
 * string runs the database out of backends under exactly the load you want it
 * to survive. The unpooled names are the fallback, not the preference.
 */
const DATABASE_URL_VARIABLES = [
  "DATABASE_URL",
  "POSTGRES_URL",
  "POSTGRES_PRISMA_URL",
  "POSTGRES_URL_NON_POOLING",
  "DATABASE_URL_UNPOOLED",
] as const;

export interface ResolvedDatabaseUrl {
  /** The variable it came from, for diagnostics. Never the value. */
  readonly variable: (typeof DATABASE_URL_VARIABLES)[number];
  readonly url: string;
}

/** The first connection string actually set, or null. Exported for the tests. */
export function resolveDatabaseUrl(env: NodeJS.ProcessEnv): ResolvedDatabaseUrl | null {
  for (const variable of DATABASE_URL_VARIABLES) {
    const url = env[variable]?.trim();
    // An empty string is how a platform spells "declared but not set", and
    // handing it to pg would fail at the first query rather than here.
    if (url !== undefined && url !== "") return { variable, url };
  }
  return null;
}

const schema = z
  .object({
    NODE_ENV: z.enum(["development", "test", "production"]).default("development"),
    PORT: z.coerce.number().int().min(1).max(65_535).default(4000),

    /**
     * HMAC key for session tokens. 32 bytes minimum, and there is no default:
     * a shipped fallback secret would let anyone mint tokens for any account.
     * Generate one with: node -e "console.log(crypto.randomBytes(48).toString('base64url'))"
     */
    JWT_SECRET: z.string().min(32, "JWT_SECRET must be at least 32 characters"),

    /** Postgres connection string. Required in production; omit it in dev or
     *  test to use the in-memory store. `loadConfig` fills this in from a
     *  platform-injected variable when it is not set directly -- see
     *  DATABASE_URL_VARIABLES. */
    DATABASE_URL: z.string().optional(),

    /** Exact origin allowed to call the API. No wildcard -- credentials are
     *  involved, and `*` with credentials is both unsafe and disallowed. */
    CORS_ORIGIN: z.string().url().default("http://localhost:5173"),

    /** Short by design. The vault key lives in the tab, so a stolen access
     *  token is a smaller prize than the session it rides on. */
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().positive().default(15 * 60),

    /** Hard ceiling on a stored vault. Bounds both the request body and the
     *  row, so one account cannot fill the disk. */
    MAX_VAULT_BYTES: z.coerce.number().int().positive().default(5 * 1024 * 1024),

    /** Set when running behind a load balancer that terminates TLS, so
     *  X-Forwarded-For and X-Forwarded-Proto can be believed. */
    TRUST_PROXY: envBoolean(false),

    /** Redirect/refuse plain HTTP and send HSTS. Defaults on in production. */
    REQUIRE_HTTPS: z.enum(["true", "false", "auto"]).default("auto"),
  })
  .superRefine((config, ctx) => {
    if (config.NODE_ENV === "production" && !config.DATABASE_URL) {
      ctx.addIssue({
        code: "custom",
        path: ["DATABASE_URL"],
        message:
          "DATABASE_URL is required in production. Refusing to start with the " +
          "in-memory store -- every vault would be lost on restart.",
      });
    }
  });

export type Config = Omit<z.infer<typeof schema>, "REQUIRE_HTTPS"> & {
  requireHttps: boolean;
  isProduction: boolean;
  /** Which variable DATABASE_URL was read from, or null when there is none. */
  databaseUrlVariable: ResolvedDatabaseUrl["variable"] | null;
};

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const database = resolveDatabaseUrl(env);
  const parsed = schema.safeParse(
    database === null ? env : { ...env, DATABASE_URL: database.url },
  );

  if (!parsed.success) {
    const detail = parsed.error.issues
      .map((issue) => "  " + issue.path.join(".") + ": " + issue.message)
      .join("\n");
    throw new Error("Invalid configuration:\n" + detail);
  }

  const { REQUIRE_HTTPS, ...rest } = parsed.data;
  const isProduction = rest.NODE_ENV === "production";

  return {
    ...rest,
    isProduction,
    requireHttps: REQUIRE_HTTPS === "auto" ? isProduction : REQUIRE_HTTPS === "true",
    databaseUrlVariable: database?.variable ?? null,
  };
}
