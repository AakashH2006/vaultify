# Deploying on Vercel

One Vercel project serves both halves of Vaultify from a single domain:

```
vaultify.vercel.app
├── /              apps/web/dist          static files, built by `build.ts`
├── /app/*.js      the module graph       unminified, SRI-hashed
└── /api/*         apps/api               the Express app, as one function
```

The client and the API therefore share an origin. That is a change from the
development setup, where they sit on `:5173` and `:4000` and CORS is real. It
makes `connect-src` narrower, not wider — the policy the browser enforces on a
deployed client is `connect-src 'self' https://api.pwnedpasswords.com`, with no
third-party API origin in it at all. The CORS code in the API is unchanged and
still exercised by its tests; it simply has nothing to allow in this shape.

## What makes this work

| File | What it does |
|---|---|
| `vercel.json` | Build command, output directory, the `/api/*` rewrite, and the security headers that do not depend on the build. |
| `api/index.ts` | The three lines Vercel's file-based routing needs. Vercel turns every file under `api/` into a function, so the logic lives elsewhere. |
| `apps/api/src/vercel.ts` | The adapter: one app per instance, platform defaults, the schema gate, a 503 when the deployment is not configured, and the body shim. Tested in `apps/api/test/vercel.test.ts`. |
| `apps/api/migrate.ts` | Applies `schema.sql` from your machine. Not needed for a first deploy — see [the schema](#the-schema) — and still the right tool for a schema change you want applied before the code that needs it goes live. |
| `npm run build:vercel` | `build.ts --same-origin`: bakes `API_ORIGIN = ""` into the client so it calls `/api/...` on its own origin. |

## Deploying

Three commands, of which only the middle one is a decision:

```bash
npx vercel link                       # once, to create or attach the project
npx vercel env add JWT_SECRET production   # paste 48 random bytes; see below
npx vercel deploy --prod
```

Then attach a Postgres database in the dashboard (Storage → Create → Neon) and
redeploy. Nothing else is required: the API reads whichever connection-string
variable the integration injected, and applies the schema itself on its first
cold start. `curl https://<domain>/api/ready` should answer:

```json
{ "status": "ready", "version": 1, "store": "postgres", "databaseUrlVariable": "POSTGRES_URL" }
```

Pushing to the default branch deploys too, once the repository is connected in
the dashboard. No framework preset is needed: `vercel.json` says everything.
The Node version comes from `engines.node` in the root `package.json`;
`>=22.6.0` resolves to the latest 24.x on this platform, which is what the
native TypeScript support this project relies on needs.

A deployment with no database still builds and serves: the client loads, the
generator and the strength meter work because they are local, and every call to
`/api/*` answers `503 api_unconfigured` naming the variable it wants. That is a
deliberate state, not a broken one — it is what the link looks like between
`vercel deploy` and attaching the database.

## Environment variables

Set these in the dashboard (Settings → Environment Variables) or with
`npx vercel env add <NAME> production`.

| Variable | Required | Notes |
|---|---|---|
| `JWT_SECRET` | yes | 32 characters minimum, no default. `node -e "console.log(crypto.randomBytes(48).toString('base64url'))"`. Rotating it invalidates every session, which is a feature. The one thing here you have to set by hand: a password manager that boots with a shipped fallback signing key is one anybody can mint tokens for. |
| `DATABASE_URL` | yes, for a working API | Postgres, and a **pooled** connection string. Usually nothing to set: an attached database injects its own name and the API reads that — `POSTGRES_URL`, `POSTGRES_PRISMA_URL`, `POSTGRES_URL_NON_POOLING` or `DATABASE_URL_UNPOOLED`, pooled hosts preferred. Setting `DATABASE_URL` yourself overrides all of them. |
| `AUTO_MIGRATE` | no | Defaults on. `false` stops the API applying `schema.sql` on a cold start, for when a migration tool or a DBA owns the schema instead. |
| `MAX_VAULT_BYTES` | recommended | Set it to `4000000`. See the request-size note below. |
| `CORS_ORIGIN` | no | Defaults to this deployment's own domain. Only matters if a client on another origin calls this API. |
| `ACCESS_TOKEN_TTL_SECONDS` | no | Defaults to 900. |
| `TRUST_PROXY` | no | Defaults to `true` here: every request arrives through Vercel's proxy, which sets `X-Forwarded-*` itself. Without it `req.secure` is false behind TLS termination and the HTTPS check rejects everything. |
| `REQUIRE_HTTPS` | no | `auto`, which means on in production. |
| `NODE_ENV` | no | Vercel sets it to `production`. |

Nothing here is secret except `JWT_SECRET` and `DATABASE_URL`, and neither is
ever logged: the 503 the API returns when they are missing names the variables
and nothing else.

## Adding the database

The API refuses to start in production without `DATABASE_URL`, and the adapter
refuses the in-memory store on any deployment. That refusal is not caution for
its own sake: on serverless there is no single process, so an account created
on one instance would not exist on the next request.

1. **Create a database.** In the Vercel dashboard, Storage → Create → Neon
   (Postgres). Attaching it to the project injects a connection string under
   its own variable name, and the API reads whichever one is there, so there is
   nothing to copy. Any Postgres reachable over TLS works — Supabase, RDS, your
   own; set `DATABASE_URL` yourself for one that is not attached through the
   platform.
2. **Use the pooled connection string.** A function instance opens its own
   pool, and many instances can be warm at once, so a direct connection string
   runs out of server-side connections under load. Neon's pooled host contains
   `-pooler`; other providers have their own equivalent.
3. **Nothing.** See [the schema](#the-schema) — the first request applies it.
   To apply it from your machine instead, which is what you want for a schema
   change that should land before the deployment needing it:

   ```bash
   npx vercel env pull .env.production      # or export DATABASE_URL yourself
   npm run migrate --workspace @vaultify/api
   ```

   It prints the host it touched and the variable the string came from, both
   worth reading when two connection strings have been on the clipboard.
4. **Check it.** `curl https://<your-domain>/api/ready` →
   `{"status":"ready",...,"store":"postgres"}`. A `503 store_unreachable` there
   means the API is running and the database is not answering it: the wrong
   connection string, a direct host where a pooled one was needed, or a
   database still waking up. Then the real thing, end to end over HTTP:

   ```bash
   BASE=https://<your-domain> npm run smoke --workspace @vaultify/api
   ```

Until a database is attached, the client deploys and runs — the UI loads and
the generator works, because it is all local — and every call to `/api/*`
answers `503 api_unconfigured` with a message the client displays as-is.

## The schema

The API applies `schema.sql` itself, on the first request each instance
serves. That is what makes attaching a database the whole procedure, and it
needs three things to be true before it is a good idea rather than a race:

- **`migrate()` takes a Postgres advisory lock.** Idempotent is not the same as
  concurrency-safe: two sessions running `create index if not exists` against
  one table at the same moment can deadlock. A single long-lived server never
  met that problem because there was only ever one of it; a burst of traffic
  here cold-starts a dozen instances that all call `migrate()`. They queue, and
  the ones that queued find the work already done.
- **The promise is memoized per instance**, so a warm instance pays nothing.
  One `create table if not exists` pass per cold start, not per request.
- **A failure is not cached.** A database that was asleep for a moment would
  otherwise poison the instance for as long as the platform keeps it warm,
  which turns a blip into an outage. The failing request answers
  `503 store_unreachable` and the next one tries again.

`AUTO_MIGRATE=false` turns it off, for a database whose schema something else
owns. `apps/api/migrate.ts` is then how you apply it, and remains the better
choice for a schema change that has to land before the code that depends on it.

One platform detail worth knowing, because its failure mode is obscure:
`schema.sql` is read at runtime through `new URL("./schema.sql",
import.meta.url)`, which a dependency tracer cannot see. It ships into the
function because `vercel.json` lists it under `includeFiles`. If that entry
ever goes missing, the build still succeeds and the first request fails on
`ENOENT` — so a test asserts the entry resolves to the file the store actually
reads, and the store's own error says to come back here.

## What differs from running it yourself

- **Rate limiting weakens.** `rateLimit` holds its counters in process memory,
  and serverless means many short-lived processes, so each enforces its own
  share of the window. The progressive lockout is the control that still
  holds: it lives in the database, survives restarts, and is per-account. The
  README already lists Redis-backed limiting as the fix, and on this platform
  it matters more than it did before.
- **Requests are capped at 4.5 MB by the platform**, below the API's 5 MB
  default for a stored vault. A vault between the two limits would be rejected
  by Vercel before the API saw it, with an error the client cannot explain. Set
  `MAX_VAULT_BYTES=4000000` so the API's own limit is the one that applies and
  the user gets the real message.
- **There is no boot to migrate on.** See [the schema](#the-schema).
- **Cold starts are visible.** The first request to an idle deployment pays for
  the module graph and a new Postgres connection. Login also pays one scrypt
  call at OWASP's parameters (~32 MB, N=2^15), which is deliberate and well
  within the function's default memory.
- **`csp.txt` is not used here.** It exists for a reverse proxy that sends the
  policy as a header. A static host cannot: the policy contains the import
  map's SHA-256 hash, which changes with every byte of every module, so a
  hand-copied header would be stale on the next commit and the client would
  not start. The build puts the policy in the page itself instead, where it
  cannot drift. `frame-ancestors` is ignored in a meta element, so
  `vercel.json` sends `X-Frame-Options: DENY` for that one directive.

## Two origins instead of one

If you would rather keep the client and the API on separate domains — the
shape the development setup has, where a CORS mistake fails loudly instead of
being hidden by a shared origin — deploy the same repository twice:

- **API project:** keep `api/index.ts`, set `CORS_ORIGIN` to the client's
  domain, and let the build output be irrelevant.
- **Client project:** build with `npm run build --workspace @vaultify/web`
  after setting `VAULTIFY_API_ORIGIN=https://<api-domain>`, which bakes that
  origin into the bundle and names it in `connect-src`.

Both halves already support this; it is two projects to keep in step rather
than one.
