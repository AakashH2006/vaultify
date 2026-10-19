# Vaultify

A zero-knowledge password manager. Encryption and decryption happen in the
browser; the master password never reaches the server, and the backend is a
storage locker for ciphertext it cannot read.

> **Status — complete, all 4 weeks.** Crypto core, API, web client and
> hardening are built, typechecked and tested: **437 tests**, or 452 with
> Postgres. See [Roadmap](#roadmap) for what each week delivered and
> [Still open](#still-open) for what it does not do.

---

## Quick start

Requires **Node 22.6+** (the packages are TypeScript and run through Node's
native type stripping — there is no build step).

```bash
npm install
npm test          # 437 tests: crypto, TOTP, API, client, build, QR
npm run demo      # the zero-knowledge flow, printed step by step
```

### Running the whole thing

Two terminals. The API, then the client:

```bash
npm run dev       # API      http://localhost:4000   (see below for JWT_SECRET)
npm run web       # client   http://localhost:5173
```

### Running the API

```bash
cp apps/api/.env.example apps/api/.env
node -e "console.log(crypto.randomBytes(48).toString('base64url'))"   # paste into JWT_SECRET
npm run dev                                                            # http://localhost:4000
```

Without `DATABASE_URL` it uses an in-memory store — fine for development, and
the API refuses to boot that way in production. For real persistence:

```bash
docker compose up -d db
# if port 5432 is taken by a local Postgres install:
#   VAULTIFY_DB_PORT=55432 docker compose up -d db

DATABASE_URL=postgres://vaultify:vaultify@localhost:5432/vaultify npm run dev
```

The schema applies itself on boot.

### Running the web client

```bash
npm run web                                             # builds, then serves on :5173
VAULTIFY_API_ORIGIN=https://api.example.com npm run build   # API on its own domain
npm run build:vercel                                        # API on the same domain
```

The client has **zero runtime dependencies** and no bundler: Node strips the
TypeScript types and the browser loads the resulting ES modules directly, so
the JavaScript that runs is the source with the annotations whited out. That
matters because the one attack this design cannot defend against is a
compromised client bundle — the mitigation is that the bundle is small enough
to read, and hashed so a changed byte is detectable. Details in
**[docs/client.md](docs/client.md)**.

To exercise a running API end to end over real HTTP:

```bash
npm run smoke --workspace @vaultify/api
```

### Deploying

One Vercel project serves both halves from one domain -- the built client as
static files, the Express app as a single function under `/api/*`:

```bash
npx vercel link && npx vercel env add JWT_SECRET production && npx vercel deploy --prod
```

Then attach a Postgres database in the dashboard and redeploy. That is the
whole procedure: `JWT_SECRET` is the only variable to set by hand, because an
attached database injects its own connection-string variable and the API reads
whichever one is there, and the schema is applied by the first request each
instance serves -- behind a Postgres advisory lock, so a burst of cold starts
queues instead of colliding. `curl https://<domain>/api/ready` answers
`{"status":"ready",...,"store":"postgres"}` once both halves are talking.

Before the database is attached the client still deploys and runs -- the
generator and the strength meter are local -- and `/api/*` answers
`503 api_unconfigured` naming the variable it wants. Two things change on
serverless that are worth knowing before you rely on them: the in-memory rate
limiter stops being global, and the platform caps a request at 4.5 MB. All of
it is in **[docs/deploy.md](docs/deploy.md)**.

---

## How it works

One master password becomes two independent keys. One goes to the server to
prove who you are; the other stays in the browser and is the only thing that
can open the vault.

```
                     master password  (never transmitted)
                            |
          salt  ----------> | PBKDF2-HMAC-SHA256, 600,000 iterations
                            v
                    master key (256 bits)
                       /            \
            HKDF "auth-key"      HKDF "wrapping-key"
                   /                    \
            AUTH KEY                WRAPPING KEY
          (to server)              (stays in browser)
                                          |
                                     wraps/unwraps
                                          v
                                    VAULT KEY (random 256 bits)
                                          |
                                    AES-256-GCM
                                          v
                                  vault ciphertext -> server
```

Full rationale, trade-offs and threat model: **[docs/architecture.md](docs/architecture.md)**.
Endpoint reference: **[docs/api.md](docs/api.md)**.
The client, and why it has no framework: **[docs/client.md](docs/client.md)**.

---

## Using the crypto library

```ts
import {
  createAccount, unlockAccount, encryptVault, decryptVault, generatePassword,
} from "@vaultify/crypto";

// Sign-up. Only `authKey` and `keyRecord` are safe to send to the server.
const { authKey, keyRecord, vaultKey } = await createAccount(
  "ada@example.com",
  "correct horse battery staple",
);

// Seal the vault before it ever touches the network.
const sealed = await encryptVault(vaultKey, {
  version: 1,
  entries: [{
    id: crypto.randomUUID(),
    name: "GitHub",
    username: "ada",
    password: generatePassword({ length: 24 }),
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  }],
}, "ada@example.com");

// Later, on any device: fetch `keyRecord` and `sealed`, then unlock locally.
const unlocked = await unlockAccount("correct horse battery staple", keyRecord);
const vault = await decryptVault(unlocked.vaultKey, sealed, "ada@example.com");
```

Wrong password, tampered ciphertext and mismatched account all raise the same
`DecryptionError`, with the same message — nothing distinguishes them to a
caller or to an attacker probing for an oracle.

---

## The API in one screen

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/api/auth/register` | Create an account from client-generated keys |
| `POST` | `/api/auth/prelogin` | Fetch KDF parameters before deriving |
| `POST` | `/api/auth/login` | Exchange an auth key for a session |
| `POST` | `/api/auth/logout` | Revoke the current session |
| `POST` | `/api/auth/change-password` | Rotate credentials; vault untouched |
| `GET` | `/api/vault` | Download the encrypted blob |
| `PUT` | `/api/vault` | Upload it, with an optimistic-concurrency check |
| `GET` | `/api/auth/2fa` | Whether 2FA is on, and codes remaining |
| `POST` | `/api/auth/2fa/setup` | Mint a TOTP secret (does not enable it) |
| `POST` | `/api/auth/2fa/enable` | Confirm a code; returns recovery codes once |
| `POST` | `/api/auth/2fa/disable` | Needs the auth key *and* a current code |
| `GET` | `/api/auth/activity` | The audit log, for the account reading it |

Full request/response shapes in [docs/api.md](docs/api.md).

---

## Layout

```
packages/crypto/          the trust boundary — pure Web Crypto, zero runtime deps
  src/constants.ts        every tunable parameter, in one auditable place
  src/kdf.ts              master password -> auth key + wrapping key
  src/cipher.ts           AES-256-GCM envelopes, versioned and context-bound
  src/vault.ts            registration, unlock, sealing, password change
  src/generator.ts        unbiased password generation
  src/recovery.ts         the printable kit, and portable encrypted backups
  test/                   79 tests against real Web Crypto (no mocks)
  demo.ts                 the flow end to end, printed

packages/totp/            RFC 6238 TOTP, base32, recovery codes
  src/totp.ts             checked against the RFC's own test vectors
  test/                   66 tests

apps/api/                 the "dumb" storage locker
  src/config.ts           env validated at boot; refuses unsafe production setups
  src/auth/               scrypt hashing of auth keys, revocable JWT sessions
  src/middleware/         security headers, HTTPS, CORS, rate limiting, authn
  src/routes/             auth and vault endpoints
  src/store/              Store interface + in-memory and Postgres implementations
  src/store/schema.sql    annotated schema
  test/                   55 route/security tests + 15 Postgres integration tests
  smoke.ts                drives a deployed instance over real HTTP

apps/web/                 the client -- zero runtime deps, no framework, no bundler
  build.ts                type-strip -> ES modules, + SRI hashes and the CSP
  serve.ts                static server sending the headers production must send
  src/session.ts          the only object holding a key; lock() drops it
  src/merge.ts            three-way merge, biased against losing a credential
  src/autolock.ts         idle / hidden / expiry, over an injectable clock
  src/strength.ts         master-password estimate, honest about its limits
  src/dom.ts              70-line element builder; no innerHTML, by construction
  src/qr.ts               a QR encoder, so 2FA needs no dependency
  src/breach.ts           Have I Been Pwned, by k-anonymity
  src/health.ts           reused / weak / breached / stale report
  src/views/              auth, vault, entries, generator, 2FA, security,
                          activity, recovery kit, offline restore, settings
  test/                   169 tests, no browser required

docs/architecture.md      key hierarchy, sync model, trade-offs, threat model
docs/api.md               endpoint reference
docs/client.md            the client: build, CSP/SRI, auto-lock, merge, 2FA
```

---

## Testing

```bash
npm test                                   # 437 tests, no infrastructure needed

docker compose up -d db                    # then, for the Postgres layer:
TEST_DATABASE_URL=postgres://vaultify:vaultify@localhost:5432/vaultify npm test
                                           # 452 tests
```

| Package | Tests |
|---|---|
| `@vaultify/crypto` | 79 |
| `@vaultify/totp` | 66 |
| `@vaultify/api` | 111 (+15 with Postgres) |
| `@vaultify/web` | 169 |

The Postgres suite skips with a clear message when `TEST_DATABASE_URL` is unset,
so a fresh clone is never red. No browser or DOM is needed for the client
suite — the logic worth testing was deliberately kept out of the views.

Three deliberate choices in how these tests are written:

- **The API tests drive the real client library.** They derive real auth keys,
  seal real vaults, and assert the blob that came back out of the database
  still decrypts. The two halves are proven to fit, not assumed to.
- **No crypto is mocked.** The same code runs in the browser and under Node, so
  the suite exercises actual Web Crypto primitives.
- **The client tests drive the real API client** against a server double that
  enforces the real compare-and-set rule, so every conflict and merge path is
  exercised end to end. They assert, among other things, that no fragment of
  the master password appears anywhere in the recorded request log.
- **TOTP is checked against RFC 6238's own vectors**, and the QR encoder is
  round-tripped through a reader written separately from the specification. A
  wrong OTP implementation still emits plausible six-digit numbers, and a QR
  code with the data one column out still looks like a QR code — neither
  failure is visible without checking it properly. Both caught real bugs.

---

## Security notes

**Account**

- **TOTP two-factor** on login (RFC 6238). Each code is accepted exactly once,
  so one watched over a shoulder cannot be replayed inside the 90 seconds it
  stays arithmetically valid. Ten single-use recovery codes, stored as scrypt
  hashes, replace the *second* factor only — redeeming one still needs the
  master password.
- **2FA is never advertised.** `prelogin` answers identically for an account
  with 2FA, one without, and one that does not exist; `totp_required` is only
  reachable after the auth key verifies. Knowing which accounts are protected
  is itself useful to an attacker.
- **Progressive lockout** per account, held in the database: 1, 2, 4, 8 then 15
  minutes, capped so it cannot be aimed at the account's real owner.
- **An audit log** the user can read — sign-ins, failures, credential changes.
  IPs are truncated (/24, /48) and user agents reduced to "Firefox on macOS"
  before storage; rows expire after 90 days.
- **A recovery kit** at registration: the vault key, printable, shown once.
  With an encrypted backup it reconstructs the data offline with no server and
  no account. It grants no account access, by design.
- **Breach checking** by k-anonymity — a 5-character SHA-1 prefix leaves the
  tab, never the password or its full hash. Opt-in, per run.

**Client**

- 600,000 PBKDF2 iterations (OWASP 2023), with a hard floor of 100,000 enforced
  in the client, the API and a database `CHECK` constraint.
- Non-extractable `CryptoKey` handles — an XSS can use a key while the tab is
  unlocked but cannot export it and attack the vault offline later.
- A fresh random 96-bit IV per encryption, asserted by test. IV reuse is the one
  catastrophic failure mode of GCM.
- Account id bound as GCM additional data, so blobs cannot be swapped between
  accounts.

**Client bundle**

- Strict CSP with **no `unsafe-inline` and no `unsafe-eval`**. The one element
  the platform forces to be inline — the import map — is allowed by SHA-256
  hash. `connect-src` names exactly one API origin, so a script that somehow
  did execute has nowhere to send a stolen key.
- **SRI over the whole module graph**: an integrity hash per module in the
  import map, plus an `integrity` attribute on the entry script. (The former
  is Chromium-only so far; the latter is universal.)
- Nothing secret is persisted — no `sessionStorage`, no cookie, no key in
  `localStorage`. Locking drops the object that holds them, so a page refresh
  genuinely requires the master password again.
- **Auto-lock** on idle (5 min default), on the tab being hidden (60 s), and at
  token expiry. Every deadline is recomputed from the clock on each tick, so a
  throttled background tab wakes up and locks rather than staying open.
- No `innerHTML` anywhere, by construction. Entry URLs are scheme-checked
  before becoming links, so a stored `javascript:` URL cannot run in a tab that
  holds the vault key.
- Zero runtime dependencies, unminified, ~240 kB — small enough to actually
  audit, which is the only real answer to a compromised-bundle attack.

**Server**

- Auth keys stored as scrypt hashes, never raw.
- Sessions are revocable: logout and password changes take effect immediately,
  even on unexpired tokens.
- Account enumeration closed off — `prelogin` returns defaults for unknown
  accounts, and login spends the same scrypt work whether or not the account
  exists.
- Rate limiting on every credential route, keyed on IP and account.
- Optimistic concurrency on vault writes: a stale write is rejected with `409`
  rather than silently clobbering another device's edit.
- Refuses to start in production without a database or a signing secret.

**Known limits** (also in [the threat model](docs/architecture.md#6-threat-model))

- A compromised client bundle can capture the master password as it is typed.
  This is structural to every web-delivered zero-knowledge app; CSP, SRI and
  reproducible builds raise the cost but do not eliminate it.
- **The server stores the TOTP seed and can generate valid codes from it.**
  Unavoidable — it is the party enforcing the second factor, at login, before
  any vault key exists. It protects account *access*, not vault *contents*;
  a database dump still yields nothing readable.
- Fixed-window rate-limit counters are per-process; behind several API
  instances they need Redis. The progressive lockout is in the database and
  does work across instances.
- Import-map integrity (full-graph SRI) is Chromium-only today. The entry
  script's own `integrity` attribute works everywhere.
- **There is no recovery if the master password is lost.** The recovery kit
  recovers your *data* from a backup, offline; it is not a way back into the
  account. That distinction is deliberate, and
  [the architecture doc explains why](docs/architecture.md#the-question-the-brief-asks-what-if-the-user-forgets-the-master-password).

---

## Roadmap

| Week | Goal | Status |
|---|---|---|
| 1 | Crypto core — KDF, AES-GCM, vault sealing, generator | **Done** |
| 2 | Backend — auth-key login, sessions, `GET`/`PUT /vault`, Postgres | **Done** |
| 3 | UI — dashboard, add-entry form, generator, auto-lock, CSP/SRI, merge | **Done** |
| 4 | Hardening — TOTP 2FA, HIBP breach report, audit log, recovery kit | **Done** |

### Still open

Nothing in the brief is outstanding. What a production deployment would want
next, in rough order of value:

- **Per-entry TOTP.** `VaultEntry.totpSecret` is sealed with the vault and
  `@vaultify/totp` already generates codes in the browser — nothing reads the
  field yet. The smallest remaining piece.
- **WebAuthn / passkeys** as a second factor: phishing-resistant in a way TOTP
  is not, and it removes the server-held seed entirely.
- **Redis-backed rate limiting**, for more than one API instance.
- **A scheduled job behind `pruneAuditEvents`** — the 90-day retention is
  implemented but nothing calls it.
- **Argon2id** as a second KDF path, if the login page can afford the WASM.
- **Import** from other password managers. Export exists.

Tracked in full at the end of
[docs/architecture.md](docs/architecture.md#7-open-items).
