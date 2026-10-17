# Vaultify API Reference

Base path `/api`. All bodies are JSON. All responses carry `Cache-Control: no-store`.

The guiding rule for every endpoint below: **the server cannot read anything it
stores.** It holds a slow hash of an auth key and two ciphertext envelopes. No
request in this document carries a master password, an encryption key, or a
decrypted vault entry.

---

## Authentication

Protected endpoints take `Authorization: Bearer <accessToken>`.

Tokens are HS256 JWTs with a session id (`sid`) that is checked against the
database on every request. A signature alone is not authority — a logout or a
master-password change kills the session immediately, even though the token is
still unexpired and cryptographically valid.

Default lifetime 15 minutes (`ACCESS_TOKEN_TTL_SECONDS`).

---

## The login flow

```
  client                                            server
    |                                                 |
    |-- POST /api/auth/prelogin { accountId } -------->|
    |<------------------------- { kdf } ---------------|
    |                                                 |
    |  derive authKey + wrappingKey from the master   |
    |  password, locally. The password stops here.    |
    |                                                 |
    |-- POST /api/auth/login { accountId, authKey } -->|
    |<-- { accessToken, keyRecord, vaultRevision } ----|
    |                                                 |
    |  unwrap the vault key with wrappingKey          |
    |                                                 |
    |-- GET /api/vault ------------------------------->|
    |<-- { vault: "<ciphertext>", vaultRevision } -----|
    |                                                 |
    |  decrypt locally                                |
```

`prelogin` exists because the client needs the account's KDF parameters before
it can derive anything, and it has no session yet.

---

## Endpoints

### `GET /api/health`

No authentication. Returns `{ "status": "ok", "version": 1 }`.

---

### `POST /api/auth/register`

```jsonc
// request
{
  "accountId": "ada@example.com",
  "authKey": "<44 chars of base64>",             // HKDF output, 256 bits
  "kdf": { "algorithm": "PBKDF2", "iterations": 600000 },
  "protectedVaultKey": "1.AES-256-GCM.<iv>.<ct>" // vault key, wrapped
}
```

```jsonc
// 201
{
  "accountId": "ada@example.com",
  "accessToken": "...", "tokenType": "Bearer", "expiresIn": 900,
  "keyRecord": { "accountId": "...", "kdf": {...}, "protectedVaultKey": "..." },
  "vault": null,
  "vaultRevision": 0
}
```

The email is trimmed and lowercased to match how the client derives its salt.
If those two ever disagree, keys silently stop matching.

`409 account_exists` on a duplicate. This endpoint genuinely cannot hide that an
address is taken — the alternative is letting a stranger overwrite an existing
account — so the mitigation is a rate limit (5/hour per IP), not a vague error.

---

### `POST /api/auth/prelogin`

```jsonc
// request
{ "accountId": "ada@example.com" }

// 200
{ "kdf": { "algorithm": "PBKDF2", "iterations": 600000 } }
```

**An unknown account returns the defaults, not a 404.** Otherwise this becomes
an account-enumeration oracle — and for a password manager, "which of these
emails has an account?" tells an attacker exactly who to phish.

---

### `POST /api/auth/login`

```jsonc
// request
{
  "accountId": "ada@example.com",
  "authKey": "<44 chars of base64>",
  "totpCode": "123456",        // only when 2FA is on; see below
  "recoveryCode": "ABCDE-FGHJK" // alternative to totpCode
}

// 200
{
  "accountId": "ada@example.com",
  "accessToken": "...", "tokenType": "Bearer", "expiresIn": 900,
  "keyRecord": { "accountId": "...", "kdf": {...}, "protectedVaultKey": "..." },
  "vaultRevision": 3,
  "twoFactor": { "enabled": true, "recoveryCodesRemaining": 9 }
}
```

**The second factor is only mentioned after the first one passes.** A caller who
does not know the master password gets the same `invalid_credentials` they
always did, whether or not the account exists and whether or not it has 2FA.
`totp_required` is unreachable without the auth key, so this endpoint cannot be
used to find out which accounts are protected.

```jsonc
// 401 — password correct, code missing
{ "error": { "code": "totp_required", "message": "Enter the code from your authenticator app." } }

// 401 — password correct, code wrong, replayed, or recovery code already spent
{ "error": { "code": "totp_invalid", "message": "That code is not valid. Try the next one." } }
```

Each TOTP step is accepted **once**. A code stays arithmetically valid for up to
90 seconds across the verification window, which is ample time for someone who
watched it being typed, so the spent step is recorded with the login.

`401 invalid_credentials` for both a wrong auth key and a non-existent account —
same status, same body, and the same amount of work. The handler runs a dummy
scrypt for unknown accounts specifically so the response time does not give the
answer away.

Rate limit: 10 per 15 minutes, keyed on IP **and** account, so attacking many
accounts from one host trips the limit while one attacker cannot lock a victim
out by burning their account's budget alone.

---

### `POST /api/auth/logout`

Authenticated. `204`, and the session is revoked immediately.

---

### `GET /api/auth/2fa`

Authenticated. `{ "enabled": true, "recoveryCodesRemaining": 9 }`.

---

### `POST /api/auth/2fa/setup`

Authenticated. Mints a secret and returns it with an `otpauth://` URI.

```jsonc
// 200
{
  "secret": "JBSWY3DPEHPK3PXP...",
  "uri": "otpauth://totp/Vaultify%3Aada%40example.com?secret=...&issuer=Vaultify&algorithm=SHA1&digits=6&period=30"
}
```

**Nothing is switched on.** 2FA is enabled only by `/2fa/enable`, which requires
a working code. Enabling on the strength of "the user was shown a QR code" is
how people lock themselves out of their own vault.

`409 conflict` if 2FA is already on.

---

### `POST /api/auth/2fa/enable`

Authenticated. `{ "code": "123456" }`.

```jsonc
// 200 — the only time these are ever returned
{ "enabled": true, "recoveryCodes": ["VCV22-ZHUTA", "E7GST-IKK3Q", ...] }
```

Ten single-use recovery codes, stored server-side as scrypt hashes. A recovery
code replaces the **second** factor, not the first — redeeming one still
requires the master password — which is why they can be printed without that
being reckless.

`401 totp_invalid` if the code does not verify; `409 totp_not_enrolled` if
`/2fa/setup` has not run.

---

### `POST /api/auth/2fa/disable`

Authenticated. `{ "authKey": "...", "code": "123456" }` → `204`.

Requires the auth key **and** a current code. Stripping a second factor is the
first thing an attacker holding a borrowed session token would do, so a live
session alone is not enough. Every remaining recovery code is destroyed.

---

### `GET /api/auth/activity`

Authenticated. The 50 most recent events for this account, newest first.

```jsonc
// 200
{
  "events": [
    {
      "event": "login",
      "succeeded": true,
      "ipPrefix": "203.0.113.0/24",   // truncated: /24 for IPv4, /48 for IPv6
      "client": "Firefox on macOS",    // coarse label, never the raw UA string
      "createdAt": "2026-10-14T06:31:02.000Z"
    }
  ]
}
```

Events: `register`, `login`, `login.totp_failed`, `login.locked_out`, `logout`,
`password_changed`, `totp_enabled`, `totp_disabled`, `recovery_code_used`.

This is the only user-linked history the server keeps. The IP is truncated and
the user agent reduced before either is written, and rows are pruned after 90
days. See [`apps/api/src/auth/audit.ts`](../apps/api/src/auth/audit.ts) for why
each of those is the way it is.

---

### `POST /api/auth/change-password`

Authenticated.

```jsonc
// request
{
  "currentAuthKey": "<44 chars of base64>",       // proves knowledge of the old password
  "newAuthKey": "<44 chars of base64>",
  "kdf": { "algorithm": "PBKDF2", "iterations": 600000 },
  "protectedVaultKey": "1.AES-256-GCM.<iv>.<ct>"  // vault key, rewrapped
}
```

`204` on success. Note three things:

- **`currentAuthKey` is required even though the caller is authenticated.** A
  borrowed access token must not be upgradeable into account takeover.
- **The vault ciphertext is not sent and not touched.** The client rewraps the
  32-byte vault key and uploads only that. See
  [architecture.md §2](architecture.md#why-a-separate-vault-key).
- **Every session is revoked, including the caller's.** If the change was
  prompted by a suspected compromise, leaving old sessions alive defeats it.

---

### `GET /api/vault`

Authenticated.

```jsonc
// 200
{
  "vault": "1.AES-256-GCM.<iv>.<ct>",  // null before the first sync
  "vaultRevision": 3,
  "vaultUpdatedAt": "2026-10-12T07:48:00.000Z",
  "keyRecord": { "accountId": "...", "kdf": {...}, "protectedVaultKey": "..." }
}
```

`vault: null` means a new account — the client should treat it as an empty
vault, not an error. The key record rides along so a client resuming from a
stored token can unwrap without a second round trip.

---

### `PUT /api/vault`

Authenticated.

```jsonc
// request
{
  "vault": "1.AES-256-GCM.<iv>.<ct>",
  "expectedRevision": 3          // the revision this edit was based on
}

// 200
{ "vaultRevision": 4, "vaultUpdatedAt": "2026-10-12T07:49:00.000Z" }
```

```jsonc
// 409
{
  "error": { "code": "conflict", "message": "The vault changed since you last loaded it..." },
  "currentRevision": 5
}
```

**On 409 the client must re-read, reapply its change over the newer vault, and
retry.** The server cannot merge — it cannot read either version. Last-write-wins
on an opaque ciphertext is permanent, invisible data loss, which is why the
revision check is a compare-and-set in SQL rather than a read-then-write.

Bodies over `MAX_VAULT_BYTES` (default 5 MB) are rejected.

---

## Errors

```jsonc
{ "error": { "code": "invalid_request", "message": "vault: is not a valid AES-256-GCM envelope" } }
```

| Code | Status | Meaning |
|---|---|---|
| `invalid_request` | 400 | Body failed validation. Message names the field. |
| `invalid_credentials` | 401 | Wrong auth key, or no such account. Indistinguishable. |
| `unauthorized` | 401 | Missing, invalid, expired or revoked token. |
| `account_exists` | 409 | That email is registered. |
| `conflict` | 409 | Stale `expectedRevision`. |
| `not_found` | 404 | No such endpoint. |
| `payload_too_large` | 413 | Body exceeded the parser limit. |
| `rate_limited` | 429 | Too many attempts. Carries `Retry-After`. |
| `account_locked` | 429 | Progressive lockout after repeated failures. Carries `Retry-After`. |
| `totp_required` | 401 | Password correct; a second factor is outstanding. |
| `totp_invalid` | 401 | Wrong, replayed or already-spent code. |
| `totp_not_enrolled` | 409 | No pending secret, or 2FA is not on. |
| `https_required` | 403 | Plain HTTP where TLS is mandatory. |
| `internal_error` | 500 | A bug. Logged server-side; no detail returned. |

Stack traces, SQL and driver errors never cross the wire.

---

## Security headers

Sent on every response:

```
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Cross-Origin-Resource-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin
Cache-Control: no-store
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload   (when HTTPS is required)
```

CORS allows exactly one configured origin. The request's `Origin` is never
reflected back — reflecting it hands the browser's same-origin protection to
the attacker.

---

## Rate limits

| Route | Limit | Key |
|---|---|---|
| `/api/auth/login`, `/api/auth/prelogin` | 10 / 15 min | IP + account |
| `/api/auth/register` | 5 / hour | IP |
| `/api/auth/change-password` | 5 / 15 min | account |
| `/api/auth/2fa/setup`, `/2fa/enable` | 10 / 15 min | account |
| `/api/auth/2fa/disable` | 5 / 15 min | account |

Counters are per-process. Behind more than one API instance this must move to
Redis, or each node enforces its own share of the limit.

### Progressive lockout

On top of the fixed windows above, each account carries a consecutive-failure
counter in the database. It survives a restart and is shared across API nodes,
which is exactly what the in-memory limiter is not.

| Consecutive failures | Lockout |
|---|---|
| 1–4 | none |
| 5 | 1 minute |
| 6 | 2 minutes |
| 7 | 4 minutes |
| 8 | 8 minutes |
| 9+ | 15 minutes (capped) |

A locked account returns `429 account_locked` **even for the correct password**,
and still spends the same scrypt work first, so the lockout does not become a
fast "this account exists" signal.

The cap is deliberate. An unbounded backoff is a denial-of-service that an
attacker can aim at an account's real owner by failing a login on a schedule,
and locking someone out of their own password vault is a serious harm. Fifteen
minutes slows a sustained grind to a few hundred guesses a year while bounding
the worst anyone can inflict.
