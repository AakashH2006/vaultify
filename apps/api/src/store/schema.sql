-- Vaultify schema.
--
-- Read this as the answer to "what does a breach of our database actually
-- give an attacker?". Every column below is either public metadata, a slow
-- hash, or a ciphertext the server has no key for.

create table if not exists accounts (
  -- Email, normalised to lowercase by the application before it gets here.
  account_id          text        primary key,

  -- scrypt hash of the client's auth key, in the format
  -- "scrypt$N$r$p$<salt b64>$<hash b64>". Never the auth key itself: that
  -- value is a bearer credential, so we store it the way we would a password.
  auth_key_hash       text        not null,

  -- KDF parameters the client must use. Stored server-side so the iteration
  -- count can be raised later without locking existing accounts out.
  -- The CHECK mirrors PBKDF2_MIN_ITERATIONS in @vaultify/crypto: even a bug in
  -- the API cannot persist a weakened work factor.
  kdf_algorithm       text        not null check (kdf_algorithm in ('PBKDF2')),
  kdf_iterations      integer     not null check (kdf_iterations >= 100000),

  -- The vault key, wrapped under the client's password-derived wrapping key.
  -- Fixed-size (~100 chars), but TEXT costs nothing extra in Postgres.
  protected_vault_key text        not null,

  -- The encrypted vault. TEXT is unbounded in Postgres (up to 1 GB), so a
  -- growing vault can never be silently truncated the way a VARCHAR(n) would
  -- truncate it -- and a truncated ciphertext is an unrecoverable vault, not a
  -- cosmetic defect. The application still enforces MAX_VAULT_BYTES.
  -- NULL until the client's first sync.
  vault               text,

  -- Optimistic concurrency. Bumped on every accepted write; a client must send
  -- the revision it based its edit on. Without this, two tabs overwrite each
  -- other and the server cannot detect it -- it cannot read either blob.
  vault_revision      bigint      not null default 0,
  vault_updated_at    timestamptz,

  created_at          timestamptz not null default now()
);

create table if not exists sessions (
  session_id uuid        primary key,
  account_id text        not null references accounts (account_id) on delete cascade,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

-- Supports revoke-all on master-password change.
create index if not exists sessions_account_id_idx on sessions (account_id);

-- Supports pruning expired rows.
create index if not exists sessions_expires_at_idx on sessions (expires_at);

-- ---------------------------------------------------------------------------
-- Two-factor authentication (Phase 4)
-- ---------------------------------------------------------------------------
--
-- Be clear about what this does and does not protect, because it is the one
-- place in the schema where the server holds a usable secret.
--
-- `totp_secret` is stored in the clear and the server CAN generate valid
-- codes from it. That is unavoidable: the server is the party enforcing the
-- second factor, and it enforces it at login -- before any vault key exists
-- anywhere. Encrypting it under a key sitting in the same database would be
-- decoration.
--
-- What matters is the blast radius. This secret guards *account access*, not
-- vault contents. An attacker who dumps this table gets the ability to pass a
-- 2FA prompt. They still need the master password, which is nowhere here, to
-- turn the encrypted vault into readable passwords. 2FA is a layer on top of
-- zero knowledge, not a hole in it.

alter table accounts add column if not exists totp_secret text;
alter table accounts add column if not exists totp_enabled boolean not null default false;

-- The last TOTP step this account successfully spent. A code is valid for up
-- to 90 seconds across the verification window, which is ample time to reuse
-- one read off a screen or sniffed from a proxy -- so each step is accepted
-- exactly once.
alter table accounts add column if not exists totp_last_step bigint;

-- Progressive lockout. The fixed-window rate limiter is per-process and resets
-- cleanly; this is per-account, survives a restart, and lengthens with each
-- consecutive failure.
alter table accounts add column if not exists failed_attempts integer not null default 0;
alter table accounts add column if not exists locked_until timestamptz;

-- Recovery codes: single-use, scrypt-hashed exactly like the auth key. A row
-- is deleted when spent, so the count of remaining rows is what the UI shows.
create table if not exists recovery_codes (
  id         bigserial   primary key,
  account_id text        not null references accounts (account_id) on delete cascade,
  code_hash  text        not null,
  created_at timestamptz not null default now()
);

create index if not exists recovery_codes_account_id_idx on recovery_codes (account_id);

-- ---------------------------------------------------------------------------
-- Audit log (Phase 4)
-- ---------------------------------------------------------------------------
--
-- "Show me sessions I do not recognise" needs the server to remember
-- something about the user, which for a zero-knowledge product is a cost, not
-- a free feature. The compromise taken here:
--
--   * The IP is truncated before it is stored -- /24 for IPv4, /48 for IPv6.
--     Enough to tell "my home connection" from "a different country"; not a
--     precise location history of the user.
--   * The user agent is reduced to a coarse label ("Firefox on macOS"), not
--     stored raw. A full UA string is a high-entropy fingerprint.
--   * Rows are pruned after 90 days.
--
-- Nothing here reveals vault contents, and the table is write-only from the
-- application's point of view apart from the user reading their own rows.

create table if not exists audit_events (
  id         bigserial   primary key,
  account_id text        not null references accounts (account_id) on delete cascade,
  event      text        not null,
  -- true for a successful action, false for a rejected attempt.
  succeeded  boolean     not null,
  -- Truncated. See the note above.
  ip_prefix  text,
  client     text,
  created_at timestamptz not null default now()
);

create index if not exists audit_events_account_created_idx
  on audit_events (account_id, created_at desc);
