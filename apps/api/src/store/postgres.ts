/**
 * Postgres-backed store.
 *
 * Every statement here is parameterised -- there is no string interpolation
 * into SQL anywhere in this file, and there never should be.
 */

import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import pg from "pg";

import type {
  AccountRecord,
  AuditEvent,
  NewAccount,
  NewAuditEvent,
  RotatedCredentials,
  SaveVaultResult,
  SessionRecord,
  Store,
  TotpEnrolment,
} from "./types.ts";

interface AccountRow {
  account_id: string;
  auth_key_hash: string;
  kdf_algorithm: "PBKDF2";
  kdf_iterations: number;
  protected_vault_key: string;
  vault: string | null;
  vault_revision: string; // bigint arrives as a string from node-postgres
  vault_updated_at: Date | null;
  created_at: Date;
  totp_secret: string | null;
  totp_enabled: boolean;
  totp_last_step: string | null; // bigint, as above
  failed_attempts: number;
  locked_until: Date | null;
}

function toAccount(row: AccountRow): AccountRecord {
  return {
    accountId: row.account_id,
    authKeyHash: row.auth_key_hash,
    kdf: { algorithm: row.kdf_algorithm, iterations: row.kdf_iterations },
    protectedVaultKey: row.protected_vault_key,
    vault: row.vault,
    vaultRevision: Number(row.vault_revision),
    vaultUpdatedAt: row.vault_updated_at?.toISOString() ?? null,
    createdAt: row.created_at.toISOString(),
    totpSecret: row.totp_secret,
    totpEnabled: row.totp_enabled,
    totpLastStep: row.totp_last_step === null ? null : Number(row.totp_last_step),
    failedAttempts: row.failed_attempts,
    lockedUntil: row.locked_until?.toISOString() ?? null,
  };
}

const ACCOUNT_COLUMNS = `
  account_id, auth_key_hash, kdf_algorithm, kdf_iterations,
  protected_vault_key, vault, vault_revision, vault_updated_at, created_at,
  totp_secret, totp_enabled, totp_last_step, failed_attempts, locked_until
`;

/** Postgres error code for a unique-constraint violation. */
const UNIQUE_VIOLATION = "23505";

/**
 * Advisory-lock key for the schema, so only one process applies it at a time.
 *
 * `schema.sql` is idempotent, which is not the same as concurrency-safe: two
 * sessions running `create index if not exists` against the same table at the
 * same moment can deadlock, and `create table if not exists` races can fail
 * with a duplicate-relation error even though both callers wanted the same
 * end state. One long-lived server never noticed, because there was only ever
 * one of it. A serverless deployment can cold-start a dozen instances on the
 * same burst of traffic, and every one of them calls migrate().
 *
 * Any constant works as long as nothing else in the database picks the same
 * one; this is "vaultify.schema" with the high bit kept clear.
 */
const SCHEMA_LOCK_KEY = 0x7641_7531;

export class PostgresStore implements Store {
  readonly #pool: pg.Pool;

  constructor(connectionString: string) {
    this.#pool = new pg.Pool({
      connectionString,
      max: 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 5_000,
    });
  }

  readonly kind = "postgres" as const;

  /** `select 1`, and nothing else: proof that the pool can reach the server. */
  async ping(): Promise<void> {
    await this.#pool.query("select 1");
  }

  /**
   * Applies schema.sql. Idempotent and safe to call concurrently, so it is
   * fine on every boot and on every cold start.
   */
  async migrate(): Promise<void> {
    const sql = await this.#readSchema();
    const client = await this.#pool.connect();

    try {
      await client.query("select pg_advisory_lock($1)", [SCHEMA_LOCK_KEY]);
      try {
        await client.query(sql);
      } finally {
        // Released explicitly rather than left to the session: this client goes
        // back to a pool that may hand it to the next request, and a
        // session-level advisory lock would ride along with it.
        await client.query("select pg_advisory_unlock($1)", [SCHEMA_LOCK_KEY]);
      }
    } finally {
      client.release();
    }
  }

  /**
   * schema.sql is read at runtime, which a bundler will not notice on its own.
   *
   * `new URL(..., import.meta.url)` is invisible to a dependency tracer, so on
   * a platform that bundles the API into a function the file has to be listed
   * as an asset to include -- `includeFiles` in vercel.json does that. If it
   * ever stops being listed, the symptom is a cold start failing on ENOENT
   * somewhere inside node:fs, so the error says what is actually wrong.
   */
  async #readSchema(): Promise<string> {
    const path = fileURLToPath(new URL("./schema.sql", import.meta.url));

    try {
      return await readFile(path, "utf8");
    } catch (cause) {
      throw new Error(
        `Could not read the schema at ${path}. If this is a bundled ` +
          "deployment, the file has to be included as an asset: see the " +
          "`includeFiles` entry for api/index.ts in vercel.json.",
        { cause },
      );
    }
  }

  async createAccount(account: NewAccount): Promise<AccountRecord | null> {
    try {
      const { rows } = await this.#pool.query<AccountRow>(
        `insert into accounts
           (account_id, auth_key_hash, kdf_algorithm, kdf_iterations, protected_vault_key)
         values ($1, $2, $3, $4, $5)
         returning ${ACCOUNT_COLUMNS}`,
        [
          account.accountId,
          account.authKeyHash,
          account.kdf.algorithm,
          account.kdf.iterations,
          account.protectedVaultKey,
        ],
      );
      return toAccount(rows[0]);
    } catch (error) {
      if ((error as { code?: string }).code === UNIQUE_VIOLATION) return null;
      throw error;
    }
  }

  async findAccount(accountId: string): Promise<AccountRecord | null> {
    const { rows } = await this.#pool.query<AccountRow>(
      `select ${ACCOUNT_COLUMNS} from accounts where account_id = $1`,
      [accountId],
    );
    return rows[0] ? toAccount(rows[0]) : null;
  }

  async saveVault(
    accountId: string,
    vault: string,
    expectedRevision: number,
  ): Promise<SaveVaultResult> {
    // The revision check lives in the WHERE clause, so the compare-and-set is
    // atomic at the database level. Doing it as read-then-write in JavaScript
    // would leave a window for two concurrent syncs to both pass the check.
    const { rows } = await this.#pool.query<{
      vault_revision: string;
      vault_updated_at: Date;
    }>(
      `update accounts
          set vault = $2,
              vault_revision = vault_revision + 1,
              vault_updated_at = now()
        where account_id = $1
          and vault_revision = $3
        returning vault_revision, vault_updated_at`,
      [accountId, vault, expectedRevision],
    );

    if (rows[0]) {
      return {
        status: "saved",
        vaultRevision: Number(rows[0].vault_revision),
        vaultUpdatedAt: rows[0].vault_updated_at.toISOString(),
      };
    }

    // No row updated: either the account is gone or the revision moved on.
    const current = await this.findAccount(accountId);
    return current
      ? { status: "conflict", currentRevision: current.vaultRevision }
      : { status: "no_such_account" };
  }

  async rotateCredentials(
    accountId: string,
    credentials: RotatedCredentials,
  ): Promise<boolean> {
    const { rowCount } = await this.#pool.query(
      `update accounts
          set auth_key_hash = $2, kdf_algorithm = $3,
              kdf_iterations = $4, protected_vault_key = $5
        where account_id = $1`,
      [
        accountId,
        credentials.authKeyHash,
        credentials.kdf.algorithm,
        credentials.kdf.iterations,
        credentials.protectedVaultKey,
      ],
    );
    return rowCount === 1;
  }

  // -------------------------------------------------------------------------
  // Two-factor authentication
  // -------------------------------------------------------------------------

  async startTotpEnrolment(accountId: string, secret: string): Promise<boolean> {
    const { rowCount } = await this.#pool.query(
      `update accounts
          set totp_secret = $2, totp_enabled = false, totp_last_step = null
        where account_id = $1`,
      [accountId, secret],
    );
    return rowCount === 1;
  }

  /**
   * One transaction, because half of this landing is a real failure mode:
   * 2FA on with no recovery codes means a lost phone is a lost vault, and the
   * user has no way to tell from the outside that it happened.
   */
  async enableTotp(accountId: string, enrolment: TotpEnrolment): Promise<boolean> {
    const client = await this.#pool.connect();
    try {
      await client.query("begin");

      const { rowCount } = await client.query(
        `update accounts set totp_secret = $2, totp_enabled = true where account_id = $1`,
        [accountId, enrolment.secret],
      );
      if (rowCount !== 1) {
        await client.query("rollback");
        return false;
      }

      await client.query(`delete from recovery_codes where account_id = $1`, [accountId]);

      if (enrolment.recoveryCodeHashes.length > 0) {
        // unnest expands the array into rows in one round trip, rather than
        // one INSERT per code.
        await client.query(
          `insert into recovery_codes (account_id, code_hash)
           select $1, unnest($2::text[])`,
          [accountId, enrolment.recoveryCodeHashes],
        );
      }

      await client.query("commit");
      return true;
    } catch (error) {
      await client.query("rollback").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async disableTotp(accountId: string): Promise<boolean> {
    const client = await this.#pool.connect();
    try {
      await client.query("begin");
      const { rowCount } = await client.query(
        `update accounts
            set totp_secret = null, totp_enabled = false, totp_last_step = null
          where account_id = $1`,
        [accountId],
      );
      await client.query(`delete from recovery_codes where account_id = $1`, [accountId]);
      await client.query("commit");
      return rowCount === 1;
    } catch (error) {
      await client.query("rollback").catch(() => {});
      throw error;
    } finally {
      client.release();
    }
  }

  async recordTotpStep(accountId: string, step: number): Promise<void> {
    // `greatest` so an out-of-order write cannot walk the marker backwards and
    // reopen a window for an already-spent code.
    await this.#pool.query(
      `update accounts
          set totp_last_step = greatest(coalesce(totp_last_step, 0), $2::bigint)
        where account_id = $1`,
      [accountId, step],
    );
  }

  async listRecoveryCodeHashes(
    accountId: string,
  ): Promise<readonly { id: string; hash: string }[]> {
    const { rows } = await this.#pool.query<{ id: string; code_hash: string }>(
      `select id, code_hash from recovery_codes where account_id = $1 order by id`,
      [accountId],
    );
    return rows.map((row) => ({ id: String(row.id), hash: row.code_hash }));
  }

  async consumeRecoveryCode(accountId: string, id: string): Promise<boolean> {
    // DELETE ... RETURNING is the compare-and-set: exactly one caller can
    // delete a given row, so two tabs redeeming the same code cannot both win.
    const { rowCount } = await this.#pool.query(
      `delete from recovery_codes where id = $1 and account_id = $2 returning id`,
      [id, accountId],
    );
    return rowCount === 1;
  }

  // -------------------------------------------------------------------------
  // Lockout and audit
  // -------------------------------------------------------------------------

  async recordFailedAttempt(accountId: string, lockedUntil: string | null): Promise<number> {
    const { rows } = await this.#pool.query<{ failed_attempts: number }>(
      `update accounts
          set failed_attempts = failed_attempts + 1, locked_until = $2
        where account_id = $1
        returning failed_attempts`,
      [accountId, lockedUntil],
    );
    return rows[0]?.failed_attempts ?? 0;
  }

  async clearFailedAttempts(accountId: string): Promise<void> {
    await this.#pool.query(
      `update accounts set failed_attempts = 0, locked_until = null where account_id = $1`,
      [accountId],
    );
  }

  async appendAuditEvent(event: NewAuditEvent): Promise<void> {
    await this.#pool.query(
      `insert into audit_events (account_id, event, succeeded, ip_prefix, client)
       values ($1, $2, $3, $4, $5)`,
      [event.accountId, event.event, event.succeeded, event.ipPrefix, event.client],
    );
  }

  async listAuditEvents(accountId: string, limit: number): Promise<readonly AuditEvent[]> {
    const { rows } = await this.#pool.query<{
      event: string;
      succeeded: boolean;
      ip_prefix: string | null;
      client: string | null;
      created_at: Date;
    }>(
      `select event, succeeded, ip_prefix, client, created_at
         from audit_events
        where account_id = $1
        order by created_at desc, id desc
        limit $2`,
      [accountId, limit],
    );
    return rows.map((row) => ({
      event: row.event,
      succeeded: row.succeeded,
      ipPrefix: row.ip_prefix,
      client: row.client,
      createdAt: row.created_at.toISOString(),
    }));
  }

  /** Retention. The audit log is the only user-linked history the server
   *  keeps, so it does not keep it indefinitely. */
  async pruneAuditEvents(olderThanDays = 90): Promise<number> {
    const { rowCount } = await this.#pool.query(
      `delete from audit_events where created_at < now() - ($1 || ' days')::interval`,
      [String(olderThanDays)],
    );
    return rowCount ?? 0;
  }

  async createSession(session: SessionRecord): Promise<void> {
    await this.#pool.query(
      `insert into sessions (session_id, account_id, expires_at) values ($1, $2, $3)`,
      [session.sessionId, session.accountId, session.expiresAt],
    );
  }

  async isSessionActive(sessionId: string): Promise<boolean> {
    const { rowCount } = await this.#pool.query(
      `select 1 from sessions where session_id = $1 and expires_at > now()`,
      [sessionId],
    );
    return rowCount === 1;
  }

  async revokeSession(sessionId: string): Promise<void> {
    await this.#pool.query(`delete from sessions where session_id = $1`, [sessionId]);
  }

  async revokeAllSessions(accountId: string): Promise<void> {
    await this.#pool.query(`delete from sessions where account_id = $1`, [accountId]);
  }

  /** Housekeeping for expired sessions. Call from a cron or a boot hook. */
  async pruneExpiredSessions(): Promise<number> {
    const { rowCount } = await this.#pool.query(`delete from sessions where expires_at <= now()`);
    return rowCount ?? 0;
  }

  async close(): Promise<void> {
    await this.#pool.end();
  }
}
