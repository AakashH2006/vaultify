/**
 * Typed client for the Vaultify API.
 *
 * Everything that crosses this module is already encrypted or already hashed.
 * Grep it for `masterPassword` and you will find nothing: the password is
 * consumed by `@vaultify/crypto` before any code here runs, and the only
 * credentials on the wire are a derived auth key and an opaque envelope.
 *
 * The access token is passed in per call rather than held in module state. A
 * token sitting in a module-level variable outlives every lock, every logout
 * and every mistake; making callers hand it over keeps its lifetime tied to the
 * session object that auto-lock destroys.
 */

import type { AccountKeyRecord, KdfParams } from "@vaultify/crypto";

export interface WireKeyRecord {
  readonly accountId: string;
  readonly kdf: KdfParams;
  /** Serialised envelope: `1.AES-256-GCM.<iv>.<ct>`. */
  readonly protectedVaultKey: string;
}

export interface TwoFactorStatus {
  readonly enabled: boolean;
  readonly recoveryCodesRemaining: number;
}

export interface Session {
  readonly accountId: string;
  readonly accessToken: string;
  readonly expiresIn: number;
  readonly keyRecord: WireKeyRecord;
  readonly vaultRevision: number;
  readonly twoFactor: TwoFactorStatus;
}

export interface ActivityEvent {
  readonly event: string;
  readonly succeeded: boolean;
  /** Already truncated by the server -- see apps/api/src/auth/audit.ts. */
  readonly ipPrefix: string | null;
  readonly client: string | null;
  readonly createdAt: string;
}

export interface VaultResponse {
  readonly vault: string | null;
  readonly vaultRevision: number;
  readonly vaultUpdatedAt: string | null;
  readonly keyRecord: WireKeyRecord;
}

export type ApiErrorCode =
  | "invalid_request"
  | "invalid_credentials"
  | "unauthorized"
  | "account_exists"
  | "conflict"
  | "not_found"
  | "payload_too_large"
  | "rate_limited"
  | "https_required"
  | "internal_error"
  | "network_error"
  | "totp_required"
  | "totp_invalid"
  | "totp_not_enrolled"
  | "account_locked";

export class ApiError extends Error {
  readonly code: ApiErrorCode;
  readonly status: number;
  /** Present on 409 from `PUT /api/vault`. */
  readonly currentRevision?: number;
  /** Seconds, present on 429. */
  readonly retryAfter?: number;

  constructor(
    code: ApiErrorCode,
    status: number,
    message: string,
    extra: { currentRevision?: number; retryAfter?: number } = {},
  ) {
    super(message);
    this.name = "ApiError";
    this.code = code;
    this.status = status;
    this.currentRevision = extra.currentRevision;
    this.retryAfter = extra.retryAfter;
  }

  /** Copy suitable for showing a user. Server messages are already safe --
   *  the API never returns stack traces or driver errors -- but a network
   *  failure needs saying in words a person can act on. */
  get userMessage(): string {
    switch (this.code) {
      case "network_error":
        return "Could not reach the server. Check your connection and try again.";
      case "invalid_credentials":
        return "Incorrect email or master password.";
      case "unauthorized":
        return "Your session has expired. Unlock again to continue.";
      case "rate_limited":
        return this.retryAfter
          ? `Too many attempts. Try again in ${formatSeconds(this.retryAfter)}.`
          : "Too many attempts. Try again shortly.";
      case "account_locked":
        return this.retryAfter
          ? `Too many failed attempts. This account is locked for ${formatSeconds(this.retryAfter)}.`
          : "Too many failed attempts. This account is locked briefly.";
      case "totp_required":
        return "Enter the 6-digit code from your authenticator app.";
      case "totp_invalid":
        // Each code can only be used once, so "wait for the next one" is
        // frequently the actual fix rather than a brush-off.
        return "That code was not accepted. Wait for the next one and try again.";
      case "internal_error":
        return "The server hit an error. Your vault was not changed.";
      default:
        return this.message;
    }
  }
}

function formatSeconds(seconds: number): string {
  if (seconds < 60) return `${seconds} second${seconds === 1 ? "" : "s"}`;
  const minutes = Math.ceil(seconds / 60);
  return `${minutes} minute${minutes === 1 ? "" : "s"}`;
}

export class ApiClient {
  readonly #baseUrl: string;
  readonly #fetch: typeof fetch;

  constructor(baseUrl: string, fetchImpl: typeof fetch = globalThis.fetch.bind(globalThis)) {
    this.#baseUrl = baseUrl.replace(/\/+$/, "");
    this.#fetch = fetchImpl;
  }

  async #request<T>(
    path: string,
    init: { method: string; body?: unknown; token?: string } = { method: "GET" },
  ): Promise<T> {
    const headers: Record<string, string> = { Accept: "application/json" };
    if (init.body !== undefined) headers["Content-Type"] = "application/json";
    if (init.token) headers["Authorization"] = `Bearer ${init.token}`;

    let response: Response;
    try {
      response = await this.#fetch(this.#baseUrl + path, {
        method: init.method,
        headers,
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
        // No cookies: the session is a bearer token held in memory. Nothing to
        // send means nothing for a cross-site request to ride on, so CSRF is
        // structurally absent rather than defended against.
        credentials: "omit",
        mode: "cors",
        cache: "no-store",
        referrerPolicy: "no-referrer",
      });
    } catch (cause) {
      throw new ApiError("network_error", 0, "Network request failed", {});
    }

    if (response.status === 204) return undefined as T;

    const payload = await response.json().catch(() => null);

    if (!response.ok) {
      const error = (payload as { error?: { code?: string; message?: string } } | null)?.error;
      const retryAfterHeader = response.headers.get("Retry-After");
      throw new ApiError(
        (error?.code as ApiErrorCode) ?? "internal_error",
        response.status,
        error?.message ?? `Request failed with status ${response.status}`,
        {
          currentRevision: (payload as { currentRevision?: number } | null)?.currentRevision,
          retryAfter: retryAfterHeader ? Number(retryAfterHeader) : undefined,
        },
      );
    }

    return payload as T;
  }

  health(): Promise<{ status: string; version: number }> {
    return this.#request("/api/health");
  }

  register(body: {
    accountId: string;
    authKey: string;
    kdf: KdfParams;
    protectedVaultKey: string;
  }): Promise<Session> {
    return this.#request("/api/auth/register", { method: "POST", body });
  }

  prelogin(accountId: string): Promise<{ kdf: KdfParams }> {
    return this.#request("/api/auth/prelogin", { method: "POST", body: { accountId } });
  }

  login(
    accountId: string,
    authKey: string,
    second: { totpCode?: string; recoveryCode?: string } = {},
  ): Promise<Session> {
    return this.#request("/api/auth/login", {
      method: "POST",
      body: {
        accountId,
        authKey,
        // Omitted entirely rather than sent as undefined: the API body
        // schema is strict and rejects unknown or null fields.
        ...(second.totpCode ? { totpCode: second.totpCode } : {}),
        ...(second.recoveryCode ? { recoveryCode: second.recoveryCode } : {}),
      },
    });
  }

  // -------------------------------------------------------------------------
  // Two-factor authentication
  // -------------------------------------------------------------------------

  twoFactorStatus(token: string): Promise<TwoFactorStatus> {
    return this.#request("/api/auth/2fa", { method: "GET", token });
  }

  startTwoFactor(token: string): Promise<{ secret: string; uri: string }> {
    return this.#request("/api/auth/2fa/setup", { method: "POST", body: {}, token });
  }

  /** Returns the recovery codes. They are shown once and never retrievable. */
  enableTwoFactor(token: string, code: string): Promise<{ recoveryCodes: string[] }> {
    return this.#request("/api/auth/2fa/enable", { method: "POST", body: { code }, token });
  }

  disableTwoFactor(token: string, authKey: string, code: string): Promise<void> {
    return this.#request("/api/auth/2fa/disable", {
      method: "POST",
      body: { authKey, code },
      token,
    });
  }

  activity(token: string): Promise<{ events: ActivityEvent[] }> {
    return this.#request("/api/auth/activity", { method: "GET", token });
  }

  logout(token: string): Promise<void> {
    return this.#request("/api/auth/logout", { method: "POST", token });
  }

  changePassword(
    token: string,
    body: {
      currentAuthKey: string;
      newAuthKey: string;
      kdf: KdfParams;
      protectedVaultKey: string;
    },
  ): Promise<void> {
    return this.#request("/api/auth/change-password", { method: "POST", body, token });
  }

  getVault(token: string): Promise<VaultResponse> {
    return this.#request("/api/vault", { method: "GET", token });
  }

  putVault(
    token: string,
    vault: string,
    expectedRevision: number,
  ): Promise<{ vaultRevision: number; vaultUpdatedAt: string }> {
    return this.#request("/api/vault", {
      method: "PUT",
      body: { vault, expectedRevision },
      token,
    });
  }
}

/** The API hands back `protectedVaultKey` as a string; the crypto library wants
 *  a parsed envelope. One place does the conversion so a shape change breaks
 *  here rather than somewhere subtle. */
export function toKeyRecord(
  wire: WireKeyRecord,
  deserialize: (value: string) => AccountKeyRecord["protectedVaultKey"],
): AccountKeyRecord {
  return {
    accountId: wire.accountId,
    kdf: wire.kdf,
    protectedVaultKey: deserialize(wire.protectedVaultKey),
  };
}
