/**
 * Error handling.
 *
 * The rule for this API: a client learns the minimum needed to react
 * correctly, and nothing more. Error bodies carry a stable machine-readable
 * `code` plus a short message that is safe to show a user. Stack traces,
 * driver errors and SQL never cross the wire.
 */

import type { NextFunction, Request, Response } from "express";

export type ErrorCode =
  | "invalid_request"
  | "invalid_credentials"
  | "unauthorized"
  | "account_exists"
  | "not_found"
  | "conflict"
  | "payload_too_large"
  | "rate_limited"
  | "https_required"
  | "internal_error"
  /** The auth key was right, but this account has 2FA on and no code was
   *  sent. Only ever returned *after* the auth key verifies, so it cannot be
   *  used to discover whether an account exists or whether it has 2FA. */
  | "totp_required"
  | "totp_invalid"
  | "totp_not_enrolled"
  | "account_locked";

export class ApiError extends Error {
  readonly status: number;
  readonly code: ErrorCode;
  readonly headers?: Record<string, string>;

  constructor(status: number, code: ErrorCode, message: string, headers?: Record<string, string>) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.headers = headers;
  }

  static badRequest(message = "The request body is not valid.") {
    return new ApiError(400, "invalid_request", message);
  }

  /**
   * Deliberately identical for "no such account" and "wrong auth key". The
   * login route also spends the same time on both paths -- see
   * `verifyAuthKey`'s dummy-verify branch -- so neither the body nor the
   * timing reveals whether an email is registered.
   */
  static invalidCredentials() {
    return new ApiError(401, "invalid_credentials", "Incorrect email or master password.");
  }

  static unauthorized(message = "Authentication required.") {
    return new ApiError(401, "unauthorized", message);
  }

  static notFound(message = "Not found.") {
    return new ApiError(404, "not_found", message);
  }

  static conflict(message: string) {
    return new ApiError(409, "conflict", message);
  }

  /** Carries Retry-After so a client can show a real countdown instead of
   *  inviting the user to keep hammering the form. */
  static locked(seconds: number) {
    return new ApiError(
      429,
      "account_locked",
      "Too many failed attempts. This account is locked briefly.",
      { "Retry-After": String(seconds) },
    );
  }
}

interface ErrorBody {
  error: { code: ErrorCode; message: string; details?: unknown };
}

export function notFoundHandler(_req: Request, res: Response): void {
  const body: ErrorBody = {
    error: { code: "not_found", message: "No such endpoint." },
  };
  res.status(404).json(body);
}

export function errorHandler(
  error: unknown,
  _req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (res.headersSent) {
    next(error);
    return;
  }

  if (error instanceof ApiError) {
    if (error.headers) {
      for (const [name, value] of Object.entries(error.headers)) res.setHeader(name, value);
    }
    res.status(error.status).json({ error: { code: error.code, message: error.message } });
    return;
  }

  // Express's body parser rejects oversized bodies before our own check.
  if (isPayloadTooLarge(error)) {
    res.status(413).json({
      error: { code: "payload_too_large", message: "The request body is too large." },
    });
    return;
  }

  // Anything reaching here is a bug. Log it server-side; tell the client nothing.
  console.error("[unhandled]", error);
  res.status(500).json({
    error: { code: "internal_error", message: "Something went wrong." },
  });
}

function isPayloadTooLarge(error: unknown): boolean {
  return (
    typeof error === "object" &&
    error !== null &&
    (error as { type?: string }).type === "entity.too.large"
  );
}
