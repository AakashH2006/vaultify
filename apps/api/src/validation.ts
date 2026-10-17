/**
 * Request validation.
 *
 * The server cannot read anything it stores, so it cannot repair bad data
 * later -- a malformed envelope written today is an unopenable vault forever.
 * Validation at the edge is the only chance to catch it, so these schemas are
 * strict about shape and length even though the contents stay opaque.
 */

import { z } from "zod";
import type { Request } from "express";
import { ApiError } from "./errors.ts";

const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;

/** Matches the compact envelope produced by @vaultify/crypto's `serialize`. */
const ENVELOPE = /^1\.AES-256-GCM\.[A-Za-z0-9+/]{16}\.[A-Za-z0-9+/]+={0,2}$/;

const envelope = (maxLength: number, label: string) =>
  z
    .string()
    .max(maxLength, label + " is too large")
    .regex(ENVELOPE, label + " is not a valid AES-256-GCM envelope");

/** Email, normalised the same way the client derives its salt -- trimmed and
 *  lowercased. If these two ever disagree, keys silently stop matching. */
export const accountId = z
  .string()
  .trim()
  .toLowerCase()
  .min(3)
  .max(254)
  .pipe(z.email("A valid email address is required"));

/** 256 bits of base64. Length is pinned because the client always sends
 *  exactly one HKDF output here. */
export const authKey = z
  .string()
  .length(44, "authKey must be 256 bits of base64")
  .regex(BASE64, "authKey must be base64");

/** Mirrors PBKDF2_MIN_ITERATIONS in @vaultify/crypto. The client enforces this
 *  too; duplicating it here means neither side can be talked out of it. */
export const kdf = z.object({
  algorithm: z.literal("PBKDF2"),
  iterations: z.number().int().min(100_000).max(10_000_000),
});

/** Wrapped 32-byte key plus a 16-byte tag. Small and fixed, so cap it tightly. */
const protectedVaultKey = envelope(256, "protectedVaultKey");

export const registerBody = z
  .object({ accountId, authKey, kdf, protectedVaultKey })
  .strict();

export const preloginBody = z.object({ accountId }).strict();

/** Six digits, optionally spaced the way a phone displays them. Not a
 *  `.length(6)` on the raw string: users paste "123 456". */
export const totpCode = z
  .string()
  .trim()
  .max(16, "That is not a 6-digit code")
  .refine((value) => value.replace(/\D/g, "").length === 6, "Enter the 6-digit code");

/** `XXXXX-XXXXX`, case- and separator-insensitive. */
export const recoveryCode = z
  .string()
  .trim()
  .max(24, "That is not a recovery code")
  .refine(
    (value) => /^[A-Za-z2-7]{10}$/.test(value.replace(/[\s-]/g, "")),
    "Enter one of your recovery codes",
  );

export const loginBody = z
  .object({
    accountId,
    authKey,
    /** Only required once 2FA is on, and the server says so with a
     *  `totp_required` error rather than advertising it up front. */
    totpCode: totpCode.optional(),
    recoveryCode: recoveryCode.optional(),
  })
  .strict();

export const totpSetupBody = z.object({}).strict();

export const totpEnableBody = z
  .object({
    /** Proves the authenticator was actually enrolled, rather than the user
     *  clicking past a QR code they never scanned and locking themselves out. */
    code: totpCode,
  })
  .strict();

export const totpDisableBody = z
  .object({
    /** A live session is not enough to remove a second factor. */
    authKey,
    code: totpCode,
  })
  .strict();

export const changePasswordBody = z
  .object({
    /** Proves the caller knows the current master password. */
    currentAuthKey: authKey,
    newAuthKey: authKey,
    kdf,
    /** The vault key, rewrapped under the new password's wrapping key. */
    protectedVaultKey,
  })
  .strict();

/** `expectedRevision` is what the client last read. The server rejects the
 *  write if the stored revision has moved on. */
export function putVaultBody(maxVaultBytes: number) {
  return z
    .object({
      vault: envelope(maxVaultBytes, "vault"),
      expectedRevision: z.number().int().min(0),
    })
    .strict();
}

/**
 * Parses a request body, converting a Zod failure into a 400 with field-level
 * detail. Safe to surface: these messages describe the request the client just
 * sent, not anything about other accounts or server internals.
 */
export function parseBody<T extends z.ZodType>(schema: T, req: Request): z.infer<T> {
  const result = schema.safeParse(req.body);
  if (result.success) return result.data;

  const detail = result.error.issues
    .map((issue) => (issue.path.length ? issue.path.join(".") + ": " : "") + issue.message)
    .join("; ");
  throw ApiError.badRequest(detail);
}
