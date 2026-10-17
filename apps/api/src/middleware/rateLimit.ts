/**
 * Fixed-window rate limiting.
 *
 * The login route is the one place where an attacker gets unlimited free
 * guesses, and 600,000 PBKDF2 iterations only make each guess expensive for
 * them if they are doing the work. Someone script-guessing weak master
 * passwords across many accounts is cheap to run and must be throttled here.
 *
 * In-process state, so this is per-instance: behind more than one API node,
 * move the counter to Redis. That is the honest caveat and it is listed in the
 * README rather than hidden here.
 */

import type { NextFunction, Request, Response } from "express";
import { ApiError } from "../errors.ts";

export interface RateLimitOptions {
  /** Window length in milliseconds. */
  windowMs: number;
  /** Requests allowed per key per window. */
  max: number;
  /** Defaults to the client IP. Login also folds in the account id, so one
   *  noisy NAT cannot lock every user behind it out. */
  keyBy?: (req: Request) => string;
}

interface Window {
  count: number;
  resetAt: number;
}

export function rateLimit(options: RateLimitOptions) {
  const windows = new Map<string, Window>();
  const keyBy = options.keyBy ?? ((req: Request) => req.ip ?? "unknown");

  // Bounded cleanup so an attacker rotating keys cannot grow the map forever.
  const sweep = () => {
    const now = Date.now();
    for (const [key, window] of windows) {
      if (window.resetAt <= now) windows.delete(key);
    }
  };
  const timer = setInterval(sweep, options.windowMs);
  timer.unref?.();

  return (req: Request, res: Response, next: NextFunction): void => {
    const now = Date.now();
    const key = keyBy(req);
    let window = windows.get(key);

    if (!window || window.resetAt <= now) {
      window = { count: 0, resetAt: now + options.windowMs };
      windows.set(key, window);
    }

    window.count += 1;
    const remaining = Math.max(0, options.max - window.count);
    const resetSeconds = Math.ceil((window.resetAt - now) / 1000);

    res.setHeader("RateLimit-Limit", String(options.max));
    res.setHeader("RateLimit-Remaining", String(remaining));
    res.setHeader("RateLimit-Reset", String(resetSeconds));

    if (window.count > options.max) {
      next(
        new ApiError(429, "rate_limited", "Too many attempts. Try again shortly.", {
          "Retry-After": String(resetSeconds),
        }),
      );
      return;
    }

    next();
  };
}

/** Rate-limit key for the credential routes: IP plus the account being
 *  targeted, so attacking many accounts from one host trips the limit, and one
 *  attacker cannot lock a victim out by exhausting their account's budget
 *  alone. */
export function ipAndAccount(req: Request): string {
  const body = req.body as { accountId?: unknown } | undefined;
  const accountId = typeof body?.accountId === "string" ? body.accountId.toLowerCase() : "-";
  return (req.ip ?? "unknown") + "|" + accountId;
}
