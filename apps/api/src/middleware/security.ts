/**
 * Transport and header hardening.
 *
 * Hand-rolled rather than pulled from a package, because for a JSON API the
 * useful set is short enough to read in one sitting -- and on a security
 * project, "I can explain every header we send" is worth more than a
 * dependency.
 */

import type { NextFunction, Request, Response } from "express";
import type { Config } from "../config.ts";
import { ApiError } from "../errors.ts";

export function securityHeaders(config: Config) {
  return (_req: Request, res: Response, next: NextFunction): void => {
    // This API only ever returns JSON. A restrictive CSP costs nothing here and
    // neutralises content-sniffing tricks against error pages.
    res.setHeader("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");

    // Nothing here should ever sit in a shared cache or a browser's disk cache.
    res.setHeader("Cache-Control", "no-store");

    // Express advertises itself by default; no reason to name the stack.
    res.removeHeader("X-Powered-By");

    if (config.requireHttps) {
      res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
    }

    next();
  };
}

/**
 * Refuses plain HTTP when TLS is required.
 *
 * A redirect would be friendlier for a browser, but this is an API: by the time
 * we could redirect, the auth key has already crossed the wire in the clear.
 * Failing the request is the honest response, and the client should be
 * configured with an https:// base URL in the first place.
 */
export function requireHttps(config: Config) {
  return (req: Request, _res: Response, next: NextFunction): void => {
    if (!config.requireHttps) {
      next();
      return;
    }

    // `req.secure` already accounts for X-Forwarded-Proto when trust proxy is on.
    if (req.secure) {
      next();
      return;
    }

    next(
      new ApiError(
        403,
        "https_required",
        "This API is only available over HTTPS.",
      ),
    );
  };
}

/**
 * CORS for exactly one origin.
 *
 * No wildcard, and no reflecting whatever Origin the request carried: the
 * browser is the only thing enforcing same-origin on the client's behalf, and
 * reflecting the origin back hands that protection to the attacker.
 */
export function cors(config: Config) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const origin = req.headers.origin;

    if (origin === config.CORS_ORIGIN) {
      res.setHeader("Access-Control-Allow-Origin", origin);
      res.setHeader("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS");
      res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
      res.setHeader("Access-Control-Max-Age", "600");
    }
    // Responses differ by Origin, so caches must key on it.
    res.setHeader("Vary", "Origin");

    if (req.method === "OPTIONS") {
      res.status(204).end();
      return;
    }
    next();
  };
}
