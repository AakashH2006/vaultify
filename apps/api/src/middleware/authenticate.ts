/**
 * Bearer-token authentication.
 *
 * Two checks, both required: the JWT must verify, and its session must still
 * be live in the store. The second is what makes logout and "sign out
 * everywhere on password change" actually work.
 */

import type { NextFunction, Request, Response } from "express";
import { ApiError } from "../errors.ts";
import type { TokenService } from "../auth/tokens.ts";
import type { Store } from "../store/types.ts";

export interface AuthenticatedRequest extends Request {
  auth?: { accountId: string; sessionId: string };
}

export function authenticate(tokens: TokenService, store: Store) {
  return async (req: AuthenticatedRequest, _res: Response, next: NextFunction): Promise<void> => {
    const header = req.headers.authorization;

    if (!header?.startsWith("Bearer ")) {
      next(ApiError.unauthorized("Missing bearer token."));
      return;
    }

    const claims = await tokens.verify(header.slice("Bearer ".length).trim());
    if (!claims) {
      next(ApiError.unauthorized("Invalid or expired token."));
      return;
    }

    // A signature alone is not enough: the session may have been revoked by a
    // logout or a password change since the token was minted.
    if (!(await store.isSessionActive(claims.sessionId))) {
      next(ApiError.unauthorized("This session has been signed out."));
      return;
    }

    req.auth = { accountId: claims.accountId, sessionId: claims.sessionId };
    next();
  };
}

/** Narrowing helper so routes do not repeat the non-null assertion. */
export function requireAuth(req: AuthenticatedRequest): { accountId: string; sessionId: string } {
  if (!req.auth) throw ApiError.unauthorized();
  return req.auth;
}
