/**
 * Session tokens (JWT, HS256).
 *
 * Two things this implementation does that a naive one often skips:
 *
 *   - Every token carries a session id (`sid`) that is checked against the
 *     store on each request. A stateless JWT cannot be revoked, which means
 *     logout is cosmetic and a master-password change cannot kick other
 *     devices off. The store lookup buys real revocation.
 *   - Issuer and audience are pinned on verification, so a token minted by
 *     some other service that happens to share the secret will not be
 *     accepted here.
 *
 * The token authorises *fetching the encrypted vault*. It is not a key, and
 * stealing it does not reveal a single stored password.
 */

import { randomUUID } from "node:crypto";
import { SignJWT, jwtVerify, type JWTPayload } from "jose";

const ISSUER = "vaultify";
const AUDIENCE = "vaultify-api";
const ALGORITHM = "HS256";

export interface SessionClaims {
  readonly accountId: string;
  readonly sessionId: string;
  readonly expiresAt: Date;
}

export interface IssuedToken {
  readonly accessToken: string;
  readonly sessionId: string;
  readonly expiresAt: Date;
  readonly expiresInSeconds: number;
}

export class TokenService {
  readonly #secret: Uint8Array;
  readonly #ttlSeconds: number;

  constructor(secret: string, ttlSeconds: number) {
    this.#secret = new TextEncoder().encode(secret);
    this.#ttlSeconds = ttlSeconds;
  }

  async issue(accountId: string): Promise<IssuedToken> {
    const sessionId = randomUUID();
    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAtSeconds = issuedAt + this.#ttlSeconds;

    const accessToken = await new SignJWT({ sid: sessionId })
      .setProtectedHeader({ alg: ALGORITHM })
      .setSubject(accountId)
      .setIssuer(ISSUER)
      .setAudience(AUDIENCE)
      .setIssuedAt(issuedAt)
      .setExpirationTime(expiresAtSeconds)
      .sign(this.#secret);

    return {
      accessToken,
      sessionId,
      expiresAt: new Date(expiresAtSeconds * 1000),
      expiresInSeconds: this.#ttlSeconds,
    };
  }

  /** Resolves to null for anything we will not accept -- bad signature, wrong
   *  algorithm, expired, wrong issuer/audience, missing claims. */
  async verify(token: string): Promise<SessionClaims | null> {
    try {
      const { payload } = await jwtVerify(token, this.#secret, {
        issuer: ISSUER,
        audience: AUDIENCE,
        // Pinning the algorithm is what stops the classic "alg: none" and
        // HS256/RS256 confusion attacks.
        algorithms: [ALGORITHM],
      });
      return toClaims(payload);
    } catch {
      return null;
    }
  }
}

function toClaims(payload: JWTPayload): SessionClaims | null {
  const sessionId = payload.sid;
  if (typeof payload.sub !== "string" || typeof sessionId !== "string" || !payload.exp) {
    return null;
  }
  return {
    accountId: payload.sub,
    sessionId,
    expiresAt: new Date(payload.exp * 1000),
  };
}
