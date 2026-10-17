/**
 * The storage locker: GET /api/vault and PUT /api/vault.
 *
 * These two handlers are intentionally dull. They move one opaque string in
 * and out of a row, check that the caller owns it, and enforce a revision. The
 * server has no idea how many entries the vault holds, what sites they are
 * for, or whether the blob it just stored decrypts to anything at all.
 */

import { Router } from "express";

import { ApiError } from "../errors.ts";
import type { Config } from "../config.ts";
import type { Store } from "../store/types.ts";
import type { TokenService } from "../auth/tokens.ts";
import { authenticate, requireAuth, type AuthenticatedRequest } from "../middleware/authenticate.ts";
import { parseBody, putVaultBody } from "../validation.ts";

export interface VaultDeps {
  store: Store;
  tokens: TokenService;
  config: Config;
}

export function vaultRoutes({ store, tokens, config }: VaultDeps): Router {
  const router = Router();
  const body = putVaultBody(config.MAX_VAULT_BYTES);

  router.use(authenticate(tokens, store));

  // -------------------------------------------------------------------------
  // GET /api/vault
  // -------------------------------------------------------------------------
  router.get("/", async (req: AuthenticatedRequest, res) => {
    const { accountId } = requireAuth(req);
    const account = await store.findAccount(accountId);

    // The token verified and its session is live, so the account should exist.
    // If it does not, it was deleted mid-session: treat that as signed out.
    if (!account) throw ApiError.unauthorized();

    res.json({
      // null before the first sync -- a new client must treat this as an empty
      // vault rather than an error.
      vault: account.vault,
      vaultRevision: account.vaultRevision,
      vaultUpdatedAt: account.vaultUpdatedAt,
      // Returned alongside so a client that resumed from a stored token can
      // unwrap its vault key without a second round trip.
      keyRecord: {
        accountId: account.accountId,
        kdf: account.kdf,
        protectedVaultKey: account.protectedVaultKey,
      },
    });
  });

  // -------------------------------------------------------------------------
  // PUT /api/vault
  // -------------------------------------------------------------------------
  router.put("/", async (req: AuthenticatedRequest, res) => {
    const { accountId } = requireAuth(req);
    const { vault, expectedRevision } = parseBody(body, req);

    const result = await store.saveVault(accountId, vault, expectedRevision);

    switch (result.status) {
      case "saved":
        res.json({
          vaultRevision: result.vaultRevision,
          vaultUpdatedAt: result.vaultUpdatedAt,
        });
        return;

      case "conflict":
        // Someone else wrote since this client last read. The server cannot
        // merge -- it cannot read either version -- so the client must re-read,
        // re-apply its change over the newer vault, and retry.
        res
          .status(409)
          .json({
            error: {
              code: "conflict",
              message:
                "The vault changed since you last loaded it. Reload and reapply your changes.",
            },
            currentRevision: result.currentRevision,
          });
        return;

      case "no_such_account":
        throw ApiError.unauthorized();
    }
  });

  return router;
}
