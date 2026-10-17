/** Shapes that cross the crypto boundary. Kept free of any crypto imports so
 *  the UI and the API layer can depend on them without pulling in Web Crypto. */

export interface VaultEntry {
  readonly id: string;
  name: string;
  username: string;
  password: string;
  url?: string;
  notes?: string;
  /**
   * Base32 TOTP seed, so Vaultify can act as the authenticator for an entry.
   *
   * Sealed with the rest of the vault, and `@vaultify/totp` already generates
   * codes in the browser -- but nothing reads this field yet. It is the
   * smallest remaining open item; see docs/architecture.md §7.
   */
  totpSecret?: string;
  readonly createdAt: string;
  updatedAt: string;
}

/** The plaintext document. This object exists only inside an unlocked tab. */
export interface VaultContents {
  readonly version: number;
  entries: VaultEntry[];
}

export const VAULT_SCHEMA_VERSION = 1;

export function emptyVault(): VaultContents {
  return { version: VAULT_SCHEMA_VERSION, entries: [] };
}
