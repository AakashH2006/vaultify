/**
 * Build-time configuration.
 *
 * `build.ts` overwrites the emitted `config.js` with the real values, so the
 * API origin is baked into the bundle rather than read from a global or an
 * inline script tag. That matters for the CSP: an inline `<script>` carrying
 * configuration is exactly the thing `script-src 'self'` exists to forbid, and
 * carving out an exception for "just the config" is how `unsafe-inline` ends up
 * in a policy.
 *
 * The values here are the development defaults and the types the build must
 * satisfy.
 */

/** Origin of the Vaultify API. Must match the API's CORS_ORIGIN pairing. */
export const API_ORIGIN = "http://localhost:4000";

/** Stamped by the build so a stale cached bundle is identifiable in a bug report. */
export const BUILD_ID = "development";
