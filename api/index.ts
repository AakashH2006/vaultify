/**
 * The API, as a Vercel Function.
 *
 * Vercel routes by file path, so this file has to exist at `/api`; the adapter
 * it calls lives in the API workspace, under test and under the typechecker.
 * `vercel.json` rewrites every `/api/*` path here, and Express sees the
 * original URL, so the routes are the same ones `server.ts` serves.
 */

import { createVercelHandler } from "../apps/api/src/vercel.ts";

export default createVercelHandler(process.env);
