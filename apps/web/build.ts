/**
 * The build. Zero dependencies, and not a bundler.
 *
 * Node 22.6+ can strip TypeScript types itself (`module.stripTypeScriptTypes`),
 * which is the same facility the rest of this repo already relies on to run
 * `.ts` files directly. So the whole build is: strip the types, rewrite `.ts`
 * import specifiers to `.js`, and write the files out. The module graph the
 * browser loads is the module graph in `src/` -- same files, same names, same
 * line numbers, because stripping replaces types with spaces rather than
 * reformatting.
 *
 * Why this matters more here than in most projects: the threat model's one
 * unfixable weakness is a compromised client bundle. The mitigation is that
 * the bundle is auditable, and "auditable" is a much stronger claim when the
 * shipped JavaScript is the source with the types whited out than when it is
 * a minified blob from a toolchain with its own dependency tree.
 *
 * Two security outputs come out of this, both listed as open items in the
 * architecture doc:
 *
 *   - **A CSP with no `unsafe-inline`.** Every script and style is a file.
 *     The one inline element that cannot be a file -- the import map, which
 *     the HTML parser requires inline -- is allowed by its SHA-256 hash, not
 *     by a blanket exemption.
 *
 *   - **SRI on the client bundle.** The import map carries an `integrity`
 *     entry for every module in the graph. A browser that supports import-map
 *     integrity (Chrome 127+) refuses a module whose bytes do not match; older
 *     browsers ignore the field and fall back to same-origin trust.
 */

import { createHash } from "node:crypto";
import { mkdir, readFile, readdir, rm, writeFile } from "node:fs/promises";
import { stripTypeScriptTypes } from "node:module";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, "../..");
const outDir = resolve(here, "dist");

/** Where the module graph is served from. Keep in step with `serve.ts`. */
const APP_BASE = "/app";

/**
 * The one third-party origin the client may contact, for the k-anonymity
 * breach check.
 *
 * Naming it here rather than widening `connect-src` is the point of the whole
 * directive: with exactly two allowed destinations, a script that somehow ran
 * on this origin has nowhere to post a stolen vault key. Adding an entry to
 * this list should always be a deliberate, reviewed act.
 */
const BREACH_API_ORIGIN = "https://api.pwnedpasswords.com";

/**
 * Workspace packages the browser needs, by bare specifier.
 *
 * Each becomes `/app/vendor/<name>/` and an import-map entry. A package added
 * here lands inside the audited bundle, so the list stays short and explicit
 * rather than being discovered by scanning package.json.
 */
const VENDORED: Record<string, string> = {
  crypto: "packages/crypto/src",
  totp: "packages/totp/src",
};

export interface BuildOptions {
  apiOrigin?: string;
  outDir?: string;
  /** Printed into the page and the import map so a stale cache is identifiable. */
  buildId?: string;
}

export { BREACH_API_ORIGIN };

export interface BuildResult {
  readonly outDir: string;
  /** Published path -> SRI hash, for every emitted module. */
  readonly integrity: Record<string, string>;
  /** `sha256-...` of the inline import map, for the CSP. */
  readonly importMapHash: string;
  readonly csp: string;
  readonly moduleCount: number;
  readonly bytes: number;
}

export async function build(options: BuildOptions = {}): Promise<BuildResult> {
  const apiOrigin = options.apiOrigin ?? process.env.VAULTIFY_API_ORIGIN ?? "http://localhost:4000";
  const target = resolve(options.outDir ?? outDir);
  const buildId = options.buildId ?? new Date().toISOString();

  await rm(target, { recursive: true, force: true });
  await mkdir(target, { recursive: true });

  const integrity: Record<string, string> = {};
  let bytes = 0;

  const emit = async (publishedPath: string, source: string): Promise<void> => {
    const absolute = join(target, publishedPath.replace(/^\//, ""));
    await mkdir(dirname(absolute), { recursive: true });
    await writeFile(absolute, source, "utf8");
    integrity[publishedPath] = sri(source);
    bytes += Buffer.byteLength(source, "utf8");
  };

  // ---- the workspace packages, unchanged, at stable paths ------------------
  for (const [name, directory] of Object.entries(VENDORED)) {
    const packageSrc = resolve(repoRoot, directory);
    for (const file of await tsFiles(packageSrc)) {
      const source = await transform(join(packageSrc, file));
      await emit(`${APP_BASE}/vendor/${name}/${toJs(file)}`, source);
    }
  }

  // ---- the application -----------------------------------------------------
  const appSrc = resolve(here, "src");
  for (const file of await tsFiles(appSrc)) {
    // `config.ts` is generated below with the real build-time values.
    if (file === "config.ts") continue;
    const source = await transform(join(appSrc, file));
    await emit(`${APP_BASE}/${toJs(file)}`, source);
  }

  await emit(`${APP_BASE}/config.js`, generatedConfig(apiOrigin, buildId));

  // ---- the import map, with integrity for every module ---------------------
  const importMap = {
    imports: Object.fromEntries(
      Object.keys(VENDORED).map((name) => [
        `@vaultify/${name}`,
        `${APP_BASE}/vendor/${name}/index.js`,
      ]),
    ),
    integrity,
  };
  // The CSP hash must cover the script element's text content *exactly* --
  // every byte, including the newlines around the JSON. Getting this subtly
  // wrong produces a policy the browser silently rejects, which here means the
  // import map never applies and every bare specifier fails to resolve. So the
  // inline text is built once, hashed, and inserted verbatim.
  const importMapText = `\n${JSON.stringify(importMap, null, 2)}\n    `;
  const importMapHash = sri(importMapText, "sha256");

  const csp = policy(apiOrigin, importMapHash);

  // ---- static assets -------------------------------------------------------
  const publicDir = resolve(here, "public");
  for (const file of await readdir(publicDir)) {
    if (file === "index.html") continue;
    const contents = await readFile(join(publicDir, file));
    await mkdir(target, { recursive: true });
    await writeFile(join(target, file), contents);
    bytes += contents.byteLength;
  }

  // The entry module carries its own `integrity` attribute -- that part of SRI
  // is universally supported, and covers the one script the HTML names directly.
  // The import map covers everything it pulls in behind that.
  const entryIntegrity = integrity[`${APP_BASE}/main.js`];
  const entryScript =
    `<script type="module" src="${APP_BASE}/main.js" ` +
    `integrity="${entryIntegrity}" crossorigin="anonymous"></script>`;

  const html = (await readFile(join(publicDir, "index.html"), "utf8"))
    .replace("<!--IMPORT_MAP-->", `<script type="importmap">${importMapText}</script>`)
    .replace("<!--ENTRY_SCRIPT-->", entryScript)
    .replace("<!--BUILD_ID-->", escapeHtml(buildId));

  await writeFile(join(target, "index.html"), html, "utf8");
  await writeFile(
    join(target, "csp.txt"),
    csp + "\n",
    "utf8",
  );

  return {
    outDir: target,
    integrity,
    importMapHash,
    csp,
    moduleCount: Object.keys(integrity).length,
    bytes,
  };
}

/**
 * Content-Security-Policy for the client.
 *
 * `default-src 'none'` and then nothing but what is actually needed. Worth
 * noting what is absent: no `unsafe-inline` anywhere, no `unsafe-eval`, and
 * `connect-src` naming exactly one API origin -- so a script that somehow did
 * execute still could not post a stolen vault key anywhere.
 */
function policy(apiOrigin: string, importMapHash: string): string {
  return [
    "default-src 'none'",
    `script-src 'self' '${importMapHash}'`,
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src 'self' ${apiOrigin} ${BREACH_API_ORIGIN}`,
    "form-action 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    "object-src 'none'",
    "require-trusted-types-for 'script'",
  ].join("; ");
}

function generatedConfig(apiOrigin: string, buildId: string): string {
  return [
    "// Generated by build.ts. Do not edit; edit src/config.ts and rebuild.",
    `export const API_ORIGIN = ${JSON.stringify(apiOrigin)};`,
    `export const BUILD_ID = ${JSON.stringify(buildId)};`,
    "",
  ].join("\n");
}

/** Strip types, then point the import specifiers at the emitted `.js` names. */
async function transform(absolutePath: string): Promise<string> {
  const source = await readFile(absolutePath, "utf8");
  let stripped: string;
  try {
    stripped = stripTypeScriptTypes(source, { mode: "strip" });
  } catch (error) {
    throw new Error(
      `Could not strip types from ${relative(repoRoot, absolutePath)}: ` +
        (error instanceof Error ? error.message : String(error)) +
        "\nThe tsconfig sets erasableSyntaxOnly, so this means a syntax Node cannot erase " +
        "(an enum, a namespace, or a parameter property) has crept in.",
    );
  }
  return rewriteSpecifiers(stripped);
}

/**
 * Rewrite `./foo.ts` to `./foo.js` in import and export specifiers.
 *
 * A regex over module syntax is usually a bad idea. It is safe here for a
 * narrow reason: this runs over *already stripped* output, and it only matches
 * a quoted relative specifier ending in `.ts` that directly follows `from` or
 * `import`. The repository has no dynamic imports of `.ts` paths and no string
 * literal of that shape in any other position; `test/build.test.ts` asserts
 * that no `.ts` specifier survives in the emitted output.
 */
function rewriteSpecifiers(source: string): string {
  return source.replace(
    /((?:^|[\s;}])(?:import|export)[\s\S]*?from\s*|(?:^|[\s;}])import\s*)(["'])(\.{1,2}\/[^"']+)\.ts\2/g,
    (_match, prefix: string, quote: string, path: string) => `${prefix}${quote}${path}.js${quote}`,
  );
}

function toJs(file: string): string {
  return file.replace(/\.ts$/, ".js").split("\\").join("/");
}

async function tsFiles(root: string): Promise<string[]> {
  const found: string[] = [];
  const walk = async (dir: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (entry.name.endsWith(".ts") && !entry.name.endsWith(".d.ts")) {
        found.push(relative(root, full).split("\\").join("/"));
      }
    }
  };
  await walk(root);
  return found.sort();
}

function sri(source: string, algorithm: "sha256" | "sha384" = "sha384"): string {
  return `${algorithm}-${createHash(algorithm).update(source, "utf8").digest("base64")}`;
}

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char] as string,
  );
}

// Run directly: `node build.ts`
if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
  const result = await build();
  const kb = (result.bytes / 1024).toFixed(1);
  console.log(`Built ${result.moduleCount} modules (${kb} kB) -> ${relative(repoRoot, result.outDir)}`);
  console.log(`Import map hash: ${result.importMapHash}`);
}
