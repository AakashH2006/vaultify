/**
 * Tests for the build itself.
 *
 * The build is not incidental tooling here. It is what makes two of the
 * project's security claims true -- that the shipped client is auditable, and
 * that the CSP contains no blanket inline exemption -- so the properties it is
 * supposed to guarantee are asserted rather than assumed.
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";

import { BREACH_API_ORIGIN, build, type BuildResult } from "../build.ts";

const API_ORIGIN = "https://api.vaultify.test";

let out: string;
let result: BuildResult;
let html: string;

before(async () => {
  out = await mkdtemp(join(tmpdir(), "vaultify-build-"));
  result = await build({ outDir: out, apiOrigin: API_ORIGIN, buildId: "test-build" });
  html = await readFile(join(out, "index.html"), "utf8");
});

after(async () => {
  await rm(out, { recursive: true, force: true });
});

async function emittedModules(): Promise<string[]> {
  const found: string[] = [];
  const walk = async (dir: string, prefix: string): Promise<void> => {
    for (const item of await readdir(dir, { withFileTypes: true })) {
      if (item.isDirectory()) await walk(join(dir, item.name), `${prefix}/${item.name}`);
      else if (item.name.endsWith(".js")) found.push(`${prefix}/${item.name}`);
    }
  };
  await walk(join(out, "app"), "/app");
  return found.sort();
}

describe("the emitted module graph", () => {
  it("includes the application and the crypto package", async () => {
    const modules = await emittedModules();
    assert.ok(modules.includes("/app/main.js"));
    assert.ok(modules.includes("/app/session.js"));
    assert.ok(modules.includes("/app/vendor/crypto/index.js"));
    assert.ok(modules.includes("/app/vendor/crypto/kdf.js"));
  });

  it("vendors every workspace package the app imports", async () => {
    // The failure this catches is silent at build time and fatal at runtime:
    // an unmapped bare specifier throws "Failed to resolve module specifier"
    // in the browser and the page renders nothing at all.
    const specifiers = new Set<string>();
    for (const published of await emittedModules()) {
      const source = await readFile(join(out, published.replace("/app/", "app/")), "utf8");
      for (const match of source.matchAll(/from\s*["'](@vaultify\/[^"']+)["']/g)) {
        specifiers.add(match[1]);
      }
    }

    assert.ok(specifiers.size > 0, "no workspace imports found; this test is not looking anywhere");

    const importMap = JSON.parse(
      html.match(/<script type="importmap">([\s\S]*?)<\/script>/)![1],
    ) as { imports: Record<string, string> };

    for (const specifier of specifiers) {
      assert.ok(
        specifier in importMap.imports,
        `${specifier} is imported but has no import-map entry`,
      );
      const target = importMap.imports[specifier].replace("/app/", "app/");
      await readFile(join(out, target), "utf8"); // throws if it was not emitted
    }
  });

  it("leaves no .ts specifier behind for the browser to choke on", async () => {
    for (const published of await emittedModules()) {
      const source = await readFile(join(out, published.replace("/app/", "app/")), "utf8");
      const offenders = source.match(/from\s*["'][^"']+\.ts["']/g);
      assert.equal(offenders, null, `${published} still imports a .ts path: ${offenders}`);
    }
  });

  it("emits plain JavaScript -- no type annotations survive", async () => {
    const session = await readFile(join(out, "app/session.js"), "utf8");
    assert.ok(!/:\s*Promise<VaultSession>/.test(session));
    assert.ok(!/\binterface\s+SaveResult\b/.test(session));
    // ...but the code itself is intact and still readable.
    assert.match(session, /class VaultSession/);
    assert.match(session, /async save\(\)/);
  });

  it("preserves line numbers, so a stack trace points at the source", async () => {
    const source = await readFile(
      new URL("../src/session.ts", import.meta.url),
      "utf8",
    );
    const emitted = await readFile(join(out, "app/session.js"), "utf8");
    assert.equal(emitted.split("\n").length, source.split("\n").length);
  });

  it("ships no bundler runtime and no third-party code", async () => {
    for (const published of await emittedModules()) {
      const source = await readFile(join(out, published.replace("/app/", "app/")), "utf8");
      assert.ok(!source.includes("node_modules"), `${published} references node_modules`);
      assert.ok(!/__webpack|__esbuild|_interopRequire/.test(source), `${published} carries a bundler shim`);
    }
  });
});

describe("subresource integrity", () => {
  it("covers every emitted module", async () => {
    const modules = await emittedModules();
    assert.deepEqual(Object.keys(result.integrity).sort(), modules);
  });

  it("publishes hashes that actually match the bytes served", async () => {
    for (const [published, expected] of Object.entries(result.integrity)) {
      const bytes = await readFile(join(out, published.replace(/^\//, "")));
      const actual = `sha384-${createHash("sha384").update(bytes).digest("base64")}`;
      assert.equal(actual, expected, `integrity mismatch for ${published}`);
    }
  });

  it("puts the integrity map where the browser will enforce it", () => {
    assert.match(html, /<script type="importmap">/);
    assert.match(html, /"integrity": \{/);
    assert.match(html, /"@vaultify\/crypto": "\/app\/vendor\/crypto\/index\.js"/);
  });

  it("gives the entry script its own integrity attribute", () => {
    // Import-map integrity is Chromium-only so far; the attribute on the entry
    // `<script>` is supported everywhere and covers the module that pulls in
    // all the rest.
    assert.match(html, /<script type="module" src="\/app\/main\.js" integrity="sha384-[^"]+"/);
    const match = html.match(/src="\/app\/main\.js" integrity="(sha384-[^"]+)"/);
    assert.equal(match?.[1], result.integrity["/app/main.js"]);
  });
});

describe("the content security policy", () => {
  it("has no blanket inline or eval exemption", () => {
    assert.ok(!result.csp.includes("unsafe-inline"), result.csp);
    assert.ok(!result.csp.includes("unsafe-eval"), result.csp);
  });

  it("allows the one unavoidable inline element by hash, not by exemption", () => {
    // Hash the element's text content byte for byte, exactly as the browser
    // does -- surrounding whitespace included. A hash taken over a trimmed or
    // re-serialised copy still looks right in a diff, but the browser rejects
    // the script, the import map never applies, and every bare specifier in
    // the app fails to resolve. Nothing else in the page catches that.
    const importMap = html.match(/<script type="importmap">([\s\S]*?)<\/script>/);
    assert.ok(importMap, "import map not found in the page");

    const hash = `sha256-${createHash("sha256").update(importMap[1], "utf8").digest("base64")}`;
    assert.equal(hash, result.importMapHash, "the shipped hash does not cover the shipped bytes");
    assert.ok(result.csp.includes(`'${hash}'`), "the CSP does not allow the import map it shipped");
  });

  it("denies everything by default and names the API explicitly", () => {
    assert.match(result.csp, /default-src 'none'/);
    assert.ok(result.csp.includes(`connect-src 'self' ${API_ORIGIN}`));
    // A stolen key cannot be posted to an attacker's host from this origin.
    assert.ok(!result.csp.includes("connect-src *"));
  });

  it("allows exactly two destinations: our API and the breach range API", () => {
    const connect = result.csp
      .split("; ")
      .find((directive) => directive.startsWith("connect-src"));
    assert.ok(connect);

    const sources = connect.replace("connect-src ", "").split(" ");
    assert.deepEqual(sources, ["'self'", API_ORIGIN, BREACH_API_ORIGIN]);
  });

  it("names the breach API by exact origin, with no wildcard", () => {
    assert.ok(result.csp.includes("https://api.pwnedpasswords.com"));
    assert.ok(!result.csp.includes("*.pwnedpasswords.com"));
    assert.ok(!/connect-src[^;]*\shttps:(\s|;|$)/.test(result.csp), "a bare https: scheme source");
  });

  it("forbids framing, plugins, form posts and base-tag hijacking", () => {
    for (const directive of [
      "frame-ancestors 'none'",
      "object-src 'none'",
      "form-action 'none'",
      "base-uri 'none'",
    ]) {
      assert.ok(result.csp.includes(directive), `missing: ${directive}`);
    }
  });

  it("is written out next to the build for the production proxy to copy", async () => {
    const onDisk = await readFile(join(out, "csp.txt"), "utf8");
    assert.equal(onDisk.trim(), result.csp);
  });
});

describe("the page", () => {
  it("contains no inline event handler or inline style", () => {
    assert.ok(!/\son[a-z]+=/i.test(html), "inline event handler in index.html");
    assert.ok(!/\sstyle="/i.test(html), "inline style attribute in index.html");
  });

  it("explains itself when scripting is off, rather than showing a blank page", () => {
    assert.match(html, /<noscript/);
    assert.match(html, /cannot work\s+without JavaScript/);
  });

  it("stamps the build id so a stale cache is identifiable", () => {
    assert.match(html, /test-build/);
  });

  it("leaves no unreplaced placeholder", () => {
    assert.ok(!html.includes("<!--IMPORT_MAP-->"));
    assert.ok(!html.includes("<!--ENTRY_SCRIPT-->"));
    assert.ok(!html.includes("<!--BUILD_ID-->"));
  });
});

describe("build-time configuration", () => {
  it("bakes the API origin into a module instead of an inline script", async () => {
    const config = await readFile(join(out, "app/config.js"), "utf8");
    assert.match(config, new RegExp(`API_ORIGIN = "${API_ORIGIN}"`));
    assert.ok(!html.includes(API_ORIGIN.replace(/^https?:\/\//, "")) || !html.includes("window."));
  });

  it("is reproducible: the same inputs give the same hashes", async () => {
    const second = await mkdtemp(join(tmpdir(), "vaultify-build-"));
    try {
      const again = await build({ outDir: second, apiOrigin: API_ORIGIN, buildId: "test-build" });
      assert.deepEqual(again.integrity, result.integrity);
      assert.equal(again.importMapHash, result.importMapHash);
    } finally {
      await rm(second, { recursive: true, force: true });
    }
  });
});
