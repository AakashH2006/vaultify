/**
 * End-to-end smoke test against a *running* Vaultify API.
 *
 *   npm run start --workspace @vaultify/api     # in one terminal
 *   npm run smoke --workspace @vaultify/api     # in another
 *
 * The unit suites run the Express app in-process against an in-memory store.
 * This one goes over real HTTP to whatever is actually deployed, driving it with
 * the genuine client library -- so it catches the things in-process tests
 * cannot: a misconfigured server, a broken database connection, a reverse proxy
 * mangling bodies.
 *
 * Override the target with BASE=https://api.example.com.
 */

import {
  createAccount,
  decryptVault,
  deserialize,
  emptyVault,
  encryptVault,
  generatePassword,
  serialize,
} from "../../packages/crypto/src/index.ts";

const BASE = process.env.BASE ?? "http://127.0.0.1:4000";
const KDF = { algorithm: "PBKDF2", iterations: 600_000 } as const;

const email = "smoke-" + Date.now() + "@example.com";
const masterPassword = "correct horse battery staple";

let failures = 0;

function check(label: string, ok: boolean): void {
  console.log((ok ? "  ✔ " : "  ✖ ") + label);
  if (!ok) failures++;
}

async function call(
  method: string,
  path: string,
  body?: unknown,
  token?: string,
): Promise<{ status: number; body: any }> {
  const response = await fetch(BASE + path, {
    method,
    headers: {
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      ...(token ? { Authorization: "Bearer " + token } : {}),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  return { status: response.status, body: text ? JSON.parse(text) : null };
}

console.log("\nVaultify smoke test against " + BASE + "\n");

// -- 1. the service is up ----------------------------------------------------
const health = await call("GET", "/api/health");
check("GET /api/health responds 200", health.status === 200);

// -- 2. registration, entirely client-side key generation --------------------
const account = await createAccount(email, masterPassword, KDF);
const registration = await call("POST", "/api/auth/register", {
  accountId: email,
  authKey: account.authKey,
  kdf: KDF,
  protectedVaultKey: serialize(account.keyRecord.protectedVaultKey),
});
check("POST /api/auth/register creates the account", registration.status === 201);
check("registration returns a bearer token", Boolean(registration.body?.accessToken));

// -- 3. seal and store a vault ----------------------------------------------
const generated = generatePassword({ length: 24 });
const now = new Date().toISOString();
const vault = {
  ...emptyVault(),
  entries: [
    {
      id: crypto.randomUUID(),
      name: "GitHub",
      username: "ada",
      password: generated,
      url: "https://github.com",
      createdAt: now,
      updatedAt: now,
    },
  ],
};

const sealed = serialize(await encryptVault(account.vaultKey, vault, email));
const saved = await call(
  "PUT",
  "/api/vault",
  { vault: sealed, expectedRevision: 0 },
  registration.body.accessToken,
);
check("PUT /api/vault stores the blob at revision 1", saved.status === 200 && saved.body.vaultRevision === 1);

// -- 4. optimistic concurrency ----------------------------------------------
const stale = await call(
  "PUT",
  "/api/vault",
  { vault: sealed, expectedRevision: 0 },
  registration.body.accessToken,
);
check("a stale write is rejected with 409", stale.status === 409);

// -- 5. log in from a "second device" ---------------------------------------
const prelogin = await call("POST", "/api/auth/prelogin", { accountId: email });
check("prelogin returns the account's KDF parameters", prelogin.body?.kdf?.iterations === KDF.iterations);

const unknownPrelogin = await call("POST", "/api/auth/prelogin", { accountId: "nobody@example.com" });
check(
  "prelogin does not reveal whether an account exists",
  unknownPrelogin.status === prelogin.status &&
    JSON.stringify(Object.keys(unknownPrelogin.body)) === JSON.stringify(Object.keys(prelogin.body)),
);

const login = await call("POST", "/api/auth/login", { accountId: email, authKey: account.authKey });
check("POST /api/auth/login accepts the derived auth key", login.status === 200);

// -- 6. the whole point: it still decrypts ----------------------------------
const fetched = await call("GET", "/api/vault", undefined, login.body.accessToken);
const reopened = await decryptVault(account.vaultKey, deserialize(fetched.body.vault), email);
check("the stored vault decrypts to the original entry", reopened.entries[0].password === generated);

const responseText = JSON.stringify(fetched.body);
check(
  "nothing the server returned contains plaintext",
  !responseText.includes(generated) && !responseText.includes("GitHub"),
);

// -- 7. negative cases -------------------------------------------------------
const wrongKey = await call("POST", "/api/auth/login", {
  accountId: email,
  authKey: "A".repeat(43) + "=",
});
check("a wrong auth key is rejected with 401", wrongKey.status === 401);

const unauthenticated = await call("GET", "/api/vault");
check("GET /api/vault without a token is rejected", unauthenticated.status === 401);

const loggedOut = await call("POST", "/api/auth/logout", undefined, login.body.accessToken);
check("POST /api/auth/logout succeeds", loggedOut.status === 204);

const afterLogout = await call("GET", "/api/vault", undefined, login.body.accessToken);
check("the revoked token no longer works", afterLogout.status === 401);

// -- 8. headers --------------------------------------------------------------
const headerProbe = await fetch(BASE + "/api/health");
check("responses are marked no-store", headerProbe.headers.get("cache-control") === "no-store");
check("the stack is not advertised", headerProbe.headers.get("x-powered-by") === null);

console.log(
  "\n" + (failures === 0 ? "All smoke checks passed." : failures + " smoke check(s) FAILED.") + "\n",
);
process.exit(failures === 0 ? 0 : 1);
