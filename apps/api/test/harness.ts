import { once } from "node:events";
import type { AddressInfo } from "node:net";
import type { Server } from "node:http";

import { createApp } from "../src/app.ts";
import { loadConfig } from "../src/config.ts";
import { MemoryStore } from "../src/store/memory.ts";
import type { Store } from "../src/store/types.ts";

/**
 * Imported by relative path rather than by package name: Node's native type
 * stripping refuses to run .ts files that live under node_modules, which is
 * where the workspace symlink points. Only the tests need the client library --
 * the API itself has no dependency on it.
 */
import {
  createAccount,
  encryptVault,
  serialize,
  emptyVault,
  type VaultContents,
} from "../../../packages/crypto/src/index.ts";

/** Matches PBKDF2_MIN_ITERATIONS, so the suite stays fast without routing
 *  around the floor the API enforces. */
export const TEST_KDF = { algorithm: "PBKDF2", iterations: 100_000 } as const;

export interface TestResponse<T = any> {
  status: number;
  body: T;
  headers: Headers;
}

export interface TestApi {
  baseUrl: string;
  store: Store;
  request(method: string, path: string, options?: RequestOptions): Promise<TestResponse>;
  get(path: string, token?: string): Promise<TestResponse>;
  post(path: string, body?: unknown, token?: string): Promise<TestResponse>;
  put(path: string, body?: unknown, token?: string): Promise<TestResponse>;
  close(): Promise<void>;
}

interface RequestOptions {
  body?: unknown;
  token?: string;
  headers?: Record<string, string>;
}

/**
 * Boots the real Express app on an ephemeral port with a fresh in-memory store.
 *
 * One instance per test, deliberately: the rate limiters hold per-process
 * state, and sharing an app across tests would make them order-dependent.
 */
export async function startApi(env: Record<string, string> = {}): Promise<TestApi> {
  const config = loadConfig({
    NODE_ENV: "test",
    JWT_SECRET: "test-secret-that-is-long-enough-to-pass-validation",
    ...env,
  });

  const store = new MemoryStore();
  const server: Server = createApp({ config, store }).listen(0);
  await once(server, "listening");

  const { port } = server.address() as AddressInfo;
  const baseUrl = "http://127.0.0.1:" + port;

  async function request(
    method: string,
    path: string,
    options: RequestOptions = {},
  ): Promise<TestResponse> {
    const headers: Record<string, string> = { ...options.headers };
    if (options.body !== undefined) headers["Content-Type"] = "application/json";
    if (options.token) headers["Authorization"] = "Bearer " + options.token;

    const response = await fetch(baseUrl + path, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });

    const text = await response.text();
    let body: unknown = null;
    if (text) {
      try {
        body = JSON.parse(text);
      } catch {
        body = text;
      }
    }

    return { status: response.status, body, headers: response.headers };
  }

  return {
    baseUrl,
    store,
    request,
    get: (path, token) => request("GET", path, { token }),
    post: (path, body, token) => request("POST", path, { body, token }),
    put: (path, body, token) => request("PUT", path, { body, token }),
    async close() {
      server.close();
      await once(server, "close");
      await store.close();
    },
  };
}

// ---------------------------------------------------------------------------
// Client-side helpers: real crypto, so the tests prove the two halves fit
// ---------------------------------------------------------------------------

export interface TestUser {
  accountId: string;
  masterPassword: string;
  authKey: string;
  protectedVaultKey: string;
  vaultKey: CryptoKey;
}

let counter = 0;

/** Runs the genuine client-side registration flow and returns the payload a
 *  browser would POST to /api/auth/register. */
export async function makeUser(masterPassword = "correct horse battery staple"): Promise<TestUser> {
  const accountId = "user" + ++counter + "@example.com";
  const account = await createAccount(accountId, masterPassword, TEST_KDF);
  return {
    accountId,
    masterPassword,
    authKey: account.authKey,
    protectedVaultKey: serialize(account.keyRecord.protectedVaultKey),
    vaultKey: account.vaultKey,
  };
}

export function registrationBody(user: TestUser) {
  return {
    accountId: user.accountId,
    authKey: user.authKey,
    kdf: TEST_KDF,
    protectedVaultKey: user.protectedVaultKey,
  };
}

/** Registers a user and returns their access token alongside the user. */
export async function register(
  api: TestApi,
  user?: TestUser,
): Promise<{ user: TestUser; token: string }> {
  const subject = user ?? (await makeUser());
  const response = await api.post("/api/auth/register", registrationBody(subject));
  if (response.status !== 201) {
    throw new Error("register failed: " + response.status + " " + JSON.stringify(response.body));
  }
  return { user: subject, token: response.body.accessToken };
}

/** Produces a real sealed vault envelope, in the serialized wire format. */
export async function sealVault(
  user: TestUser,
  contents: VaultContents = sampleVault(),
): Promise<string> {
  return serialize(await encryptVault(user.vaultKey, contents, user.accountId));
}

export function sampleVault(password = "s3cr3t-value"): VaultContents {
  const now = "2026-01-13T00:00:00.000Z";
  return {
    ...emptyVault(),
    entries: [
      {
        id: "entry-1",
        name: "GitHub",
        username: "ada",
        password,
        url: "https://github.com",
        createdAt: now,
        updatedAt: now,
      },
    ],
  };
}
