/**
 * The audit log, and the privacy decisions baked into it.
 *
 * "Show me logins I do not recognise" is a genuinely useful control, and it
 * is also the one feature in Vaultify that asks the server to remember
 * something about a user. For a product whose entire pitch is that the server
 * knows nothing, that deserves an explicit answer rather than a default.
 *
 * The answer taken here is to record the smallest thing that still answers
 * the user's question:
 *
 *   - **The IP is truncated before storage** -- /24 for IPv4, /48 for IPv6.
 *     That distinguishes "my usual connection" from "somewhere else entirely",
 *     which is the question being asked, while refusing to build a precise
 *     movement history of a person who came here specifically to not be
 *     profiled.
 *   - **The user agent is reduced to a coarse label** such as "Firefox on
 *     macOS". A raw UA string is a high-entropy fingerprint; "Firefox on
 *     macOS" tells the user what they need to recognise their own laptop.
 *   - **Rows expire after 90 days** (`pruneAuditEvents`).
 *
 * Writes are best-effort: a failure to log must never fail the login it is
 * describing. Losing an audit row is bad; locking a user out of their vault
 * because the audit table is full is worse.
 */

import type { Request } from "express";
import type { NewAuditEvent, Store } from "../store/types.ts";

export type AuditEventName =
  | "register"
  | "login"
  | "login.totp_failed"
  | "login.locked_out"
  | "logout"
  | "password_changed"
  | "totp_enabled"
  | "totp_disabled"
  | "recovery_code_used";

/**
 * Drop the host-identifying part of an address.
 *
 * IPv4 keeps three octets (`203.0.113.0/24`), IPv6 the first three hextets
 * (`2001:db8:1234::/48`) -- which is the prefix a residential customer is
 * typically delegated, so it identifies the connection without identifying
 * the device on it.
 */
export function truncateIp(ip: string | undefined): string | null {
  if (!ip) return null;

  // Express hands back "::ffff:203.0.113.5" for IPv4 over a v6 socket.
  const unmapped = ip.startsWith("::ffff:") ? ip.slice(7) : ip;

  if (unmapped.includes(".") && !unmapped.includes(":")) {
    const octets = unmapped.split(".");
    if (octets.length !== 4) return null;
    return `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
  }

  if (unmapped.includes(":")) {
    const hextets = expandIpv6(unmapped);
    if (!hextets) return null;
    return `${hextets.slice(0, 3).join(":")}::/48`;
  }

  return null;
}

/**
 * Expand an IPv6 address to its eight hextets.
 *
 * The `::` shorthand has to be expanded rather than split naively: in `::1`
 * the `1` is the *last* hextet, not the third, so taking the first three
 * fields of a plain split records `0:0:1::/48` for what is really
 * `0:0:0::/48`. Leading zeros are dropped, matching how the address is
 * normally written.
 */
function expandIpv6(address: string): string[] | null {
  const halves = address.split("::");
  if (halves.length > 2) return null;

  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];

  if (halves.length === 1) {
    return head.length === 8 ? head.map(normaliseHextet) : null;
  }

  const gap = 8 - head.length - tail.length;
  if (gap < 1) return null;

  return [...head, ...Array<string>(gap).fill("0"), ...tail].map(normaliseHextet);
}

function normaliseHextet(part: string): string {
  const value = Number.parseInt(part || "0", 16);
  return Number.isNaN(value) ? "0" : value.toString(16);
}

const BROWSERS: Array<[RegExp, string]> = [
  // Order matters: Edge and Opera both claim to be Chrome, and Chrome claims
  // to be Safari. Most specific first.
  [/\bEdg(?:e|A|iOS)?\//, "Edge"],
  [/\bOPR\/|\bOpera\//, "Opera"],
  [/\bFirefox\/|\bFxiOS\//, "Firefox"],
  [/\bChrome\/|\bCriOS\//, "Chrome"],
  [/\bSafari\//, "Safari"],
];

const PLATFORMS: Array<[RegExp, string]> = [
  [/\bAndroid\b/, "Android"],
  [/\b(?:iPhone|iPad|iPod)\b/, "iOS"],
  [/\bWindows\b/, "Windows"],
  [/\bMac OS X\b|\bMacintosh\b/, "macOS"],
  [/\bCrOS\b/, "ChromeOS"],
  [/\bLinux\b/, "Linux"],
];

/**
 * "Firefox on macOS", or null when the agent is unrecognised.
 *
 * Deliberately lossy. Returning the raw string would hand the database a
 * stable per-device fingerprint, which is precisely the kind of record this
 * project exists to avoid keeping.
 */
export function describeClient(userAgent: string | undefined): string | null {
  if (!userAgent) return null;

  const browser = BROWSERS.find(([pattern]) => pattern.test(userAgent))?.[1];
  const platform = PLATFORMS.find(([pattern]) => pattern.test(userAgent))?.[1];

  if (browser && platform) return `${browser} on ${platform}`;
  return browser ?? platform ?? null;
}

/** Everything the log keeps about a request, derived at the edge. */
export function requestContext(req: Request): Pick<NewAuditEvent, "ipPrefix" | "client"> {
  return {
    ipPrefix: truncateIp(req.ip),
    client: describeClient(req.get("user-agent")),
  };
}

/**
 * Append an event, swallowing any failure.
 *
 * Call it without awaiting where the request does not depend on it. The
 * promise is still handled so an unhandled rejection cannot take the process
 * down.
 */
export function audit(
  store: Store,
  req: Request,
  accountId: string,
  event: AuditEventName,
  succeeded: boolean,
): void {
  void store
    .appendAuditEvent({ accountId, event, succeeded, ...requestContext(req) })
    .catch(() => {
      // Intentionally silent. An audit write that fails must not fail, or
      // delay, the operation it is describing.
    });
}
