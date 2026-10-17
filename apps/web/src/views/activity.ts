/**
 * Account activity -- the audit log, read back.
 *
 * This exists to answer one question: "is anyone else getting into my
 * account?" So failed sign-ins are given more visual weight than successful
 * ones, and the view says plainly what the server does and does not keep.
 * A log the user cannot interpret is worse than no log, because it looks like
 * oversight without providing any.
 */

import { type ActivityEvent, ApiError, type ApiClient } from "../api.ts";
import { el, mount } from "../dom.ts";
import type { VaultSession } from "../session.ts";

const LABELS: Record<string, string> = {
  register: "Account created",
  login: "Signed in",
  "login.totp_failed": "Two-factor code rejected",
  "login.locked_out": "Blocked — account temporarily locked",
  logout: "Signed out",
  password_changed: "Master password changed",
  totp_enabled: "Two-factor turned on",
  totp_disabled: "Two-factor turned off",
  recovery_code_used: "Recovery code used",
};

export function renderActivity(
  root: HTMLElement,
  handlers: { api: ApiClient; session: VaultSession },
): void {
  const list = el("div", { class: "activity" });

  mount(root,
    el("div", { class: "card" },
      el("h2", {}, "Account activity"),
      el("p", { class: "subtitle" },
        "Sign-ins and credential changes on this account. If something here was not " +
        "you, change your master password — it signs every other device out.",
      ),
      list,
      el("p", { class: "subtitle" },
        "Addresses are truncated before they are stored (the last part is discarded) " +
        "and the browser is recorded as a coarse label rather than a full user-agent " +
        "string. This is the only history the server keeps about you, it is kept for " +
        "90 days, and it says nothing about what is in your vault.",
      ),
    ),
  );

  mount(list, el("p", { class: "status status-notice" }, "Loading…"));

  void (async () => {
    try {
      const { events } = await handlers.api.activity(handlers.session.accessToken);
      mount(list, events.length === 0
        ? el("p", { class: "subtitle" }, "Nothing recorded yet.")
        : el("ul", { class: "activity-list" }, ...events.map(renderEvent)));
    } catch (error) {
      mount(list, el("p", { class: "status status-error" },
        error instanceof ApiError ? error.userMessage : "Could not load activity.",
      ));
    }
  })();
}

function renderEvent(event: ActivityEvent): HTMLElement {
  const where = [event.client, event.ipPrefix].filter(Boolean).join(" · ");

  return el("li", { class: event.succeeded ? "activity-row" : "activity-row failed" },
    el("div", { class: "activity-main" },
      el("div", { class: "activity-label" }, LABELS[event.event] ?? event.event),
      el("div", { class: "activity-where" }, where || "Unknown device"),
    ),
    el("time", { class: "activity-when", title: event.createdAt }, relative(event.createdAt)),
  );
}

/** "3 minutes ago". Absolute time stays available in the title attribute,
 *  because "yesterday" is useless when you are trying to place an event. */
function relative(timestamp: string): string {
  const then = Date.parse(timestamp);
  if (Number.isNaN(then)) return timestamp;

  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 60) return "just now";

  const units: Array<[seconds: number, name: Intl.RelativeTimeFormatUnit]> = [
    [60, "minute"],
    [3600, "hour"],
    [86_400, "day"],
    [604_800, "week"],
    [2_629_800, "month"],
    [31_557_600, "year"],
  ];

  let chosen: [number, Intl.RelativeTimeFormatUnit] = units[0];
  for (const unit of units) {
    if (seconds >= unit[0]) chosen = unit;
  }

  const formatter = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });
  return formatter.format(-Math.round(seconds / chosen[0]), chosen[1]);
}
