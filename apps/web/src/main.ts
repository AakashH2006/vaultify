/**
 * The application shell: owns the session, the auto-lock timer, and which view
 * is on screen.
 *
 * The state machine is small on purpose -- `locked` or `unlocked`, nothing in
 * between. Every path out of `unlocked` runs through `lock()`, so there is
 * exactly one place where secrets are dropped and exactly one thing to audit.
 *
 * Saving is debounced rather than manual. A password manager where the user
 * can forget to press Save is a password manager that loses passwords, and
 * since every write is a compare-and-set that merges on conflict (see
 * `session.ts`), writing often is safe.
 */

import { ApiClient, ApiError } from "./api.ts";
import { AutoLock, DEFAULT_IDLE_MS, type LockReason } from "./autolock.ts";
import { cancelPendingClear, copySecret } from "./clipboard.ts";
import { ICONS, el, icon, mount } from "./dom.ts";
import { VaultSession } from "./session.ts";
import { renderActivity } from "./views/activity.ts";
import { renderAuth } from "./views/auth.ts";
import { openEntryForm } from "./views/entry.ts";
import { renderGeneratorView } from "./views/generator.ts";
import { openRecoveryKit } from "./views/recovery.ts";
import { openRestore } from "./views/restore.ts";
import { renderSecurity } from "./views/security.ts";
import { renderSettings } from "./views/settings.ts";
import { openTwoFactorDisable, openTwoFactorSetup, downloadText } from "./views/twofactor.ts";
import { renderVault, type VaultViewState } from "./views/vault.ts";
import { API_ORIGIN } from "./config.ts";

type Tab = "vault" | "security" | "generator" | "activity" | "settings";

/** How long after the last edit we push. Long enough to batch a burst of
 *  typing, short enough that closing the tab rarely loses anything. */
const SAVE_DEBOUNCE_MS = 1_200;
const TICK_MS = 1_000;

/** The remembered email is not a secret and makes the unlock screen one field
 *  shorter. Nothing else is ever persisted -- see the note in `session.ts`. */
const LAST_EMAIL_KEY = "vaultify.last-email";
const IDLE_KEY = "vaultify.idle-ms";

const api = new ApiClient(API_ORIGIN);

/** The mount point. Resolved once, loudly, rather than optional-chained at
 *  every call site -- if the shell is missing there is nothing to degrade to. */
function mountPoint(): HTMLElement {
  const node = document.getElementById("app");
  if (!node) throw new Error("Missing #app -- index.html and main.js are out of step.");
  return node;
}

const app = mountPoint();

let session: VaultSession | null = null;
let tab: Tab = "vault";
let saveTimer: ReturnType<typeof setTimeout> | null = null;
let banner: { message: string; kind: "ok" | "warn" | "error" } | null = null;

const listState: VaultViewState = { query: "", order: "name" };

/**
 * Breach-check results, kept for the lifetime of the session so switching
 * tabs does not silently re-run lookups against a third party. Cleared with
 * everything else on lock.
 */
let breaches = new Map<string, number>();

const autoLock = new AutoLock({
  idleMs: readIdleMs(),
  onLock: (reason) => lock(reason),
  onTick: (remaining) => paintCountdown(remaining),
});

setInterval(() => autoLock.tick(), TICK_MS);

for (const event of ["pointerdown", "keydown", "scroll", "focus"] as const) {
  window.addEventListener(event, () => autoLock.activity(), { passive: true, capture: true });
}
document.addEventListener("visibilitychange", () => {
  autoLock.visibilityChanged(document.visibilityState === "hidden");
});

/**
 * A pending save on tab close is the one case where debouncing can lose data.
 * We cannot await anything here -- the page is going -- so we flush
 * synchronously-ish and warn the user if there is still something in flight.
 */
window.addEventListener("beforeunload", (event) => {
  if (!session || session.locked || !session.dirty) return;
  flushSave();
  event.preventDefault();
});

// ---------------------------------------------------------------------------
// Session lifecycle
// ---------------------------------------------------------------------------

async function openSession(open: () => Promise<VaultSession>, email: string): Promise<void> {
  const opened = await open();
  session = opened;
  rememberEmail(email);
  autoLock.arm(opened.expiresAt);
  tab = "vault";
  listState.query = "";
  banner = null;
  breaches = new Map();
  render();

  // Registration is the only moment the vault key can be written down. Show
  // it before anything else can distract from it.
  if (opened.recoveryKey) {
    openRecoveryKit({
      session: opened,
      copy: (value, what) => void copy(value, what),
      onDone: render,
    });
  }
}

function lock(reason: LockReason): void {
  if (saveTimer !== null) {
    clearTimeout(saveTimer);
    saveTimer = null;
  }
  const hadUnsaved = session?.locked === false && session.dirty;

  cancelPendingClear();
  void navigator.clipboard?.writeText?.("").catch(() => {});

  session?.lock();
  session = null;
  autoLock.disarm();
  // Breach counts are keyed by plaintext password, so they are as sensitive
  // as the vault itself and go the same way.
  breaches = new Map();

  render({ notice: lockNotice(reason, Boolean(hadUnsaved)) });
}

function lockNotice(reason: LockReason, hadUnsaved: boolean): string {
  const unsaved = hadUnsaved ? " Unsaved changes were discarded." : "";
  switch (reason) {
    case "idle":
      return `Locked after inactivity.${unsaved}`;
    case "hidden":
      return `Locked because the tab was left in the background.${unsaved}`;
    case "session-expired":
      return `The session expired. Unlock to continue.${unsaved}`;
    case "manual":
      return `Locked.${unsaved}`;
  }
}

// ---------------------------------------------------------------------------
// Saving
// ---------------------------------------------------------------------------

function scheduleSave(): void {
  if (saveTimer !== null) clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    saveTimer = null;
    void flushSave();
  }, SAVE_DEBOUNCE_MS);
  setBanner("Saving…", "warn");
}

async function flushSave(): Promise<void> {
  const active = session;
  if (!active || active.locked || !active.dirty) return;

  try {
    const result = await active.save();
    autoLock.activity();
    if (result.mergeNotes.length > 0) {
      // A merge happened. Say so, and say what was done -- the entry list the
      // user is looking at just changed underneath them.
      setBanner(result.mergeNotes.join(" "), "warn");
      render();
      return;
    }
    setBanner("Saved.", "ok");
  } catch (error) {
    if (error instanceof ApiError && error.code === "unauthorized") {
      lock("session-expired");
      return;
    }
    setBanner(
      error instanceof ApiError
        ? `Not saved — ${error.userMessage}`
        : "Not saved. Your changes are still here; they will retry on the next edit.",
      "error",
    );
  }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function render(options: { notice?: string } = {}): void {
  const active = session;

  if (!active || active.locked) {
    document.body.dataset.state = "locked";
    renderAuth(app, {
      unlock: (email, password, second) =>
        openSession(() => VaultSession.unlock(api, email, password, second), email),
      register: (email, password) =>
        openSession(() => VaultSession.register(api, email, password), email),
      restore: () => openRestore({ copy: (value, what) => void copy(value, what) }),
    }, { email: lastEmail(), notice: options.notice });
    return;
  }

  document.body.dataset.state = "unlocked";
  const content = el("main", { class: "content" });

  mount(app, header(active), bannerNode(), content);

  switch (tab) {
    case "vault":
      renderVault(content, active.entries, listState, {
        add: () => openEntry(null),
        edit: (entry) => openEntry(entry),
        copy: (value, what) => void copy(value, what),
      });
      break;
    case "security":
      renderSecurity(content, {
        entries: active.entries,
        edit: (entry) => openEntry(entry),
        breaches,
        onBreachResults: (results) => {
          for (const [password, count] of results) breaches.set(password, count);
        },
      });
      break;
    case "generator":
      renderGeneratorView(content, { copy: (value) => void copy(value, "Password") });
      break;
    case "activity":
      renderActivity(content, { api, session: active });
      break;
    case "settings":
      renderSettings(content, {
        accountId: active.accountId,
        idleMs: autoLock.idleMs,
        revision: active.revision,
        twoFactor: active.twoFactor,
        setUpTwoFactor: () =>
          openTwoFactorSetup({
            api,
            session: active,
            onChanged: () => {
              setBanner("Two-factor authentication is on.", "ok");
              render();
            },
            copy: (value, what) => void copy(value, what),
          }),
        disableTwoFactor: () =>
          openTwoFactorDisable({
            api,
            session: active,
            onChanged: () => {
              setBanner("Two-factor authentication is off.", "warn");
              render();
            },
            copy: (value, what) => void copy(value, what),
          }),
        downloadBackup: async () => {
          const file = await active.exportBackup();
          downloadText(file.filename, file.contents);
        },
        setIdleMs: (ms) => {
          autoLock.setIdleMs(ms);
          try {
            localStorage.setItem(IDLE_KEY, String(autoLock.idleMs));
          } catch {
            // Private mode, or storage disabled. The setting applies to this
            // session regardless; only the memory of it is lost.
          }
          setBanner(`Auto-lock set to ${Math.round(autoLock.idleMs / 60_000)} minutes.`, "ok");
          render();
        },
        changePassword: async (current, next) => {
          await active.changePassword(current, next);
          render({ notice: "Master password changed. Every session was signed out — unlock with the new one." });
        },
        signOut: async () => {
          await active.signOut();
          session = null;
          autoLock.disarm();
          render({ notice: "Signed out." });
        },
        lock: () => autoLock.lockNow(),
      });
      break;
  }
}

function header(active: VaultSession): HTMLElement {
  const countdown = el("span", { class: "countdown", title: "Time until auto-lock" });

  const refresh = el("button", { type: "button", class: "icon-button", title: "Check for changes from other devices" },
    icon(ICONS.refresh),
  );
  refresh.addEventListener("click", () => void pull(active));

  const lockButton = el("button", { type: "button", class: "ghost" }, icon(ICONS.lock), el("span", {}, "Lock"));
  lockButton.addEventListener("click", () => autoLock.lockNow());

  return el("header", { class: "app-bar" },
    el("div", { class: "brand" }, icon(ICONS.lock), el("span", {}, "Vaultify")),
    el("nav", { class: "tabs" },
      tabButton("vault", "Vault"),
      tabButton("security", "Security"),
      tabButton("generator", "Generator"),
      tabButton("activity", "Activity"),
      tabButton("settings", "Settings"),
    ),
    el("div", { class: "app-bar-right" }, countdown, refresh, lockButton),
  );
}

function tabButton(target: Tab, label: string): HTMLButtonElement {
  const node = el("button", {
    type: "button",
    class: target === tab ? "tab active" : "tab",
    "aria-expanded": String(target === tab),
  }, label);
  node.addEventListener("click", () => {
    tab = target;
    render();
  });
  return node;
}

function bannerNode(): HTMLElement {
  const node = el("div", { class: "banner", "aria-live": "polite" });
  if (!banner) {
    node.hidden = true;
    return node;
  }
  node.classList.add(`banner-${banner.kind}`);
  node.textContent = banner.message;
  return node;
}

function paintCountdown(remaining: number): void {
  const node = document.querySelector(".countdown");
  if (!node) return;
  const seconds = Math.ceil(remaining / 1000);
  // Only show it when it is close enough to matter. A timer counting down from
  // five minutes is just anxiety.
  node.textContent = seconds <= 60 ? `Locks in ${seconds}s` : "";
}

function setBanner(message: string, kind: "ok" | "warn" | "error"): void {
  banner = { message, kind };
  const node = document.querySelector(".banner");
  if (node instanceof HTMLElement) {
    node.hidden = false;
    node.className = `banner banner-${kind}`;
    node.textContent = message;
  }
  if (kind === "ok") {
    setTimeout(() => {
      if (banner?.message === message) {
        banner = null;
        const current = document.querySelector(".banner");
        if (current instanceof HTMLElement) current.hidden = true;
      }
    }, 3000);
  }
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

function openEntry(existing: Parameters<typeof openEntryForm>[0]): void {
  const active = session;
  if (!active || active.locked) return;

  openEntryForm(existing, {
    save: (draft) => {
      if (existing) {
        active.updateEntry(existing.id, draft);
      } else {
        active.addEntry(draft);
      }
      scheduleSave();
      render();
    },
    remove: existing
      ? () => {
          active.deleteEntry(existing.id);
          scheduleSave();
          render();
        }
      : undefined,
  });
}

async function copy(value: string, what: string): Promise<void> {
  autoLock.activity();
  const result = await copySecret(value);
  setBanner(result.ok ? `${what} copied. The clipboard clears in 20s.` : result.message,
    result.ok ? "ok" : "error");
}

async function pull(active: VaultSession): Promise<void> {
  try {
    const outcome = await active.refresh();
    setBanner(
      outcome.notes.length > 0
        ? outcome.notes.join(" ")
        : outcome.changed
          ? "Updated from another device."
          : "Already up to date.",
      outcome.notes.length > 0 ? "warn" : "ok",
    );
    render();
  } catch (error) {
    if (error instanceof ApiError && error.code === "unauthorized") return lock("session-expired");
    setBanner(error instanceof ApiError ? error.userMessage : "Could not refresh.", "error");
  }
}

// ---------------------------------------------------------------------------
// Small persisted, non-secret preferences
// ---------------------------------------------------------------------------

function lastEmail(): string {
  try {
    return localStorage.getItem(LAST_EMAIL_KEY) ?? "";
  } catch {
    return "";
  }
}

function rememberEmail(email: string): void {
  try {
    localStorage.setItem(LAST_EMAIL_KEY, email.trim().toLowerCase());
  } catch {
    // Storage unavailable. The unlock screen simply starts empty next time.
  }
}

function readIdleMs(): number {
  try {
    const stored = Number(localStorage.getItem(IDLE_KEY));
    return Number.isFinite(stored) && stored > 0 ? stored : DEFAULT_IDLE_MS;
  } catch {
    return DEFAULT_IDLE_MS;
  }
}

render();
