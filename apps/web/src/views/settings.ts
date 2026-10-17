/**
 * Settings: auto-lock timeout, master-password change, sign out.
 *
 * The password change here deliberately re-states what it costs. Rotating the
 * master password revokes every session on every device, including this one --
 * that is the point of it, since the usual reason to rotate is suspicion that
 * a session is in the wrong hands. A user who is surprised by being signed out
 * mid-task will assume the app broke.
 */

import { el, mount } from "../dom.ts";
import { MAX_IDLE_MS, MIN_IDLE_MS } from "../autolock.ts";
import { estimateStrength } from "../strength.ts";
import { ApiError } from "../api.ts";

export interface SettingsHandlers {
  accountId: string;
  idleMs: number;
  revision: number;
  twoFactor: { enabled: boolean; recoveryCodesRemaining: number };
  setIdleMs: (ms: number) => void;
  changePassword: (current: string, next: string) => Promise<void>;
  signOut: () => Promise<void>;
  lock: () => void;
  setUpTwoFactor: () => void;
  disableTwoFactor: () => void;
  downloadBackup: () => Promise<void>;
}

const IDLE_CHOICES = [1, 5, 15, 30, 60];

export function renderSettings(root: HTMLElement, handlers: SettingsHandlers): void {
  mount(root,
    el("div", { class: "card" },
      el("h2", {}, "Account"),
      definition("Signed in as", handlers.accountId),
      definition("Vault revision", String(handlers.revision)),
      el("p", { class: "subtitle" },
        "The revision increments on every successful sync. It is how this tab detects " +
        "that another device wrote first.",
      ),
    ),
    twoFactorCard(handlers),
    backupCard(handlers),
    autoLockCard(handlers),
    passwordCard(handlers),
    el("div", { class: "card" },
      el("h2", {}, "Session"),
      el("div", { class: "row gap" },
        action("Lock now", "ghost", () => handlers.lock()),
        action("Sign out", "danger", () => void handlers.signOut()),
      ),
      el("p", { class: "subtitle" },
        "Locking drops the keys from this tab. Signing out also revokes the session " +
        "on the server, so the access token stops working immediately rather than " +
        "when it expires.",
      ),
    ),
  );
}

function twoFactorCard(handlers: SettingsHandlers): HTMLElement {
  const { enabled, recoveryCodesRemaining } = handlers.twoFactor;

  const action = el("button", { type: "button", class: enabled ? "danger" : "primary" },
    enabled ? "Turn off" : "Turn on two-factor",
  );
  action.addEventListener("click", enabled ? handlers.disableTwoFactor : handlers.setUpTwoFactor);

  const low = enabled && recoveryCodesRemaining <= 3;

  return el("div", { class: "card" },
    el("h2", {}, "Two-factor authentication"),
    el("p", { class: "subtitle" },
      enabled
        ? "On. Signing in needs a code from your authenticator as well as your master password."
        : "Off. Anyone who learns your master password can download your encrypted vault — " +
          "they still could not read it, but a second factor stops them getting that far.",
    ),
    enabled
      ? el("p", { class: low ? "subtitle warn" : "subtitle" },
          `${recoveryCodesRemaining} recovery code${recoveryCodesRemaining === 1 ? "" : "s"} left.` +
          (low ? " Turn two-factor off and on again to issue a fresh set." : ""),
        )
      : null,
    el("p", { class: "subtitle" },
      "This protects access to your account. It does not change how your vault is " +
      "encrypted — that still rests entirely on your master password.",
    ),
    action,
  );
}

function backupCard(handlers: SettingsHandlers): HTMLElement {
  const status = el("p", { class: "status", "aria-live": "polite" });
  const download = el("button", { type: "button", class: "primary" }, "Download encrypted backup");

  download.addEventListener("click", () => {
    void (async () => {
      download.disabled = true;
      try {
        await handlers.downloadBackup();
        status.textContent = "Saved. Keep it apart from your recovery key.";
        status.className = "status status-ok";
      } catch {
        status.textContent = "Could not build the backup.";
        status.className = "status status-error";
      } finally {
        download.disabled = false;
      }
    })();
  });

  return el("div", { class: "card" },
    el("h2", {}, "Backup"),
    el("p", { class: "subtitle" },
      "The same ciphertext the server holds, as a file. With your recovery key it " +
      "can be opened on any machine, with no account and no network — which is what " +
      "makes the key worth keeping.",
    ),
    el("p", { class: "subtitle" },
      "The file is encrypted, so it is safe to store in ordinary cloud storage. Just " +
      "not in the same place as the recovery key.",
    ),
    download,
    status,
  );
}

function autoLockCard(handlers: SettingsHandlers): HTMLElement {
  const select = el("select", { "aria-label": "Auto-lock after" },
    ...IDLE_CHOICES.map((minutes) => {
      const node = el("option", { value: String(minutes) }, `${minutes} minute${minutes === 1 ? "" : "s"}`);
      if (minutes * 60_000 === handlers.idleMs) node.selected = true;
      return node;
    }),
  );
  select.addEventListener("change", () => {
    handlers.setIdleMs(Number(select.value) * 60_000);
  });

  return el("div", { class: "card" },
    el("h2", {}, "Auto-lock"),
    el("label", { class: "field" }, el("span", {}, "Lock after inactivity"), select),
    el("p", { class: "subtitle" },
      `Between ${MIN_IDLE_MS / 1000} seconds and ${MAX_IDLE_MS / 60_000} minutes. The tab also ` +
      "locks a minute after it is hidden, and the moment the session token expires. " +
      "Locking drops the vault key — nothing short of your master password reopens it.",
    ),
  );
}

function passwordCard(handlers: SettingsHandlers): HTMLElement {
  const current = el("input", { type: "password", id: "current-password", autocomplete: "current-password" });
  const next = el("input", { type: "password", id: "next-password", autocomplete: "new-password" });
  const confirm = el("input", { type: "password", id: "confirm-new-password", autocomplete: "new-password" });
  const status = el("p", { class: "status", "aria-live": "polite" });
  const submit = el("button", { type: "button", class: "primary" }, "Change master password");

  submit.addEventListener("click", () => {
    if (!current.value || !next.value) {
      return fail("Both the current and the new password are required.");
    }
    if (next.value !== confirm.value) {
      return fail("The two new passwords do not match.");
    }
    if (next.value === current.value) {
      return fail("The new password is the same as the current one.");
    }
    if (estimateStrength(next.value).score < 2) {
      return fail("That new password is too weak to protect a vault.");
    }
    void run();
  });

  function fail(message: string): void {
    status.textContent = message;
    status.className = "status status-error";
  }

  async function run(): Promise<void> {
    submit.disabled = true;
    status.textContent = "Re-wrapping the vault key… (two key derivations, so this is slow)";
    status.className = "status status-notice";
    try {
      await handlers.changePassword(current.value, next.value);
      // On success every session dies, including this one; the app shell
      // sends us back to the unlock screen. Nothing to render here.
    } catch (error) {
      fail(error instanceof ApiError ? error.userMessage : "Could not change the password.");
      submit.disabled = false;
    } finally {
      current.value = "";
      next.value = "";
      confirm.value = "";
    }
  }

  return el("div", { class: "card" },
    el("h2", {}, "Master password"),
    el("p", { class: "subtitle" },
      "Your entries are not re-encrypted. Only the 32-byte vault key is re-wrapped and " +
      "uploaded, so this is fast regardless of how large the vault is.",
    ),
    labelled("Current password", current),
    labelled("New password", next),
    labelled("Repeat new password", confirm),
    status,
    submit,
    el("p", { class: "subtitle warn" },
      "This signs you out everywhere, including here. Save any open edits first.",
    ),
  );
}

function labelled(label: string, control: HTMLElement): HTMLElement {
  return el("label", { class: "field", for: control.id }, el("span", {}, label), control);
}

function definition(term: string, value: string): HTMLElement {
  return el("div", { class: "definition" }, el("span", { class: "term" }, term), el("span", {}, value));
}

function action(label: string, kind: string, onClick: () => void): HTMLButtonElement {
  const node = el("button", { type: "button", class: kind }, label);
  node.addEventListener("click", onClick);
  return node;
}
