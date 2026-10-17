/**
 * The recovery kit, shown once, immediately after registration.
 *
 * The architecture document is blunt that a forgotten master password means
 * the data is gone, and that this is the system working rather than failing.
 * This screen is the honest counterpart to that: the one thing we *can* offer
 * is a copy of the vault key that the user, and only the user, holds.
 *
 * It is important not to oversell it, so the wording here is careful about
 * what the kit does:
 *
 *   - It is **not** a password reset. It cannot sign you in; authenticating
 *     still needs the master password.
 *   - It decrypts a backup file you already have. Kit + backup = your data,
 *     with no server involved and no account needed.
 *   - Which means it is only useful if a backup exists, so the screen pushes
 *     the download rather than mentioning it in passing.
 *
 * Someone who finds the printout alone has an unusable 52-character string.
 * Someone who finds the printout *and* a backup file has the vault — which is
 * why the screen says to keep them apart.
 */

import { el } from "../dom.ts";
import type { VaultSession } from "../session.ts";
import { downloadText } from "./twofactor.ts";

export interface RecoveryKitHandlers {
  session: VaultSession;
  copy: (value: string, what: string) => void;
  /** Called once the user dismisses the screen. */
  onDone: () => void;
}

export function openRecoveryKit(handlers: RecoveryKitHandlers): HTMLDialogElement | null {
  const key = handlers.session.recoveryKey;
  if (!key) return null;

  const acknowledged = el("input", { type: "checkbox", id: "saved-kit" });
  const done = el("button", { type: "button", class: "primary", disabled: true }, "Done");
  const status = el("p", { class: "status", "aria-live": "polite" });

  acknowledged.addEventListener("change", () => {
    done.disabled = !acknowledged.checked;
  });

  const copyKey = el("button", { type: "button", class: "ghost small" }, "Copy key");
  copyKey.addEventListener("click", () => handlers.copy(key, "Recovery key"));

  const printKit = el("button", { type: "button", class: "ghost small" }, "Download kit");
  printKit.addEventListener("click", () => {
    downloadText(`vaultify-recovery-kit-${handlers.session.accountId}.txt`, kitText(handlers.session.accountId, key));
  });

  const backup = el("button", { type: "button", class: "primary" }, "Download encrypted backup");
  backup.addEventListener("click", () => {
    void (async () => {
      backup.disabled = true;
      try {
        const file = await handlers.session.exportBackup();
        downloadText(file.filename, file.contents);
        status.textContent = "Backup saved. Keep it somewhere other than the kit.";
        status.className = "status status-ok";
      } catch {
        status.textContent = "Could not build the backup.";
        status.className = "status status-error";
      } finally {
        backup.disabled = false;
      }
    })();
  });

  const dialog = el("dialog", { class: "sheet" },
    el("div", {},
      el("h2", {}, "Your recovery kit"),
      el("p", { class: "subtitle" },
        "There is no password reset for Vaultify, and no support channel that can " +
        "help — that is what makes the vault unreadable to us. This key is the one " +
        "thing we can give you instead, and it is shown only now.",
      ),

      el("pre", { class: "recovery-key" }, key),
      el("div", { class: "row gap" }, copyKey, printKit),

      el("h3", {}, "What it does"),
      el("ul", { class: "kit-notes" },
        el("li", {},
          el("strong", {}, "It decrypts a backup file. "),
          "Together, the key and a backup give you your passwords back with no " +
          "server involved — even if Vaultify no longer exists.",
        ),
        el("li", {},
          el("strong", {}, "It is not a way to sign in. "),
          "Signing in still needs your master password, so anyone who finds this " +
          "key on its own cannot reach your account.",
        ),
        el("li", {},
          el("strong", {}, "Keep the two apart. "),
          "The key and a backup file together are your vault. Separately, each is " +
          "useless.",
        ),
      ),

      el("h3", {}, "Take a backup now"),
      el("p", { class: "subtitle" },
        "The key opens a backup, so it is worth nothing without one. Your vault is " +
        "empty right now, but you can download a fresh backup from Settings at any " +
        "time — and should, whenever you add something you cannot afford to lose.",
      ),
      backup,
      status,

      el("label", { class: "checkbox", for: "saved-kit" },
        acknowledged,
        el("span", {},
          "I have saved this key somewhere safe and offline. I understand it will " +
          "not be shown again.",
        ),
      ),
      el("div", { class: "dialog-actions" }, el("span", { class: "spacer" }), done),
    ),
  ) as HTMLDialogElement;

  done.addEventListener("click", () => {
    handlers.session.forgetRecoveryKey();
    handlers.onDone();
    dialog.close();
  });

  // No cancel, and Escape is swallowed: this is the only time the key exists.
  dialog.addEventListener("cancel", (event) => event.preventDefault());
  dialog.addEventListener("close", () => dialog.remove());

  document.body.appendChild(dialog);
  dialog.showModal();
  return dialog;
}

function kitText(accountId: string, key: string): string {
  return [
    "VAULTIFY RECOVERY KIT",
    "=====================",
    "",
    `Account:  ${accountId}`,
    `Created:  ${new Date().toISOString()}`,
    "",
    "Recovery key:",
    "",
    `    ${key}`,
    "",
    "WHAT THIS IS",
    "------------",
    "This is your vault key. It decrypts a Vaultify backup file without any",
    "server, any account, and without your master password.",
    "",
    "WHAT IT IS NOT",
    "--------------",
    "It is not a password reset. You cannot sign in with it. Signing in needs",
    "your master password, which is not written here and is not recoverable.",
    "",
    "HOW TO USE IT",
    "-------------",
    "1. Find your encrypted backup file (vaultify-backup-YYYY-MM-DD.json).",
    "2. Open Vaultify and choose 'Restore from a backup'.",
    "3. Supply this key and the backup file.",
    "",
    "The restore runs entirely in your browser and needs no account.",
    "",
    "KEEP THIS SEPARATE FROM YOUR BACKUP FILE.",
    "Together they are your vault. Apart, each one is useless.",
    "",
  ].join("\n");
}
