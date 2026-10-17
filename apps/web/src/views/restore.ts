/**
 * Restore from a recovery kit and a backup file.
 *
 * This screen is reachable from the locked page, without an account and
 * without a network, which is the entire point of it. If Vaultify's servers
 * are gone, or the account is unreachable because the master password is
 * lost, the user still has a file and a printout, and those are enough.
 *
 * It is read-only on purpose. Restoring *into* an account would need a master
 * password and a live session, at which point the normal flow applies. What
 * someone in this situation needs is to see their passwords and move them
 * somewhere else, so the screen shows them and offers a plaintext export with
 * a warning attached.
 */

import {
  RecoveryKeyError,
  DecryptionError,
  decryptVault,
  deserialize,
  parseBackup,
  vaultKeyFromRecoveryKey,
  type VaultContents,
} from "@vaultify/crypto";

import { el, mount } from "../dom.ts";
import { hostOf } from "../search.ts";
import { downloadText } from "./twofactor.ts";

export function openRestore(options: { copy: (value: string, what: string) => void }): HTMLDialogElement {
  const body = el("div", { class: "restore" });
  const dialog = el("dialog", { class: "sheet wide" }, body) as HTMLDialogElement;

  dialog.addEventListener("close", () => dialog.remove());
  document.body.appendChild(dialog);
  dialog.showModal();

  showForm();
  return dialog;

  // -------------------------------------------------------------------------

  function showForm(): void {
    const file = el("input", { type: "file", id: "backup-file" });
    file.accept = ".json,application/json";

    const key = el("textarea", {
      id: "recovery-key",
      rows: "2",
      placeholder: "ABCDE-FGHJK-MNPQR-…",
      spellcheck: false,
      class: "key-input",
    });

    const status = el("p", { class: "status", "aria-live": "polite" });
    const submit = el("button", { type: "button", class: "primary" }, "Open backup");

    submit.addEventListener("click", () => void run());

    async function run(): Promise<void> {
      const chosen = file.files?.[0];
      if (!chosen) return fail("Choose your backup file.");
      if (!key.value.trim()) return fail("Paste or type your recovery key.");

      submit.disabled = true;
      status.textContent = "Decrypting…";
      status.className = "status status-notice";

      try {
        const backup = parseBackup(await chosen.text());
        const vaultKey = await vaultKeyFromRecoveryKey(key.value);
        const contents = await decryptVault(
          vaultKey,
          deserialize(backup.vault),
          backup.accountId,
        );
        showEntries(contents, backup.accountId, backup.exportedAt);
      } catch (error) {
        // The three failure modes are genuinely different here, and someone
        // recovering under stress deserves to be told which one they hit
        // rather than a single "something went wrong".
        if (error instanceof RecoveryKeyError) return fail(error.message);
        if (error instanceof DecryptionError) {
          return fail(
            "That key does not open this backup. Check for a mistyped character — " +
              "the key has no letter I, L, O or U.",
          );
        }
        return fail("Could not read that file.");
      }
    }

    function fail(message: string): void {
      status.textContent = message;
      status.className = "status status-error";
      submit.disabled = false;
    }

    mount(body,
      el("h2", {}, "Restore from a backup"),
      el("p", { class: "subtitle" },
        "Your recovery key and a backup file are enough to read your passwords — " +
        "no account, no master password, and nothing sent anywhere. This runs " +
        "entirely in this tab.",
      ),
      el("label", { class: "field", for: "backup-file" },
        el("span", {}, "Backup file"),
        file,
      ),
      el("label", { class: "field", for: "recovery-key" },
        el("span", {}, "Recovery key"),
        key,
      ),
      status,
      el("div", { class: "dialog-actions" },
        el("span", { class: "spacer" }),
        close("Cancel"),
        submit,
      ),
    );
  }

  function showEntries(contents: VaultContents, accountId: string, exportedAt: string): void {
    const rows = contents.entries.map((entry) => {
      const secret = el("code", { class: "secret" }, "••••••••••••");
      let revealed = false;

      const reveal = el("button", { type: "button", class: "ghost small" }, "Show");
      reveal.addEventListener("click", () => {
        revealed = !revealed;
        secret.textContent = revealed ? entry.password : "••••••••••••";
        secret.classList.toggle("revealed", revealed);
        reveal.textContent = revealed ? "Hide" : "Show";
      });

      const copy = el("button", { type: "button", class: "ghost small" }, "Copy");
      copy.addEventListener("click", () => options.copy(entry.password, "Password"));

      const host = hostOf(entry.url);

      return el("li", { class: "entry" },
        el("div", { class: "entry-main" },
          el("div", { class: "entry-name" }, entry.name),
          el("div", { class: "entry-sub" },
            [entry.username, host].filter(Boolean).join(" · ") || "—",
          ),
        ),
        el("div", { class: "entry-secret" }, secret),
        el("div", { class: "entry-actions" }, reveal, copy),
      );
    });

    const exportPlain = el("button", { type: "button", class: "danger" }, "Export as plain text");
    let armed = false;
    exportPlain.addEventListener("click", () => {
      if (!armed) {
        armed = true;
        exportPlain.textContent = "This file is unencrypted — click again";
        setTimeout(() => {
          armed = false;
          exportPlain.textContent = "Export as plain text";
        }, 5000);
        return;
      }
      downloadText(`vaultify-plaintext-${accountId}.json`, JSON.stringify(contents, null, 2));
      armed = false;
      exportPlain.textContent = "Export as plain text";
    });

    mount(body,
      el("h2", {}, "Recovered"),
      el("p", { class: "subtitle" },
        `${contents.entries.length} ${contents.entries.length === 1 ? "entry" : "entries"} ` +
        `from ${accountId}` +
        (exportedAt ? `, backed up ${exportedAt.slice(0, 10)}.` : "."),
      ),
      el("ul", { class: "entries" }, ...rows),
      el("p", { class: "subtitle warn" },
        "A plain-text export is readable by anything on this machine, and by anything " +
        "it is later copied to. Prefer importing it straight into a password manager.",
      ),
      el("div", { class: "dialog-actions" },
        exportPlain,
        el("span", { class: "spacer" }),
        close("Done"),
      ),
    );
  }

  function close(label: string): HTMLButtonElement {
    const node = el("button", { type: "button", class: "ghost" }, label);
    node.addEventListener("click", () => dialog.close());
    return node;
  }
}
