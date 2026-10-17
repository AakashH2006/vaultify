/**
 * Two-factor enrolment.
 *
 * Three screens in sequence, and the order is the whole design:
 *
 *   1. **Scan** -- the QR code, with the secret in text underneath for anyone
 *      enrolling on the same device they are reading this on.
 *   2. **Confirm** -- type a code. Nothing is switched on until this passes.
 *      Enabling on the strength of "the user saw a QR code" is how people
 *      lock themselves out of their own vault.
 *   3. **Recovery codes** -- shown exactly once, with a deliberate obstacle
 *      before the user can leave. The server holds only hashes, so this
 *      screen is the single opportunity to keep them.
 *
 * The obstacle on step 3 is a checkbox, not a timer. A timer trains people to
 * wait and then click; a checkbox that says what they are confirming at least
 * puts the claim in front of them.
 */

import { formatSecret } from "@vaultify/totp";

import { ApiError, type ApiClient } from "../api.ts";
import { el, mount } from "../dom.ts";
import { encodeQr, qrToSvg } from "../qr.ts";
import type { VaultSession } from "../session.ts";

export interface TwoFactorHandlers {
  api: ApiClient;
  session: VaultSession;
  /** Re-render the settings view once the status changes. */
  onChanged: () => void;
  copy: (value: string, what: string) => void;
}

export function openTwoFactorSetup(handlers: TwoFactorHandlers): HTMLDialogElement {
  const body = el("div", { class: "twofactor" });
  const dialog = el("dialog", { class: "sheet" }, body) as HTMLDialogElement;

  document.body.appendChild(dialog);
  dialog.addEventListener("close", () => dialog.remove());
  dialog.showModal();

  void showScan();
  return dialog;

  // -------------------------------------------------------------------------

  async function showScan(): Promise<void> {
    mount(body, el("h2", {}, "Set up two-factor authentication"), loading());

    let setup: { secret: string; uri: string };
    try {
      setup = await handlers.api.startTwoFactor(handlers.session.accessToken);
    } catch (error) {
      return showError(error);
    }

    const code = encodeQr(setup.uri);
    const secretText = el("code", { class: "secret-text" }, formatSecret(setup.secret));

    const copySecret = el("button", { type: "button", class: "ghost small" }, "Copy secret");
    copySecret.addEventListener("click", () => handlers.copy(setup.secret, "Secret"));

    const next = el("button", { type: "button", class: "primary" }, "I have scanned it");
    next.addEventListener("click", () => showConfirm());

    mount(body,
      el("h2", {}, "Set up two-factor authentication"),
      el("p", { class: "subtitle" },
        "Scan this with an authenticator app. It protects your account from someone " +
        "who has learned your master password — it does not change how your vault is " +
        "encrypted.",
      ),
      el("div", { class: "qr" }, qrToSvg(code)),
      el("details", { class: "manual" },
        el("summary", {}, "Can’t scan it?"),
        el("p", { class: "subtitle" }, "Enter this key into your app by hand:"),
        el("div", { class: "row gap" }, secretText, copySecret),
      ),
      el("div", { class: "dialog-actions" },
        el("span", { class: "spacer" }),
        cancel("Cancel"),
        next,
      ),
    );
  }

  function showConfirm(): void {
    const input = el("input", {
      type: "text",
      inputmode: "numeric",
      autocomplete: "one-time-code",
      maxlength: "7",
      placeholder: "123456",
      class: "code-input",
      "aria-label": "6-digit code",
    });
    const status = el("p", { class: "status", "aria-live": "polite" });
    const submit = el("button", { type: "button", class: "primary" }, "Turn on");

    async function confirm(): Promise<void> {
      if (input.value.replace(/\D/g, "").length !== 6) {
        status.textContent = "Enter the 6-digit code your app is showing.";
        status.className = "status status-error";
        return;
      }

      submit.disabled = true;
      status.textContent = "Checking…";
      status.className = "status status-notice";

      try {
        const result = await handlers.api.enableTwoFactor(
          handlers.session.accessToken,
          input.value,
        );
        await handlers.session.refreshTwoFactor();
        showRecoveryCodes(result.recoveryCodes);
      } catch (error) {
        status.textContent =
          error instanceof ApiError ? error.userMessage : "Could not turn on two-factor.";
        status.className = "status status-error";
        submit.disabled = false;
        input.select();
      }
    }

    submit.addEventListener("click", () => void confirm());
    input.addEventListener("keydown", (event) => {
      if (event.key === "Enter") void confirm();
    });

    mount(body,
      el("h2", {}, "Confirm the code"),
      el("p", { class: "subtitle" },
        "Type the 6-digit code your authenticator is showing. Nothing is switched on " +
        "until this matches, so a code that never reached your phone cannot lock you out.",
      ),
      el("label", { class: "field" }, el("span", {}, "Code"), input),
      status,
      el("div", { class: "dialog-actions" },
        el("span", { class: "spacer" }),
        back("Back", () => void showScan()),
        submit,
      ),
    );

    input.focus();
  }

  function showRecoveryCodes(codes: string[]): void {
    const acknowledged = el("input", { type: "checkbox", id: "saved-codes" });
    const done = el("button", { type: "button", class: "primary", disabled: true }, "Done");

    acknowledged.addEventListener("change", () => {
      done.disabled = !acknowledged.checked;
    });

    done.addEventListener("click", () => {
      handlers.onChanged();
      dialog.close();
    });

    const copyAll = el("button", { type: "button", class: "ghost small" }, "Copy all");
    copyAll.addEventListener("click", () => handlers.copy(codes.join("\n"), "Recovery codes"));

    const download = el("button", { type: "button", class: "ghost small" }, "Download");
    download.addEventListener("click", () => {
      downloadText(
        "vaultify-recovery-codes.txt",
        [
          "Vaultify recovery codes",
          `Account: ${handlers.session.accountId}`,
          `Issued:  ${new Date().toISOString()}`,
          "",
          "Each code works once, and replaces your authenticator app -- not your",
          "master password. You will still need the master password to sign in.",
          "",
          ...codes,
          "",
        ].join("\n"),
      );
    });

    mount(body,
      el("h2", {}, "Save your recovery codes"),
      el("p", { class: "subtitle" },
        "Two-factor is now on. These codes are the way back in if you lose your phone. " +
        "They are shown once — the server keeps only hashes of them.",
      ),
      el("ol", { class: "recovery-codes" }, ...codes.map((code) => el("li", {}, code))),
      el("div", { class: "row gap" }, copyAll, download),
      el("p", { class: "subtitle" },
        "Each works once. A recovery code replaces your authenticator, not your master " +
        "password — someone who finds them still cannot open your vault.",
      ),
      el("label", { class: "checkbox", for: "saved-codes" },
        acknowledged,
        el("span", {}, "I have saved these somewhere I can reach without my phone."),
      ),
      el("div", { class: "dialog-actions" }, el("span", { class: "spacer" }), done),
    );
  }

  function showError(error: unknown): void {
    mount(body,
      el("h2", {}, "Set up two-factor authentication"),
      el("p", { class: "status status-error" },
        error instanceof ApiError ? error.userMessage : "Could not start setup.",
      ),
      el("div", { class: "dialog-actions" }, el("span", { class: "spacer" }), cancel("Close")),
    );
  }

  function cancel(label: string): HTMLButtonElement {
    const node = el("button", { type: "button", class: "ghost" }, label);
    node.addEventListener("click", () => dialog.close());
    return node;
  }

  function back(label: string, onClick: () => void): HTMLButtonElement {
    const node = el("button", { type: "button", class: "ghost" }, label);
    node.addEventListener("click", onClick);
    return node;
  }

  function loading(): HTMLElement {
    return el("p", { class: "status status-notice" }, "Generating a secret…");
  }
}

/**
 * Turning 2FA off: master password plus a current code.
 *
 * Removing a second factor is the first thing an attacker with a borrowed
 * session would do, so a live session alone is not enough -- the server
 * requires both, and this form collects both.
 */
export function openTwoFactorDisable(handlers: TwoFactorHandlers): HTMLDialogElement {
  const password = el("input", { type: "password", autocomplete: "current-password" });
  const code = el("input", {
    type: "text",
    inputmode: "numeric",
    maxlength: "7",
    placeholder: "123456",
    autocomplete: "one-time-code",
  });
  const status = el("p", { class: "status", "aria-live": "polite" });
  const submit = el("button", { type: "button", class: "danger" }, "Turn off two-factor");

  const dialog = el("dialog", { class: "sheet" },
    el("div", {},
      el("h2", {}, "Turn off two-factor authentication"),
      el("p", { class: "subtitle" },
        "This needs your master password as well as a current code. A borrowed session " +
        "must not be enough to strip a second factor.",
      ),
      el("label", { class: "field" }, el("span", {}, "Master password"), password),
      el("label", { class: "field" }, el("span", {}, "Current code"), code),
      status,
      el("div", { class: "dialog-actions" },
        el("span", { class: "spacer" }),
        closeButton(),
        submit,
      ),
    ),
  ) as HTMLDialogElement;

  function closeButton(): HTMLButtonElement {
    const node = el("button", { type: "button", class: "ghost" }, "Cancel");
    node.addEventListener("click", () => dialog.close());
    return node;
  }

  submit.addEventListener("click", () => void run());

  async function run(): Promise<void> {
    if (!password.value || code.value.replace(/\D/g, "").length !== 6) {
      status.textContent = "Both the master password and a current code are required.";
      status.className = "status status-error";
      return;
    }

    submit.disabled = true;
    status.textContent = "Deriving your key…";
    status.className = "status status-notice";

    try {
      const authKey = await handlers.session.deriveAuthKey(password.value);
      await handlers.api.disableTwoFactor(handlers.session.accessToken, authKey, code.value);
      await handlers.session.refreshTwoFactor();
      handlers.onChanged();
      dialog.close();
    } catch (error) {
      status.textContent =
        error instanceof ApiError ? error.userMessage : "Could not turn two-factor off.";
      status.className = "status status-error";
      submit.disabled = false;
    } finally {
      password.value = "";
    }
  }

  dialog.addEventListener("close", () => {
    password.value = "";
    dialog.remove();
  });

  document.body.appendChild(dialog);
  dialog.showModal();
  password.focus();
  return dialog;
}

/** Hand the browser a file without a server round trip. */
export function downloadText(filename: string, contents: string): void {
  // A blob URL keeps the content off the URL bar and out of history, which
  // matters when the content is recovery codes or a vault key.
  const url = URL.createObjectURL(new Blob([contents], { type: "text/plain;charset=utf-8" }));
  const link = el("a", { href: url, class: "hidden-download" });
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  // Revoked on the next turn of the event loop: Safari needs the URL to still
  // resolve when the click is processed.
  setTimeout(() => URL.revokeObjectURL(url), 0);
}
