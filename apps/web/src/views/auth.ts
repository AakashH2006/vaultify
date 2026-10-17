/**
 * The unlock and sign-up screen.
 *
 * Two things here are deliberate and worth not "fixing" later.
 *
 * The derivation is slow on purpose -- 600,000 PBKDF2 iterations is roughly
 * half a second of main-thread work -- so the button shows what the delay *is*
 * rather than a generic spinner. A user who thinks the app is sluggish will
 * ask for it to be made faster; a user who reads "deriving keys" understands
 * they are being protected and the complaint evaporates.
 *
 * Sign-up makes the no-recovery rule a blocking checkbox rather than a line of
 * fine print. There is genuinely no reset path, and finding that out after
 * losing the password is the worst possible moment.
 */

import { el, mount } from "../dom.ts";
import { estimateStrength } from "../strength.ts";
import { ApiError } from "../api.ts";

export interface AuthHandlers {
  unlock: (
    email: string,
    password: string,
    second?: { totpCode?: string; recoveryCode?: string },
  ) => Promise<void>;
  register: (email: string, password: string) => Promise<void>;
  restore: () => void;
}

type Mode = "unlock" | "register";

export function renderAuth(
  root: HTMLElement,
  handlers: AuthHandlers,
  options: { email?: string; notice?: string } = {},
): void {
  let mode: Mode = "unlock";
  let busy = false;

  const status = el("p", { class: "status", "aria-live": "polite" }, options.notice ?? "");
  if (options.notice) status.classList.add("status-notice");

  const email = el("input", {
    type: "email",
    id: "email",
    autocomplete: "username",
    placeholder: "you@example.com",
    required: true,
    value: options.email ?? "",
    spellcheck: false,
  });

  const password = el("input", {
    type: "password",
    id: "master-password",
    autocomplete: "current-password",
    placeholder: "Master password",
    required: true,
  });

  const confirm = el("input", {
    type: "password",
    id: "confirm-password",
    autocomplete: "new-password",
    placeholder: "Repeat it",
    required: true,
  });

  const acknowledge = el("input", { type: "checkbox", id: "acknowledge" });

  /**
   * The second-factor field, revealed only after the server says the password
   * was right. Showing it up front would tell anyone who typed an email
   * address whether that account has 2FA -- which is exactly the sort of
   * "who is worth attacking" signal the prelogin endpoint is careful not to
   * give away.
   */
  const totp = el("input", {
    type: "text",
    id: "totp-code",
    inputmode: "numeric",
    autocomplete: "one-time-code",
    maxlength: "7",
    placeholder: "123456",
    class: "code-input",
  });
  const totpField = el("label", { class: "field", for: "totp-code", hidden: true },
    el("span", {}, "Authenticator code"),
    totp,
  );

  const useRecovery = el("button", { type: "button", class: "link small", hidden: true },
    "Use a recovery code instead",
  );
  let recoveryMode = false;

  useRecovery.addEventListener("click", () => {
    recoveryMode = !recoveryMode;
    totp.value = "";
    totp.placeholder = recoveryMode ? "ABCDE-FGHJK" : "123456";
    totp.maxLength = recoveryMode ? 12 : 7;
    totp.inputMode = recoveryMode ? "text" : "numeric";
    (totpField.firstElementChild as HTMLElement).textContent = recoveryMode
      ? "Recovery code"
      : "Authenticator code";
    useRecovery.textContent = recoveryMode
      ? "Use my authenticator app instead"
      : "Use a recovery code instead";
    totp.focus();
  });

  /** True once the server has told us a second factor is outstanding. */
  let awaitingSecondFactor = false;

  const meter = el("div", { class: "meter", hidden: true },
    el("div", { class: "meter-track" }, el("div", { class: "meter-fill" })),
    el("span", { class: "meter-label" }),
  );
  const hints = el("ul", { class: "hints" });

  const confirmField = field("Confirm", confirm);
  const acknowledgeField = el("label", { class: "checkbox", hidden: true },
    acknowledge,
    el("span", {},
      "I understand that ",
      el("strong", {}, "there is no way to recover my vault"),
      " if I forget this password. No reset link, no support channel.",
    ),
  );

  const submit = el("button", { type: "submit", class: "primary" }, "Unlock");
  const toggle = el("button", { type: "button", class: "link" }, "Create an account");

  const restoreLink = el("button", { type: "button", class: "link subtle" },
    "Lost your password? Restore from a backup",
  );
  restoreLink.addEventListener("click", handlers.restore);

  const form = el("form", { class: "card auth", autocomplete: "on" },
    el("h1", {}, "Vaultify"),
    el("p", { class: "subtitle" },
      "Your master password never leaves this tab. Everything is encrypted here, before it is sent.",
    ),
    field("Email", email),
    field("Master password", password),
    meter,
    hints,
    confirmField,
    acknowledgeField,
    totpField,
    useRecovery,
    status,
    submit,
    el("p", { class: "switch" }, toggle),
    el("p", { class: "switch" }, restoreLink),
  );

  function setMode(next: Mode): void {
    mode = next;
    const registering = mode === "register";

    submit.textContent = registering ? "Create vault" : "Unlock";
    toggle.textContent = registering ? "I already have a vault" : "Create an account";
    confirmField.hidden = !registering;
    acknowledgeField.hidden = !registering;
    meter.hidden = !registering;
    hints.hidden = !registering;
    password.setAttribute("autocomplete", registering ? "new-password" : "current-password");
    confirm.required = registering;
    acknowledge.required = registering;

    // Switching mode abandons any pending second factor: the whole login is
    // being started over, and leaving a stale code field on screen would be
    // confusing at best.
    awaitingSecondFactor = false;
    recoveryMode = false;
    totp.value = "";
    totpField.hidden = true;
    useRecovery.hidden = true;
    restoreLink.hidden = registering;

    setStatus("");
    renderStrength();
  }

  function setStatus(message: string, kind: "error" | "notice" | "" = ""): void {
    status.textContent = message;
    status.className = "status" + (kind ? ` status-${kind}` : "");
  }

  function renderStrength(): void {
    if (mode !== "register") return;
    const strength = estimateStrength(password.value);
    const fill = meter.querySelector(".meter-fill") as HTMLElement;
    const label = meter.querySelector(".meter-label") as HTMLElement;

    fill.style.width = `${Math.min(100, (strength.bits / 110) * 100)}%`;
    fill.dataset.score = String(strength.score);
    label.textContent = password.value
      ? `${strength.label} — about ${strength.bits} bits`
      : "";

    mount(hints, ...strength.hints.map((hint) => el("li", {}, hint)));
  }

  password.addEventListener("input", renderStrength);

  toggle.addEventListener("click", () => setMode(mode === "unlock" ? "register" : "unlock"));

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (busy) return;

    const emailValue = email.value.trim();
    const passwordValue = password.value;

    if (!emailValue || !passwordValue) {
      setStatus("Email and master password are both required.", "error");
      return;
    }

    if (mode === "register") {
      if (passwordValue !== confirm.value) {
        setStatus("The two passwords do not match.", "error");
        return;
      }
      if (estimateStrength(passwordValue).score < 2) {
        setStatus(
          "That master password is too weak to protect a vault. Make it longer, or use several words.",
          "error",
        );
        return;
      }
      if (!acknowledge.checked) {
        setStatus("Please confirm you understand that the vault cannot be recovered.", "error");
        return;
      }
    }

    if (awaitingSecondFactor && !totp.value.trim()) {
      setStatus(
        recoveryMode ? "Enter one of your recovery codes." : "Enter the 6-digit code.",
        "error",
      );
      return;
    }

    void run(emailValue, passwordValue);
  });

  async function run(emailValue: string, passwordValue: string): Promise<void> {
    busy = true;
    submit.disabled = true;
    // Say what the wait is for. See the note at the top of the file.
    submit.textContent = "Deriving keys…";
    setStatus("600,000 PBKDF2 iterations. This takes a moment, by design.", "notice");

    try {
      if (mode === "register") {
        await handlers.register(emailValue, passwordValue);
      } else {
        const code = totp.value.trim();
        await handlers.unlock(
          emailValue,
          passwordValue,
          !code ? {} : recoveryMode ? { recoveryCode: code } : { totpCode: code },
        );
      }
      // On success the caller replaces this view; nothing to clean up.
    } catch (error) {
      const needsCode = error instanceof ApiError && error.code === "totp_required";
      const badCode = error instanceof ApiError && error.code === "totp_invalid";

      if (needsCode || badCode) {
        // The password was right. Keep it in the field: clearing it would
        // make the user retype a long passphrase and pay another 600,000
        // iterations for a mistake they did not make.
        awaitingSecondFactor = true;
        totpField.hidden = false;
        useRecovery.hidden = false;
        totp.value = "";
        setStatus(describe(error, mode), needsCode ? "notice" : "error");
        totp.focus();
        return;
      }

      setStatus(describe(error, mode), "error");
      password.value = "";
      confirm.value = "";
      totp.value = "";
      renderStrength();
      password.focus();
    } finally {
      busy = false;
      submit.disabled = false;
      submit.textContent = mode === "register" ? "Create vault" : "Unlock";
    }
  }

  setMode("unlock");
  // After setMode, which clears the status line on every mode switch. The
  // notice explains why the user is looking at this screen again -- "locked
  // after inactivity", "signed out everywhere" -- and losing it leaves them to
  // guess whether something went wrong.
  if (options.notice) setStatus(options.notice, "notice");

  mount(root, form);
  (options.email ? password : email).focus();
}

function field(label: string, input: HTMLElement): HTMLElement {
  return el("label", { class: "field", for: input.id }, el("span", {}, label), input);
}

function describe(error: unknown, mode: Mode): string {
  if (error instanceof ApiError) {
    if (error.code === "account_exists") {
      return "An account already exists for that email. Unlock it instead.";
    }
    return error.userMessage;
  }
  // A DecryptionError here means the auth key was accepted but the vault key
  // would not unwrap -- the server handed us a record that does not match this
  // password. Rare, and worth describing precisely rather than as "wrong password".
  if (error instanceof Error && error.name === "DecryptionError") {
    return mode === "unlock"
      ? "That master password cannot open this vault."
      : "Could not seal the new vault. Nothing was saved.";
  }
  return "Something went wrong. Nothing was sent that could have leaked your password.";
}
