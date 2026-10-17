/**
 * The add/edit entry form, shown as a modal dialog.
 *
 * Uses a native `<dialog>`: focus trapping, Escape-to-close and the backdrop
 * come from the platform instead of from several hundred lines of our own
 * focus-management code that would then live inside the trust boundary.
 *
 * The generator is embedded rather than linked. A user who has to leave the
 * form to get a strong password will type one from memory instead, and the
 * whole point of a password manager is that they never have to.
 */

import type { VaultEntry } from "@vaultify/crypto";
import { el, mount } from "../dom.ts";
import { renderGenerator } from "./generator.ts";

export type EntryDraft = Omit<VaultEntry, "id" | "createdAt" | "updatedAt">;

export interface EntryFormHandlers {
  save: (draft: EntryDraft) => void | Promise<void>;
  remove?: () => void | Promise<void>;
}

export function openEntryForm(
  existing: VaultEntry | null,
  handlers: EntryFormHandlers,
): HTMLDialogElement {
  const name = input("name", "text", existing?.name ?? "", "GitHub");
  const username = input("username", "text", existing?.username ?? "", "ada@example.com");
  const password = input("password", "password", existing?.password ?? "", "");
  const url = input("url", "url", existing?.url ?? "", "https://github.com");
  const notes = el("textarea", {
    id: "notes",
    rows: "3",
    placeholder: "Recovery codes, security answers, anything else.",
  });
  notes.value = existing?.notes ?? "";

  password.setAttribute("autocomplete", "new-password");
  username.setAttribute("autocomplete", "off");
  name.setAttribute("autocomplete", "off");

  const reveal = el("button", { type: "button", class: "ghost small" }, "Show");
  reveal.addEventListener("click", () => {
    const hidden = password.type === "password";
    password.type = hidden ? "text" : "password";
    reveal.textContent = hidden ? "Hide" : "Show";
  });

  const generatorWrap = el("div", { class: "generator-slot", hidden: true });
  const generatorToggle = el("button", { type: "button", class: "ghost small" }, "Generate");
  generatorToggle.addEventListener("click", () => {
    const showing = generatorWrap.hidden;
    generatorWrap.hidden = !showing;
    generatorToggle.textContent = showing ? "Close generator" : "Generate";
    if (showing && generatorWrap.childElementCount === 0) {
      mount(generatorWrap,
        renderGenerator({
          onUse: (value) => {
            password.value = value;
            password.type = "text";
            reveal.textContent = "Hide";
            generatorWrap.hidden = true;
            generatorToggle.textContent = "Generate";
          },
        }),
      );
    }
  });

  const status = el("p", { class: "status", "aria-live": "polite" });

  const dialog = el("dialog", { class: "sheet" },
    el("form", { class: "entry-form" },
      el("h2", {}, existing ? "Edit entry" : "New entry"),

      labelled("Name", name),
      labelled("Username", username),

      el("div", { class: "field" },
        el("span", {}, "Password"),
        el("div", { class: "row gap" }, password, reveal, generatorToggle),
        generatorWrap,
      ),

      labelled("Website", url),
      labelled("Notes", notes),
      status,

      el("div", { class: "dialog-actions" },
        existing && handlers.remove
          ? deleteButton(() => void handlers.remove?.(), () => dialog.close())
          : null,
        el("span", { class: "spacer" }),
        button("Cancel", "ghost", () => dialog.close()),
        button(existing ? "Save changes" : "Add entry", "primary", submit),
      ),
    ),
  ) as HTMLDialogElement;

  async function submit(): Promise<void> {
    if (!name.value.trim()) {
      status.textContent = "Give the entry a name so you can find it again.";
      status.className = "status status-error";
      name.focus();
      return;
    }
    if (!password.value) {
      status.textContent = "An entry with no password is probably a mistake.";
      status.className = "status status-error";
      password.focus();
      return;
    }

    await handlers.save({
      name: name.value.trim(),
      username: username.value.trim(),
      password: password.value,
      url: url.value.trim() || undefined,
      notes: notes.value.trim() || undefined,
      totpSecret: existing?.totpSecret,
    });
    dialog.close();
  }

  // Enter submits, as in any form, but a textarea needs its newlines.
  dialog.addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey && event.target !== notes) {
      event.preventDefault();
      void submit();
    }
  });

  // The DOM node holds plaintext while it is open. Drop it on close rather
  // than leaving a detached subtree full of passwords for the GC to get to
  // whenever it feels like it.
  dialog.addEventListener("close", () => {
    password.value = "";
    notes.value = "";
    dialog.remove();
  });

  document.body.appendChild(dialog);
  dialog.showModal();
  name.focus();
  return dialog;
}

function input(id: string, type: string, value: string, placeholder: string): HTMLInputElement {
  const node = el("input", { id, type, placeholder, spellcheck: false });
  node.value = value;
  return node;
}

function labelled(label: string, control: HTMLElement): HTMLElement {
  return el("label", { class: "field", for: control.id }, el("span", {}, label), control);
}

function button(label: string, kind: string, onClick: () => void): HTMLButtonElement {
  const node = el("button", { type: "button", class: kind }, label);
  node.addEventListener("click", onClick);
  return node;
}

/**
 * Delete needs a second click, not a `confirm()` dialog -- the CSP forbids
 * nothing here, but a modal inside a modal is awkward and a native confirm
 * blocks the event loop. Two clicks, with the button changing to say what the
 * second one does, is clearer and unambiguous.
 */
function deleteButton(remove: () => void, close: () => void): HTMLButtonElement {
  let armed = false;
  const node = el("button", { type: "button", class: "danger" }, "Delete");
  node.addEventListener("click", () => {
    if (!armed) {
      armed = true;
      node.textContent = "Delete — click again";
      setTimeout(() => {
        armed = false;
        node.textContent = "Delete";
      }, 4000);
      return;
    }
    remove();
    close();
  });
  return node;
}
