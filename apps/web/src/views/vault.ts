/**
 * The dashboard: the list of entries, the search box, and the per-row actions.
 *
 * A password is never rendered into the DOM until the user asks for it. The
 * row holds the ciphertext-derived plaintext in the session object, not in an
 * attribute, and reveal is per-row and resets on every re-render. This is not
 * paranoia about the DOM itself -- it is about screenshots, screen-sharing and
 * shoulder-surfing, which are the realistic ways a password leaks off a screen
 * that is already unlocked.
 */

import type { VaultEntry } from "@vaultify/crypto";
import { ICONS, el, icon, mount } from "../dom.ts";
import { filterEntries, hostOf, initials, safeHref, sortEntries, type SortOrder } from "../search.ts";

export interface VaultViewHandlers {
  add: () => void;
  edit: (entry: VaultEntry) => void;
  copy: (value: string, what: string) => void;
}

export interface VaultViewState {
  query: string;
  order: SortOrder;
}

export function renderVault(
  root: HTMLElement,
  entries: readonly VaultEntry[],
  state: VaultViewState,
  handlers: VaultViewHandlers,
): void {
  const search = el("input", {
    type: "search",
    id: "search",
    class: "search",
    placeholder: "Search by name, username, site or notes",
    "aria-label": "Search entries",
    spellcheck: false,
  });
  search.value = state.query;

  const sort = el("select", { class: "sort", "aria-label": "Sort entries" },
    option("name", "Name", state.order),
    option("recent", "Recently updated", state.order),
    option("created", "Recently added", state.order),
  );

  const list = el("ul", { class: "entries" });

  const addButton = el("button", { type: "button", class: "primary" },
    icon(ICONS.plus),
    el("span", {}, "New entry"),
  );
  addButton.addEventListener("click", handlers.add);

  function paint(): void {
    const visible = sortEntries(filterEntries(entries, state.query), state.order);

    if (entries.length === 0) {
      mount(list, emptyState(
        "This vault is empty.",
        "Add your first entry — the password is encrypted in this tab before it is stored.",
      ));
      return;
    }
    if (visible.length === 0) {
      mount(list, emptyState("No matches.", `Nothing in this vault matches “${state.query}”.`));
      return;
    }

    mount(list, ...visible.map((entry) => renderRow(entry, handlers)));
  }

  search.addEventListener("input", () => {
    state.query = search.value;
    paint();
  });
  sort.addEventListener("change", () => {
    state.order = sort.value as SortOrder;
    paint();
  });

  mount(root,
    el("div", { class: "toolbar" },
      el("div", { class: "search-wrap" }, icon(ICONS.search), search),
      sort,
      addButton,
    ),
    el("p", { class: "count" },
      entries.length === 1 ? "1 entry" : `${entries.length} entries`,
    ),
    list,
  );

  paint();
}

function renderRow(entry: VaultEntry, handlers: VaultViewHandlers): HTMLElement {
  const host = hostOf(entry.url);
  const href = safeHref(entry.url);

  const secret = el("code", { class: "secret" }, "••••••••••••");
  let revealed = false;

  const reveal = el("button", {
    type: "button",
    class: "icon-button",
    title: "Reveal password",
    "aria-label": `Reveal password for ${entry.name}`,
  }, icon(ICONS.eye));

  reveal.addEventListener("click", () => {
    revealed = !revealed;
    secret.textContent = revealed ? entry.password : "••••••••••••";
    secret.classList.toggle("revealed", revealed);
    reveal.title = revealed ? "Hide password" : "Reveal password";
  });

  const copyPassword = el("button", {
    type: "button",
    class: "icon-button",
    title: "Copy password",
    "aria-label": `Copy password for ${entry.name}`,
  }, icon(ICONS.copy));
  copyPassword.addEventListener("click", () => handlers.copy(entry.password, "Password"));

  const open = el("button", {
    type: "button",
    class: "icon-button",
    title: "Edit",
    "aria-label": `Edit ${entry.name}`,
  }, icon(ICONS.gear));
  open.addEventListener("click", () => handlers.edit(entry));

  const subtitle: Array<Node | string> = [];
  if (entry.username) {
    const username = el("button", { type: "button", class: "link subtle", title: "Copy username" },
      entry.username,
    );
    username.addEventListener("click", () => handlers.copy(entry.username, "Username"));
    subtitle.push(username);
  }
  if (host) {
    if (subtitle.length) subtitle.push(el("span", { class: "dot" }, "·"));
    subtitle.push(
      href
        ? el("a", { class: "link subtle", href, target: "_blank", rel: "noreferrer noopener" }, host)
        : el("span", { class: "subtle" }, host),
    );
  }

  return el("li", { class: "entry", "data-id": entry.id },
    el("div", { class: "avatar", "aria-hidden": "true" }, initials(entry.name)),
    el("div", { class: "entry-main" },
      el("div", { class: "entry-name" }, entry.name),
      el("div", { class: "entry-sub" }, ...subtitle),
    ),
    el("div", { class: "entry-secret" }, secret),
    el("div", { class: "entry-actions" }, reveal, copyPassword, open),
  );
}

function emptyState(title: string, detail: string): HTMLElement {
  return el("li", { class: "empty" },
    icon(ICONS.lock),
    el("p", { class: "empty-title" }, title),
    el("p", { class: "subtitle" }, detail),
  );
}

function option(value: SortOrder, label: string, selected: SortOrder): HTMLOptionElement {
  const node = el("option", { value }, label);
  if (value === selected) node.selected = true;
  return node;
}
