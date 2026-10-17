/**
 * A small element builder, in place of a framework.
 *
 * The reason is not minimalism for its own sake. The threat model names a
 * compromised client bundle as the one attack that breaks zero-knowledge
 * entirely, and the practical defence is that the bundle is small enough to
 * read. A framework would be an order of magnitude more code inside the trust
 * boundary, delivered by a supply chain this project does not control.
 *
 * The second reason is this module's hard rule: **there is no innerHTML here,
 * and no path to it.** Every string a caller passes becomes a text node. A
 * vault entry named `<img onerror=...>` is a string with angle brackets in it,
 * not markup -- which matters, because entry names come from whatever the user
 * saved, and the tab rendering them holds the decryption key.
 */

type Child = Node | string | null | undefined | false;

export interface Attrs {
  class?: string;
  id?: string;
  type?: string;
  name?: string;
  value?: string;
  placeholder?: string;
  title?: string;
  href?: string;
  rel?: string;
  target?: string;
  for?: string;
  role?: string;
  disabled?: boolean;
  checked?: boolean;
  required?: boolean;
  readonly?: boolean;
  hidden?: boolean;
  min?: string;
  max?: string;
  step?: string;
  maxlength?: string;
  autocomplete?: string;
  autofocus?: boolean;
  inputmode?: string;
  spellcheck?: boolean;
  rows?: string;
  "aria-label"?: string;
  "aria-live"?: string;
  "aria-hidden"?: string;
  "aria-expanded"?: string;
  "data-id"?: string;
  [key: `on${string}`]: unknown;
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);

  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;

    if (key.startsWith("on") && typeof value === "function") {
      node.addEventListener(key.slice(2), value as EventListener);
      continue;
    }
    if (value === true) {
      node.setAttribute(key, "");
      continue;
    }
    node.setAttribute(key, String(value));
  }

  append(node, children);
  return node;
}

export function append(parent: Node, children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    // A string becomes a text node. Always. This is the whole XSS story.
    parent.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
  }
}

export function clear(node: Node): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function mount(parent: Node, ...children: Child[]): void {
  clear(parent);
  append(parent, children);
}

/** `<svg>` needs a namespace, and icons are the one place we accept a path
 *  string -- which is ours, never user data. */
export function icon(path: string, label?: string): SVGSVGElement {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("fill", "none");
  svg.setAttribute("stroke", "currentColor");
  svg.setAttribute("stroke-width", "1.8");
  svg.setAttribute("stroke-linecap", "round");
  svg.setAttribute("stroke-linejoin", "round");
  svg.setAttribute("aria-hidden", label ? "false" : "true");
  svg.classList.add("icon");
  if (label) svg.setAttribute("aria-label", label);

  const node = document.createElementNS("http://www.w3.org/2000/svg", "path");
  node.setAttribute("d", path);
  svg.appendChild(node);
  return svg;
}

export const ICONS = {
  lock: "M7 11V7a5 5 0 0 1 10 0v4M5 11h14v10H5z",
  plus: "M12 5v14M5 12h14",
  copy: "M9 9h10v12H9zM5 15V3h10v2",
  search: "M11 19a8 8 0 1 1 0-16 8 8 0 0 1 0 16zm10 2-4.3-4.3",
  dice: "M4 7l8-4 8 4v10l-8 4-8-4zM8 11h.01M12 13h.01M16 11h.01",
  refresh: "M20 11a8 8 0 1 0-2 6m2-6v-5m0 5h-5",
  trash: "M4 7h16M9 7V5h6v2m-8 0 1 13h8l1-13",
  eye: "M2 12s4-7 10-7 10 7 10 7-4 7-10 7-10-7-10-7zm10 3a3 3 0 1 0 0-6 3 3 0 0 0 0 6z",
  gear: "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6zM19 12a7 7 0 0 0-.1-1.2l2-1.6-2-3.4-2.4 1a7 7 0 0 0-2-1.2L14 3h-4l-.4 2.6a7 7 0 0 0-2 1.2l-2.4-1-2 3.4 2 1.6a7 7 0 0 0 0 2.4l-2 1.6 2 3.4 2.4-1a7 7 0 0 0 2 1.2L10 21h4l.4-2.6a7 7 0 0 0 2-1.2l2.4 1 2-3.4-2-1.6c.07-.4.1-.8.1-1.2z",
} as const;
