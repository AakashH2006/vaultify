/**
 * The password generator panel.
 *
 * All of the hard work is in `@vaultify/crypto/generator` -- rejection sampling
 * so the character distribution is actually uniform. This file is the dial.
 *
 * The one piece of judgement here is showing entropy in bits next to the
 * password. "Strong" is a word; 131 bits is a number the user can compare
 * against the 60-ish bits a human-chosen password usually carries, and it makes
 * the length slider feel like it is buying something.
 */

import { CHARSETS, MAX_LENGTH, MIN_LENGTH, entropyBits, generatePassword } from "@vaultify/crypto";
import { el, mount } from "../dom.ts";

export interface GeneratorOptions {
  /** Called with each freshly generated password. */
  onUse?: (password: string) => void;
  onCopy?: (password: string) => void;
  initialLength?: number;
}

type Toggle = keyof typeof CHARSETS | "excludeAmbiguous";

export function renderGenerator(options: GeneratorOptions = {}): HTMLElement {
  const config = {
    length: options.initialLength ?? 20,
    lowercase: true,
    uppercase: true,
    digits: true,
    symbols: true,
    excludeAmbiguous: false,
  };

  const output = el("output", { class: "generated", for: "length" });
  const entropy = el("span", { class: "entropy" });

  const length = el("input", {
    type: "range",
    id: "length",
    min: String(MIN_LENGTH),
    max: String(MAX_LENGTH),
    step: "1",
    value: String(config.length),
  });
  const lengthLabel = el("span", { class: "length-value" }, String(config.length));

  const toggles: Array<[Toggle, string]> = [
    ["lowercase", "a-z"],
    ["uppercase", "A-Z"],
    ["digits", "0-9"],
    ["symbols", "!@#"],
    ["excludeAmbiguous", "No look-alikes"],
  ];

  const warning = el("p", { class: "status", "aria-live": "polite" });

  function regenerate(): void {
    try {
      const password = generatePassword(config);
      output.textContent = password;
      output.dataset.value = password;
      entropy.textContent = `${Math.round(entropyBits(config))} bits of entropy`;
      warning.textContent = "";
      warning.className = "status";
    } catch (error) {
      // The only reachable case: every character class switched off.
      output.textContent = "";
      delete output.dataset.value;
      entropy.textContent = "";
      warning.textContent =
        error instanceof Error ? error.message : "Choose at least one character set.";
      warning.className = "status status-error";
    }
  }

  const controls = el("div", { class: "toggles" },
    ...toggles.map(([key, label]) => {
      const input = el("input", { type: "checkbox", checked: config[key] });
      input.addEventListener("change", () => {
        config[key] = input.checked;
        regenerate();
      });
      return el("label", { class: "chip" }, input, el("span", {}, label));
    }),
  );

  length.addEventListener("input", () => {
    config.length = Number(length.value);
    lengthLabel.textContent = String(config.length);
    regenerate();
  });

  const reroll = el("button", { type: "button", class: "ghost", title: "Generate another" }, "Regenerate");
  reroll.addEventListener("click", regenerate);

  const actions = el("div", { class: "row gap" }, reroll);

  if (options.onCopy) {
    const copy = el("button", { type: "button", class: "ghost" }, "Copy");
    copy.addEventListener("click", () => {
      const value = output.dataset.value;
      if (value) options.onCopy?.(value);
    });
    actions.appendChild(copy);
  }

  if (options.onUse) {
    const use = el("button", { type: "button", class: "primary" }, "Use this");
    use.addEventListener("click", () => {
      const value = output.dataset.value;
      if (value) options.onUse?.(value);
    });
    actions.appendChild(use);
  }

  const panel = el("section", { class: "generator" },
    el("div", { class: "generated-row" }, output),
    entropy,
    el("label", { class: "field slider", for: "length" },
      el("span", {}, "Length ", lengthLabel),
      length,
    ),
    controls,
    warning,
    actions,
  );

  regenerate();
  return panel;
}

/** Standalone generator view, for the "Generate" tab. */
export function renderGeneratorView(
  root: HTMLElement,
  handlers: { copy: (value: string) => void },
): void {
  mount(root,
    el("div", { class: "card" },
      el("h2", {}, "Generator"),
      el("p", { class: "subtitle" },
        "Unbiased: characters are drawn by rejection sampling, not modulo, so every " +
        "position is uniform over the alphabet you picked.",
      ),
      renderGenerator({ onCopy: handlers.copy }),
    ),
  );
}
