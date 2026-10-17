/**
 * The security check: reused, weak, stale and breached passwords.
 *
 * Everything except the breach column is computed locally from the decrypted
 * vault and runs the moment the view opens. The breach check is the one thing
 * in Vaultify that contacts a third party, so it sits behind an explicit
 * button with the exact mechanism spelled out next to it -- not a toggle in
 * settings, not a background task, and never on by default.
 *
 * The wording of that explanation is load-bearing. "We check your passwords
 * against known breaches" would be true and would also leave a careful user
 * assuming the worst. Saying "the first five characters of a SHA-1 hash, which
 * matches about 800 passwords" lets them judge it for themselves.
 */

import type { VaultEntry } from "@vaultify/crypto";

import { checkPasswords } from "../breach.ts";
import { ICONS, el, icon, mount } from "../dom.ts";
import { buildHealthReport, summarise, type Finding, type HealthReport } from "../health.ts";

export interface SecurityHandlers {
  entries: readonly VaultEntry[];
  edit: (entry: VaultEntry) => void;
  /** Breach results survive a re-render so a check is not repeated for free. */
  breaches: Map<string, number>;
  onBreachResults: (results: Map<string, number>) => void;
}

const LABELS: Record<Finding["kind"], string> = {
  breached: "Found in a breach",
  reused: "Reused",
  weak: "Weak",
  stale: "Over a year old",
};

export function renderSecurity(root: HTMLElement, handlers: SecurityHandlers): void {
  const results = el("div", { class: "findings" });
  const breachPanel = el("div", { class: "card" });

  function paint(): void {
    const report = buildHealthReport(handlers.entries, { breaches: handlers.breaches });
    mount(results, ...renderReport(report, handlers));
    mount(breachPanel, ...renderBreachPanel(report));
  }

  function renderBreachPanel(report: HealthReport): Array<Node | string> {
    const status = el("p", { class: "status", "aria-live": "polite" });
    const run = el("button", { type: "button", class: "primary" },
      report.breachChecked ? "Check again" : "Check against known breaches",
    );

    run.addEventListener("click", () => {
      void (async () => {
        const passwords = handlers.entries.map((entry) => entry.password).filter(Boolean);
        if (passwords.length === 0) {
          status.textContent = "There is nothing to check yet.";
          status.className = "status";
          return;
        }

        run.disabled = true;
        status.className = "status status-notice";

        const found = await checkPasswords(passwords, {
          onProgress: (done, total) => {
            status.textContent = `Checking… ${done} of ${total} lookups.`;
          },
        });

        handlers.onBreachResults(found);
        for (const [password, count] of found) handlers.breaches.set(password, count);

        const missed = new Set(passwords).size - found.size;
        status.textContent = missed > 0
          ? `Done. ${missed} password${missed === 1 ? "" : "s"} could not be checked — ` +
            "they are reported as unknown, not as safe."
          : "Done.";
        status.className = missed > 0 ? "status status-error" : "status status-ok";
        run.disabled = false;
        paint();
      })();
    });

    return [
      el("h2", {}, "Breach check"),
      el("p", { class: "subtitle" },
        "Checks your passwords against Have I Been Pwned without revealing them. " +
        "For each one, the browser computes a SHA-1 hash and sends only its first " +
        "five characters — a prefix shared by roughly 800 other passwords — then " +
        "compares the returned list locally.",
      ),
      el("p", { class: "subtitle" },
        "This is the only feature that contacts anyone but Vaultify's own server, " +
        "which is why it runs only when you press the button.",
      ),
      status,
      run,
    ];
  }

  mount(root, el("div", { class: "card" }, el("h2", {}, "Security check"), results), breachPanel);
  paint();
}

function renderReport(report: HealthReport, handlers: SecurityHandlers): Array<Node | string> {
  if (report.checked === 0) {
    return [el("p", { class: "subtitle" }, "Add an entry and this will have something to say.")];
  }

  const summary = el("p", { class: "summary" }, summarise(report));

  if (report.findings.length === 0) {
    return [
      el("div", { class: "all-clear" }, icon(ICONS.lock), summary),
      el("p", { class: "subtitle" },
        `${report.checked} ${report.checked === 1 ? "entry" : "entries"} checked.`,
      ),
    ];
  }

  // Group by kind so the list reads as "here are the breached ones", rather
  // than interleaving four different kinds of advice.
  const groups = new Map<Finding["kind"], Finding[]>();
  for (const finding of report.findings) {
    const bucket = groups.get(finding.kind);
    if (bucket) bucket.push(finding);
    else groups.set(finding.kind, [finding]);
  }

  const sections: Array<Node | string> = [
    summary,
    el("p", { class: "subtitle" },
      `${report.healthy} of ${report.checked} entries have nothing wrong.`,
    ),
  ];

  for (const [kind, findings] of groups) {
    sections.push(
      el("section", { class: `finding-group finding-${kind}` },
        el("h3", {}, `${LABELS[kind]} (${findings.length})`),
        el("ul", { class: "finding-list" },
          ...findings.map((finding) => renderFinding(finding, handlers)),
        ),
      ),
    );
  }

  return sections;
}

function renderFinding(finding: Finding, handlers: SecurityHandlers): HTMLElement {
  const fix = el("button", { type: "button", class: "link" }, "Fix");
  fix.addEventListener("click", () => {
    const entry = handlers.entries.find((candidate) => candidate.id === finding.entryId);
    if (entry) handlers.edit(entry);
  });

  return el("li", { class: "finding" },
    el("div", { class: "finding-main" },
      el("div", { class: "finding-name" }, finding.entryName),
      el("div", { class: "finding-detail" }, finding.detail),
    ),
    fix,
  );
}
