# The Vaultify Web Client

The client is the trust boundary. The API is a storage locker that cannot read
what it holds; the browser tab is the only place a plaintext password ever
exists. Everything below follows from that.

---

## 1. Why there is no framework

`apps/web` has **zero runtime dependencies**. No React, no bundler, no CSS
framework — 36 ES modules, shipped unminified, roughly 240 kB of readable
JavaScript.

That is not minimalism as an aesthetic. The threat model names one attack that
breaks zero-knowledge outright: a compromised client bundle, which can capture
the master password as it is typed. There is no cryptographic defence against
it. The only real mitigations are *auditability* — a reviewer can read what the
browser actually runs — and *integrity* — the browser can detect that the
bytes changed.

A framework would put an order of magnitude more code inside that boundary,
delivered through a dependency tree this project does not control. For an
application whose security argument rests on "you can check what we shipped",
that is the wrong trade.

The cost is real and worth stating: no component model, no reactivity, manual
DOM updates. The codebase is small enough that this is tolerable, and
[`src/dom.ts`](../apps/web/src/dom.ts) — under 100 lines of code — is the
entire substitute.

---

## 2. The build

There isn't one, in the usual sense. Node 22.6+ strips TypeScript types
natively, and [`build.ts`](../apps/web/build.ts) uses that: strip the types,
rewrite `.ts` import specifiers to `.js`, write the files out.

```
src/session.ts  ──strip types──►  dist/app/session.js
                                  same file, same names, same line numbers
```

Nothing is bundled, renamed, inlined or minified. The module graph the browser
loads is the module graph in `src/`, so a stack trace in the console points at
a real line of real source. Type stripping replaces annotations with spaces
rather than reformatting, which is what keeps the line numbers honest.

```bash
npm run build                                   # -> apps/web/dist
VAULTIFY_API_ORIGIN=https://api.example.com npm run build
```

### What the build produces for security

**A CSP with no `unsafe-inline`.** Every script and style is a file. The single
element the platform forces to be inline — the import map, which the HTML
parser requires in the document — is allowed by its SHA-256 hash:

```
default-src 'none';
script-src 'self' 'sha256-wPX/zJ5gITaJqTDouwsW4LXTUyp71yaqgvOVMHMMgfA=';
style-src 'self';
connect-src 'self' http://localhost:4000;
form-action 'none'; base-uri 'none'; frame-ancestors 'none'; object-src 'none';
require-trusted-types-for 'script'
```

`connect-src` naming exactly one origin is the directive that matters most
here: a script that somehow did execute still has nowhere to send a stolen
vault key.

> A hash must cover the element's text content **byte for byte**, surrounding
> whitespace included. A hash taken over a trimmed copy looks correct in a
> diff, and the browser silently rejects the script — which here means the
> import map never applies and nothing loads. `test/build.test.ts` extracts
> the exact inline text from the built page and re-hashes it.

**SRI over the whole module graph.** The import map carries an `integrity`
entry for every module, and the entry `<script>` carries its own `integrity`
attribute:

```html
<script type="importmap">
{
  "imports": { "@vaultify/crypto": "/app/vendor/crypto/index.js" },
  "integrity": {
    "/app/vendor/crypto/kdf.js": "sha384-EIexZ1+qsSBX3KGNUHKnF37rDWhqgrt2…",
    …
  }
}
</script>
<script type="module" src="/app/main.js" integrity="sha384-zOo+uue8bpZrNaOho…"></script>
```

The attribute on the entry script is supported everywhere. Import-map
integrity is Chromium 127+; browsers without it ignore the field and fall back
to same-origin trust. Partial coverage, stated rather than overclaimed.

`dist/csp.txt` is written next to the build. A production proxy should copy
that file rather than restate the policy, so the hash cannot drift away from
the bytes it covers.

---

## 3. What is never persisted

| | Where it lives | Survives a refresh? |
|---|---|---|
| Master password | A local in the handler that derives from it | No |
| Vault key (`CryptoKey`) | One field on the session object | No |
| Decrypted entries | One field on the session object | No |
| Access token | One field on the session object | No |
| Last-used email | `localStorage` | Yes |
| Auto-lock preference | `localStorage` | Yes |

No `sessionStorage`, no cookie, no IndexedDB, no secret in `localStorage`.
Locking is implemented as *dropping the object*.

The cost is visible: refreshing the page asks for the master password again.
The alternative is leaving a key somewhere a later page load can find it, which
hands the vault to any XSS that ever lands on this origin — including one
introduced a year from now. A password manager that survives a refresh has, by
construction, stored the means to decrypt itself.

---

## 4. Auto-lock

[`src/autolock.ts`](../apps/web/src/autolock.ts) is a state machine over an
injected clock, which is what makes it testable without waiting out real
minutes. It fires on whichever deadline comes first:

| Trigger | Default | Reason |
|---|---|---|
| Inactivity | 5 minutes (configurable 1–60) | The unattended laptop |
| Tab hidden | 60 seconds | Switching away is the common case; instant locking would make the app unusable |
| Token expiry | 15 minutes | The session is dead anyway |
| Manual | — | The user asked |

Every deadline is recomputed from the clock on each tick, so a tab whose timers
the browser throttled cannot stay unlocked by simply not being ticked — it
wakes up late and locks immediately. There is a test for exactly that.

What locking guarantees is that *the application* has no path back to the
plaintext without the master password. It does not guarantee the bytes are gone
from memory: strings are immutable, the GC may have copied them, and `CryptoKey`
material lives outside JavaScript's reach entirely. Overwriting the fields is
best-effort and documented as such.

---

## 5. Sync, and the merge the server cannot do

Saves are debounced (1.2 s) rather than manual. A password manager where the
user can forget to press Save is a password manager that loses passwords.

Every write is a compare-and-set on the vault revision. When it loses:

```
PUT /api/vault { expectedRevision: 3 }  ->  409 { currentRevision: 5 }
     |
     GET /api/vault        decrypt the newer vault
     |
     mergeVaults(base, mine, theirs)
     |
PUT /api/vault { expectedRevision: 5 }  ->  200
```

Up to three attempts, then the error surfaces. The merge is three-way — the
client keeps the last-synced state as a common ancestor, which is what makes
"this entry is in theirs but not mine" answerable rather than a guess.

**The rule that decides every ambiguous case: never silently lose a
credential.**

| Situation | Outcome |
|---|---|
| Added on either side | Kept |
| Deleted on one side, untouched on the other | Deleted |
| Deleted on one side, **edited** on the other | **Kept**, with a note |
| Edited differently on both sides | **Both kept**, the older as "(conflicted copy)", with a note |
| No common ancestor (first sync) | Everything from both sides kept |

A duplicate entry is a visible annoyance the user fixes in two clicks. A
password that quietly disappears is noticed when it is needed, which is exactly
when it cannot be recovered. Conflicted copies get a *stable* derived id, so
re-running a merge does not keep minting new ones.

Merges are never silent: the notes are shown in the banner, because the list
the user is looking at just changed underneath them.

---

## 6. Smaller decisions worth knowing

**The search box does not match on passwords.** Names, usernames, URLs and
notes are searchable; the secret is not. Filtering on it would let an observer
narrow a password a character at a time by watching which rows survive each
keystroke.

**Entry URLs are scheme-checked before becoming links.** `safeHref` accepts
only `http:` and `https:`. An entry's URL field is attacker-influenced data
rendered into an `href` in a tab that holds the vault key — `javascript:` there
is stored XSS with the best possible scope.

**`dom.ts` has no `innerHTML` and no path to one.** Every string a caller
passes becomes a text node. An entry named `<img onerror=…>` is a string with
angle brackets in it.

**Clipboard copies clear after 20 seconds**, but only if the clipboard still
holds what we put there — clearing unconditionally would wipe whatever the user
copied in the meantime. The system clipboard is readable by every other
application on the machine and synced across devices by some operating systems;
shortening the window is all a web page can do, and the UI says so.

**Deleting takes two clicks**, with the button restating what the second one
does. No `confirm()`: it blocks the event loop and reads as a browser artefact
rather than part of the application.

**The derivation delay is labelled, not spinnered.** The button says "Deriving
keys…" and the status line says "600,000 PBKDF2 iterations. This takes a
moment, by design." A user who thinks the app is slow asks for it to be made
faster; a user who knows what the wait buys them does not.

**No-recovery is a blocking checkbox at sign-up**, not fine print. Learning
there is no reset path *after* losing the password is the worst possible
moment.

---

## 7. Password strength

[`src/strength.ts`](../apps/web/src/strength.ts) estimates search space and
discounts the patterns that make a password far weaker than its length
suggests: repeats, runs, keyboard walks, years, and a short list of passwords
at the top of every breach corpus. Registration refuses anything below "fair".

It is **not** zxcvbn. A real estimator carries a ~30k-word dictionary and n-gram
tables and would roughly double the download on the login path. The gap is
deliberate and worth naming: this will rate `Tr0ub4dor&3` as strong when a
dictionary-aware cracker breaks it quickly. It is a nudge away from obviously
bad choices, not a guarantee.

(The example passphrase from this project's own README is in the rejected list.
A published example is a published password.)

---

## 8. Testing

169 tests, no browser and no DOM required — the logic worth testing was kept
out of the views on purpose.

| Suite | Covers |
|---|---|
| `merge.test.ts` | 16 tests — every divergence scenario, written as what happens on two devices |
| `session.test.ts` | 33 tests — real crypto, the real `ApiClient`, a fake server enforcing the real compare-and-set |
| `search.test.ts` | 20 tests — filtering, sorting, and the `javascript:`/`data:` payloads `safeHref` exists to refuse |
| `build.test.ts` | 23 tests — SRI hashes match the served bytes, the CSP has no inline exemption, every workspace import is vendored, the build is reproducible |
| `autolock.test.ts` | 17 tests — every deadline, including the throttled-tab case |
| `strength.test.ts` | 15 tests — ordering and the floor, not exact bit counts |
| `qr.test.ts` | 14 tests — round-tripped through an independently written reader |
| `breach.test.ts` | 31 tests — what crosses the wire, and the health report |

`session.test.ts` is the one to read first. It drives the real client library
against a server double and asserts, among other things, that no fragment of
the master password appears anywhere in the recorded request log, and that the
stored blob contains none of the entry's plaintext.

```bash
npm test --workspace @vaultify/web
```

---

## 9. Running it

```bash
npm run build --workspace @vaultify/web   # or let `npm run web` do it
npm run web                               # http://localhost:5173
```

`serve.ts` is a dependency-free static server. It builds on start and sends the
same headers production must send, generated by the same build that produced
the files — so the CSP and the import-map hash cannot drift apart.

It deliberately does **not** proxy the API. A proxy would put the client and
the API on one origin, which is more convenient and strictly worse: it hides a
CORS misconfiguration until production, and it widens `connect-src` from one
named origin to `'self'`.

The API must allow the client's origin:

```
CORS_ORIGIN=http://localhost:5173
```

---

## 10. Two-factor, the breach check, and the recovery kit

### The QR encoder

`src/qr.ts` is about 370 lines of ISO/IEC 18004 — byte mode, error correction
level M, versions 1–10 — because enrolling an authenticator without a QR code
means asking someone to type 32 base32 characters into a phone, and because
pulling in a dependency would undercut the one argument this client has
against a compromised-bundle attack.

It is tested by **round-tripping through a reader written separately from the
spec**: `test/qr.test.ts` undoes the mask, walks the placement backwards,
de-interleaves the blocks and parses the byte-mode header. A QR code with the
data one column out still looks exactly like a QR code, so asserting "a grid
was produced" would be worth nothing. The reader does no error correction on
purpose — repairing errors would hide the small placement bugs it exists to
find.

That test caught a real one: the second copy of the format information was
overwriting the module the spec requires to always be dark. The code still
scanned, because the first copy was intact, and only a conformance check
surfaced it.

### The breach check

Opt-in, per run, and never a background task. The mechanism is k-anonymity:

```
SHA-1("password123")  =  CBFDA C6008F9CAB4083784CBD1874F76618D2A97
                         └─┬─┘ └──────────────┬──────────────────┘
                     sent to HIBP        compared locally
```

The service learns that someone asked about one of roughly 800 passwords. It
never sees the password or its full hash. Lookups are de-duplicated by prefix,
which is partly about speed and mostly so that a vault reusing one password
across ten entries does not produce ten identical requests — that pattern is
itself information.

Two decisions worth keeping:

- **A failed lookup leaves the password absent from the results, not marked
  clean.** Telling someone a password is fine because the network hiccupped is
  worse than saying nothing, and the UI reports the difference.
- **`connect-src` names `https://api.pwnedpasswords.com` explicitly.** With
  exactly two allowed destinations, a script that somehow ran on this origin
  still has nowhere to post a stolen vault key. `test/build.test.ts` asserts
  the directive holds those two and nothing else.

### The recovery kit

Shown once, at registration, and never derivable again:

```
0WZ0Z-4MSBR-1BTKE-XJ454-MWC97-XATJJ-E0TTX-W2138-GA27F-53G80-CG
```

That is the vault key, in an alphabet with no I, L, O or U, because it is a
thing people transcribe from paper under stress. `decodeRecoveryKey` maps the
substitutions a human makes (`I`→`1`, `O`→`0`) and **refuses a key of the wrong
length** rather than quietly producing a `CryptoKey` that never decrypts
anything — a miserable failure to debug while holding a printout.

What it does, and what the UI says it does:

| | |
|---|---|
| Decrypts a backup file | Yes — offline, no account, no network, no server |
| Signs you in | **No.** Authentication needs the master password |
| Useful on its own | No. The kit opens a backup; without one it opens nothing |

So the screen that shows the kit also pushes the encrypted backup download, and
tells the user to keep the two apart: together they are the vault, separately
each is useless. `Restore from a backup` on the locked page takes both and
decrypts entirely in the tab — it is reachable with no account and works with
the API switched off, which is the whole point.

### Auto-lock drops the breach results too

They are keyed by plaintext password, so they are exactly as sensitive as the
vault and go the same way on lock.

---

## 11. Still open

- **Per-entry TOTP.** `VaultEntry.totpSecret` is sealed with the vault and
  `@vaultify/totp` already generates codes in the browser; nothing reads the
  field yet. This is the smallest remaining piece.
- **Import** from other password managers. Export exists (plaintext, behind a
  two-click warning, on the restore screen); import does not.
- **A service worker** so the client works offline — which also pins the bundle
  and makes a swapped script detectable across sessions.
- **WebAuthn / passkeys** as a second factor. Phishing-resistant in a way TOTP
  is not, and it would remove the server-held seed entirely.
- **Re-issuing recovery codes** without turning 2FA off and on again.
- **A worker for key derivation.** 600,000 PBKDF2 iterations currently block
  the main thread for a second or so, which is why the button says "Deriving
  keys…" rather than showing a spinner that cannot animate.
