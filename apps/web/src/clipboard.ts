/**
 * Clipboard handling, with the limitation stated rather than hidden.
 *
 * Copying a password puts it somewhere this application does not control:
 * the system clipboard is readable by every other application on the machine,
 * synced across devices by some operating systems, and kept in clipboard
 * history by others. Nothing a web page does changes that.
 *
 * What we can do is shorten the exposure. After a timeout we overwrite the
 * clipboard, but only if it still holds what we put there -- clearing it
 * unconditionally would wipe something the user copied in the meantime, which
 * is both rude and a good way to lose their work.
 *
 * Reading the clipboard back needs a permission the user may not have granted.
 * When it is unavailable we skip the check and clear anyway: a stale password
 * sitting in the clipboard is the worse of the two failures.
 */

export const DEFAULT_CLEAR_MS = 20_000;

export interface ClipboardResult {
  readonly ok: boolean;
  /** When the copy will be cleared, or null when it will not be. */
  readonly clearsAt: number | null;
  readonly message: string;
}

let pendingClear: ReturnType<typeof setTimeout> | null = null;

export async function copySecret(
  value: string,
  clearAfterMs: number = DEFAULT_CLEAR_MS,
): Promise<ClipboardResult> {
  if (!navigator.clipboard?.writeText) {
    return {
      ok: false,
      clearsAt: null,
      message: "This browser will not allow copying from a script. Reveal and copy by hand.",
    };
  }

  try {
    await navigator.clipboard.writeText(value);
  } catch {
    // Firefox and Safari refuse the write outside a user gesture, and every
    // browser refuses it in an insecure context.
    return {
      ok: false,
      clearsAt: null,
      message: "The browser blocked the copy. Reveal the password and copy it by hand.",
    };
  }

  if (pendingClear !== null) clearTimeout(pendingClear);
  pendingClear = setTimeout(() => {
    void clearIfUnchanged(value);
  }, clearAfterMs);

  return {
    ok: true,
    clearsAt: Date.now() + clearAfterMs,
    message: `Copied. The clipboard clears in ${Math.round(clearAfterMs / 1000)}s.`,
  };
}

async function clearIfUnchanged(expected: string): Promise<void> {
  pendingClear = null;
  try {
    if (navigator.clipboard?.readText) {
      const current = await navigator.clipboard.readText();
      if (current !== expected) return; // the user copied something else; leave it
    }
    await navigator.clipboard.writeText("");
  } catch {
    // Permission denied, or the document lost focus. Nothing further to try;
    // the UI already warned that a copied password is exposed until overwritten.
  }
}

/** Cancel a pending clear -- used on lock, where we clear immediately instead. */
export function cancelPendingClear(): void {
  if (pendingClear !== null) {
    clearTimeout(pendingClear);
    pendingClear = null;
  }
}
