/**
 * Copying a credential — the 24-digit anonymous account number (MR-1723).
 *
 * `navigator.clipboard.writeText` is an ordinary copy: on Windows it lands in
 * clipboard history (Win+V), syncs to the cloud clipboard, and stays on the
 * clipboard for good. On Windows, Rust's `copy_sensitive` marks the copy to
 * stay out of both and clears it after a minute if it is still there.
 * macOS and Linux have no such copy, and their webviews (WKWebView,
 * WebKitGTK) only allow a clipboard write inside the user's click — so there
 * the number is written straight away, the ordinary way, as before.
 */
import { invoke } from '@tauri-apps/api/core';
import { isWindowsPlatform } from '@/utils/helpers';

/**
 * Call it synchronously from the click handler (no `await` before it): the
 * platform is decided without a round-trip, so off Windows the write happens
 * inside the user gesture WebKit requires.
 *
 * Rejects when the copy failed. Callers keep their "not copied" path: on
 * Windows a failed native copy is NEVER retried as an ordinary one, which is
 * exactly the copy this exists to avoid.
 */
export function copySensitive(text: string): Promise<void> {
  if (!isWindowsPlatform()) return navigator.clipboard.writeText(text);
  return invoke<boolean>('copy_sensitive', { text }).then((copied) => {
    if (copied !== true) throw new Error('The account number was not copied.');
  });
}
