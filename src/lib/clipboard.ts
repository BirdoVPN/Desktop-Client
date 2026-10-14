/**
 * Copying a credential — the 24-digit anonymous account number (MR-1723).
 *
 * `navigator.clipboard.writeText` is an ordinary copy: on Windows it lands in
 * clipboard history (Win+V), syncs to the cloud clipboard, and stays on the
 * clipboard for good. Rust's `copy_sensitive` marks the copy to stay out of
 * both and clears it after a minute if it is still there. Where Rust has no
 * such copy (macOS, Linux) it answers `false`, and the number is copied the
 * ordinary way, as before.
 */
import { invoke } from '@tauri-apps/api/core';

/**
 * Rejects when the copy failed. Callers keep their "not copied" path: on
 * Windows a failed native copy is NEVER retried as an ordinary one, which is
 * exactly the copy this exists to avoid.
 */
export async function copySensitive(text: string): Promise<void> {
  const copiedNatively = await invoke<boolean>('copy_sensitive', { text });
  if (copiedNatively !== true) await navigator.clipboard.writeText(text);
}
