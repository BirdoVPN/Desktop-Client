/**
 * Browser keys that make no sense in an app window (W2-033).
 *
 * WebView2 leaves its browser accelerators on by default (wry's
 * `with_browser_accelerator_keys` defaults to true; ICoreWebView2Settings3):
 * F5 / Ctrl+R reloaded the React app mid-session — losing the navigation stack,
 * an in-progress 2FA challenge and any open dialog — and Ctrl+P opened a print
 * dialog of the UI. `preventDefault` in the page stops them in Chromium; the
 * Rust side can additionally turn the setting off. The right-click menu offers
 * the same Reload / Print / Save as, so it is suppressed outside text fields
 * (where Copy / Paste are useful).
 */
export function isBlockedBrowserShortcut(e: Pick<KeyboardEvent, 'key' | 'ctrlKey' | 'metaKey' | 'shiftKey' | 'altKey'>): boolean {
  const key = e.key.length === 1 ? e.key.toLowerCase() : e.key;
  if (key === 'F5' || key === 'F3' || key === 'F7' || key === 'BrowserRefresh') return true;
  const mod = e.ctrlKey || e.metaKey;
  if (!mod || e.altKey) return false;
  // r reload, p print, f / g find, u view source, s save, j downloads,
  // h history, o open file, n new window.
  return ['r', 'p', 'f', 'g', 'u', 's', 'j', 'h', 'o', 'n', 'F5'].includes(key);
}

function isEditable(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return (
    target.isContentEditable ||
    target instanceof HTMLTextAreaElement ||
    (target instanceof HTMLInputElement && target.type !== 'checkbox' && target.type !== 'radio')
  );
}

/** Install the guard on `doc`; returns the undo. */
export function installBrowserShortcutGuard(doc: Document = document): () => void {
  const onKeyDown = (e: KeyboardEvent) => {
    if (isBlockedBrowserShortcut(e)) e.preventDefault();
  };
  const onContextMenu = (e: MouseEvent) => {
    if (!isEditable(e.target)) e.preventDefault();
  };
  doc.addEventListener('keydown', onKeyDown, true);
  doc.addEventListener('contextmenu', onContextMenu);
  return () => {
    doc.removeEventListener('keydown', onKeyDown, true);
    doc.removeEventListener('contextmenu', onContextMenu);
  };
}
