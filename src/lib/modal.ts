/**
 * Modal behaviour for dialogs and sheets (W2-017): initial focus, a Tab trap,
 * Escape, an inert background, and focus returned to the trigger on close.
 *
 * Every dialog here was hand-rolled and none did all of it: the Home sign-out
 * and deep-link dialogs had no dialog role, no aria-modal and no Escape; no
 * dialog moved focus in, trapped Tab, or gave focus back; and the page behind
 * every modal stayed focusable, so keyboard users tabbed into invisible content.
 *
 * `inert` rather than `<dialog>.showModal()`: the dialogs render inside the
 * phone column (below the custom title bar, which must stay usable), and
 * `inert` is supported by WebView2's Chromium. The Tab trap is kept as well —
 * it is what the tests can see, and it covers a host where `inert` is ignored.
 */
import { useCallback, useEffect, useRef, type RefObject } from 'react';

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), ' +
  'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/** Open modals, innermost last: only the top one handles keys. */
const stack: HTMLElement[] = [];

/** True while any dialog or sheet is open (AppShell's Escape-to-go-back yields to it). */
export function isModalOpen(): boolean {
  return stack.length > 0;
}

function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => !el.closest('[inert]') && el.getAttribute('aria-hidden') !== 'true',
  );
}

/**
 * Make everything outside `el` inert: walk up to <body>, marking each level's
 * siblings. Elements marked `data-modal-exempt` (the title bar's window
 * controls, the notice host) are left alone. Returns the undo.
 */
export function inertOthers(el: HTMLElement): () => void {
  const touched: HTMLElement[] = [];
  let node: HTMLElement = el;
  while (node.parentElement && node !== document.body) {
    for (const sib of Array.from(node.parentElement.children)) {
      if (sib === node || !(sib instanceof HTMLElement)) continue;
      if (sib.hasAttribute('inert') || sib.hasAttribute('data-modal-exempt')) continue;
      if (sib.tagName === 'SCRIPT' || sib.tagName === 'STYLE') continue;
      sib.setAttribute('inert', '');
      touched.push(sib);
    }
    node = node.parentElement;
  }
  return () => touched.forEach((t) => t.removeAttribute('inert'));
}

export interface ModalOptions {
  /** Called on Escape. Omit (or pass undefined) while the dialog must not close. */
  onEscape?: () => void;
  /** Focused on open; the first focusable element otherwise. */
  initialFocusRef?: RefObject<HTMLElement | null>;
}

/**
 * Modal behaviour as a CALLBACK REF: attach it to the dialog's outermost
 * element and the behaviour lives exactly as long as that element does (React
 * 19 runs the returned cleanup on detach). A callback ref rather than an
 * effect so that nested refs — the initial-focus target inside the dialog —
 * are already attached when it runs, and so a re-render can never re-run the
 * setup and yank focus back to the first field.
 */
export function useModalRoot({ onEscape, initialFocusRef }: ModalOptions = {}): (
  root: HTMLElement | null,
) => (() => void) | undefined {
  const latest = useRef<ModalOptions>({});
  useEffect(() => {
    latest.current = { onEscape, initialFocusRef };
  });

  return useCallback((root: HTMLElement | null) => {
    if (!root) return undefined;
    const previouslyFocused = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    stack.push(root);
    const release = inertOthers(root);

    const first = latest.current.initialFocusRef?.current ?? focusables(root)[0];
    if (first) {
      first.focus();
    } else {
      if (!root.hasAttribute('tabindex')) root.setAttribute('tabindex', '-1');
      root.focus();
    }

    // On the DOCUMENT, not the root: when the focused control is removed (a
    // dialog swapping its content, say) focus falls to <body>, and a listener
    // on the root would then never hear Escape — or the Tab that should bring
    // focus back inside.
    const onKeyDown = (e: KeyboardEvent) => {
      if (stack[stack.length - 1] !== root) return;
      if (e.key === 'Escape') {
        // Stop here so Escape does not ALSO pop the screen underneath.
        e.stopPropagation();
        latest.current.onEscape?.();
        return;
      }
      if (e.key !== 'Tab') return;
      const items = focusables(root);
      if (items.length === 0) {
        e.preventDefault();
        return;
      }
      const firstItem = items[0];
      const lastItem = items[items.length - 1];
      const active = document.activeElement;
      if (e.shiftKey && (active === firstItem || !root.contains(active))) {
        e.preventDefault();
        lastItem.focus();
      } else if (!e.shiftKey && (active === lastItem || !root.contains(active))) {
        e.preventDefault();
        firstItem.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);

    return () => {
      document.removeEventListener('keydown', onKeyDown);
      release();
      const at = stack.lastIndexOf(root);
      if (at >= 0) stack.splice(at, 1);
      // Back to the control that opened it, if it is still there to take focus.
      if (previouslyFocused && previouslyFocused.isConnected) previouslyFocused.focus();
    };
  }, []);
}
