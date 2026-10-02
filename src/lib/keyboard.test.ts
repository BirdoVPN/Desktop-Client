/**
 * WebView2's browser accelerators are blocked (W2-033). Whether preventDefault
 * actually stops each one in WebView2 is on the device checklist; this pins
 * which keys the page refuses.
 *
 * Run: npx vitest run src/lib/keyboard.test.ts
 */
import { describe, it, expect, afterEach } from 'vitest';
import { installBrowserShortcutGuard, isBlockedBrowserShortcut } from './keyboard';

const key = (k: string, mods: Partial<{ ctrlKey: boolean; shiftKey: boolean; altKey: boolean; metaKey: boolean }> = {}) => ({
  key: k,
  ctrlKey: false,
  shiftKey: false,
  altKey: false,
  metaKey: false,
  ...mods,
});

describe('isBlockedBrowserShortcut', () => {
  it.each([
    ['F5', key('F5')],
    ['Ctrl+R', key('r', { ctrlKey: true })],
    ['Ctrl+Shift+R', key('R', { ctrlKey: true, shiftKey: true })],
    ['Ctrl+F5', key('F5', { ctrlKey: true })],
    ['Ctrl+P', key('p', { ctrlKey: true })],
    ['Ctrl+F', key('f', { ctrlKey: true })],
    ['F3', key('F3')],
    ['Ctrl+U', key('u', { ctrlKey: true })],
    ['Ctrl+S', key('s', { ctrlKey: true })],
    ['F7 (caret browsing)', key('F7')],
  ])('blocks %s', (_n, e) => {
    expect(isBlockedBrowserShortcut(e)).toBe(true);
  });

  it.each([
    ['plain typing', key('r')],
    ['Ctrl+C', key('c', { ctrlKey: true })],
    ['Ctrl+V', key('v', { ctrlKey: true })],
    ['Ctrl+A', key('a', { ctrlKey: true })],
    ['Escape', key('Escape')],
    ['Tab', key('Tab')],
    ['AltGr+R (Ctrl+Alt)', key('r', { ctrlKey: true, altKey: true })],
  ])('leaves %s alone', (_n, e) => {
    expect(isBlockedBrowserShortcut(e)).toBe(false);
  });
});

describe('installBrowserShortcutGuard', () => {
  let undo: () => void = () => {};
  afterEach(() => undo());

  it('prevents F5 in the page, and the context menu outside text fields only', () => {
    undo = installBrowserShortcutGuard();
    const f5 = new KeyboardEvent('keydown', { key: 'F5', cancelable: true, bubbles: true });
    document.body.dispatchEvent(f5);
    expect(f5.defaultPrevented).toBe(true);

    const menuOnPage = new MouseEvent('contextmenu', { cancelable: true, bubbles: true });
    document.body.dispatchEvent(menuOnPage);
    expect(menuOnPage.defaultPrevented).toBe(true);

    const input = document.createElement('input');
    document.body.appendChild(input);
    const menuInField = new MouseEvent('contextmenu', { cancelable: true, bubbles: true });
    input.dispatchEvent(menuInField);
    expect(menuInField.defaultPrevented).toBe(false);
    input.remove();
  });
});
