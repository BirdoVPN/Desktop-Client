/**
 * copySensitive — the account number's copy (MR-1723).
 *
 * Run: npx vitest run src/lib/clipboard.test.ts
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { copySensitive } from './clipboard';

vi.mock('@tauri-apps/api/core');
const mockedInvoke = vi.mocked(invoke);
const writeText = vi.fn();
const realUserAgent = navigator.userAgent;

function setUserAgent(ua: string) {
  Object.defineProperty(window.navigator, 'userAgent', { value: ua, configurable: true });
}

beforeEach(() => {
  mockedInvoke.mockReset();
  writeText.mockReset().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
});

afterEach(() => setUserAgent(realUserAgent));

describe('copySensitive on Windows', () => {
  beforeEach(() => setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/141.0'));

  it('Rust copies it, kept out of clipboard history; the web clipboard is not touched', async () => {
    mockedInvoke.mockResolvedValue(true);
    await copySensitive('123456789012345678901234');
    expect(mockedInvoke).toHaveBeenCalledWith('copy_sensitive', { text: '123456789012345678901234' });
    expect(writeText).not.toHaveBeenCalled();
  });

  it('a failed native copy is reported, never retried as an ordinary (Win+V-visible) copy', async () => {
    mockedInvoke.mockRejectedValue({ code: 'unknown', message: 'The clipboard could not be reached.' });
    await expect(copySensitive('123456789012345678901234')).rejects.toBeTruthy();
    expect(writeText).not.toHaveBeenCalled();
  });

  it('an answer that is not "copied" is a failure, not a silent success', async () => {
    mockedInvoke.mockResolvedValue(false);
    await expect(copySensitive('123456789012345678901234')).rejects.toThrow();
    expect(writeText).not.toHaveBeenCalled();
  });
});

describe('copySensitive on macOS and Linux', () => {
  for (const ua of [
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko)',
  ]) {
    it(`writes at once, inside the click (WebKit's user-gesture rule), with no IPC first: ${ua.slice(13, 32)}`, async () => {
      setUserAgent(ua);
      const copied = copySensitive('123456789012345678901234');
      // Synchronously, before anything is awaited: still inside the gesture.
      expect(writeText).toHaveBeenCalledWith('123456789012345678901234');
      await copied;
      expect(mockedInvoke).not.toHaveBeenCalled();
    });
  }

  it('a refused web copy is reported to the caller', async () => {
    setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15');
    writeText.mockRejectedValue(new DOMException('denied', 'NotAllowedError'));
    await expect(copySensitive('123456789012345678901234')).rejects.toThrow('denied');
  });
});
