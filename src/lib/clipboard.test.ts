/**
 * copySensitive — the account number's copy (MR-1723).
 *
 * Run: npx vitest run src/lib/clipboard.test.ts
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { copySensitive } from './clipboard';

vi.mock('@tauri-apps/api/core');
const mockedInvoke = vi.mocked(invoke);
const writeText = vi.fn();

beforeEach(() => {
  mockedInvoke.mockReset();
  writeText.mockReset().mockResolvedValue(undefined);
  Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
});

describe('copySensitive', () => {
  it('Windows: Rust copies it, kept out of clipboard history; the web clipboard is not touched', async () => {
    mockedInvoke.mockResolvedValue(true);
    await copySensitive('123456789012345678901234');
    expect(mockedInvoke).toHaveBeenCalledWith('copy_sensitive', { text: '123456789012345678901234' });
    expect(writeText).not.toHaveBeenCalled();
  });

  it('macOS / Linux: Rust answers false and it is copied the ordinary way, as before', async () => {
    mockedInvoke.mockResolvedValue(false);
    await copySensitive('123456789012345678901234');
    expect(writeText).toHaveBeenCalledWith('123456789012345678901234');
  });

  it('a failed native copy is reported, never retried as an ordinary (Win+V-visible) copy', async () => {
    mockedInvoke.mockRejectedValue({ code: 'unknown', message: 'The clipboard could not be reached.' });
    await expect(copySensitive('123456789012345678901234')).rejects.toBeTruthy();
    expect(writeText).not.toHaveBeenCalled();
  });
});
