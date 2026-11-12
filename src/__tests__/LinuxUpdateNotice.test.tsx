/**
 * A-M50: the Linux new-version notice. Shown only on Linux, only for a newer
 * version Rust reports, remembers a dismissal per version, and a failed check
 * shows nothing at all.
 *
 * Run: npx vitest run src/__tests__/LinuxUpdateNotice.test.tsx
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { LinuxUpdateNotice } from '@/components/LinuxUpdateNotice';
import { LINUX_UPDATE_DISMISSED_KEY } from '@/session/linux-release';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));
const invokeMock = vi.mocked(invoke);

const LINUX_UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko)';
const WINDOWS_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/120';
const MAC_UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15';

function setUa(ua: string) {
  vi.spyOn(navigator, 'userAgent', 'get').mockReturnValue(ua);
}

/** Past the 20 s startup delay, with the check's promise settled. */
async function startupDelay() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(20_001);
  });
}

beforeEach(() => {
  vi.useFakeTimers({ shouldAdvanceTime: true });
  localStorage.clear();
  invokeMock.mockReset();
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

describe('LinuxUpdateNotice', () => {
  it('shows the notice on Linux when a newer version is reported', async () => {
    setUa(LINUX_UA);
    invokeMock.mockResolvedValue('1.4.55');
    render(<LinuxUpdateNotice />);
    await startupDelay();
    expect(screen.getByText('BirdoVPN 1.4.55 is available')).toBeInTheDocument();
    expect(invokeMock).toHaveBeenCalledWith('check_linux_release');
  });

  it.each([
    ['Windows', WINDOWS_UA],
    ['macOS', MAC_UA],
  ])('is not shown, and never checks, on %s', async (_name, ua) => {
    setUa(ua);
    invokeMock.mockResolvedValue('1.4.55');
    render(<LinuxUpdateNotice />);
    await startupDelay();
    expect(screen.queryByText(/is available/)).toBeNull();
    expect(invokeMock).not.toHaveBeenCalled();
  });

  it('shows nothing when up to date (null)', async () => {
    setUa(LINUX_UA);
    invokeMock.mockResolvedValue(null);
    render(<LinuxUpdateNotice />);
    await startupDelay();
    expect(screen.queryByText(/is available/)).toBeNull();
  });

  it('shows nothing when the check fails', async () => {
    setUa(LINUX_UA);
    invokeMock.mockRejectedValue(new Error('network down'));
    render(<LinuxUpdateNotice />);
    await startupDelay();
    expect(screen.queryByText(/is available/)).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('opens the release page through Rust, with no URL argument', async () => {
    setUa(LINUX_UA);
    invokeMock.mockImplementation((cmd) => Promise.resolve(cmd === 'check_linux_release' ? '1.4.55' : undefined));
    render(<LinuxUpdateNotice />);
    await startupDelay();
    await userEvent.setup({ advanceTimers: vi.advanceTimersByTime }).click(screen.getByRole('button', { name: /download/i }));
    expect(invokeMock).toHaveBeenCalledWith('open_linux_release_page');
  });

  it('remembers a dismissal per version, and announces a newer one', async () => {
    setUa(LINUX_UA);
    invokeMock.mockResolvedValue('1.4.55');
    const first = render(<LinuxUpdateNotice />);
    await startupDelay();
    await userEvent.setup({ advanceTimers: vi.advanceTimersByTime }).click(screen.getByRole('button', { name: 'Dismiss' }));
    expect(screen.queryByText(/is available/)).toBeNull();
    expect(localStorage.getItem(LINUX_UPDATE_DISMISSED_KEY)).toBe('1.4.55');
    first.unmount();

    // Next start: same version stays dismissed.
    render(<LinuxUpdateNotice />);
    await startupDelay();
    expect(screen.queryByText(/is available/)).toBeNull();

    // A newer release at the next 24 h check is announced again.
    invokeMock.mockResolvedValue('1.4.56');
    await act(async () => {
      await vi.advanceTimersByTimeAsync(24 * 60 * 60 * 1000);
    });
    expect(screen.getByText('BirdoVPN 1.4.56 is available')).toBeInTheDocument();
  });
});

describe('the Linux notice stays private and unscoped', () => {
  const read = (p: string) => readFileSync(resolve(__dirname, p), 'utf8').replace(/\r\n/g, '\n');

  it('sends a generic User-Agent, no e-mail, and keeps GitHub out of the webview opener scope', () => {
    const rs = read('../../src-tauri/src/commands/linux_release.rs');
    expect(rs).toContain('const USER_AGENT: &str = "BirdoVPN-Desktop-update-check";');
    expect(rs).not.toMatch(/\.cookie|\.bearer_auth|\.basic_auth|Authorization/i);
    const caps = read('../../src-tauri/capabilities/default.json');
    expect(caps).not.toContain('github.com');
  });
});
