/**
 * Every link that leaves the app (MR-713: the shell plugin's `open` was
 * replaced by `openUrl` from @tauri-apps/plugin-opener).
 *
 * Each call site is driven through the real UI and must hand openUrl exactly
 * one argument, the expected URL: a second argument (`with`) would ask for a
 * specific program, which the capability's url-only scope refuses.
 *
 * The URLs observed across the whole file must equal the `opened` list in
 * fixtures/opener-urls.json. The Rust test
 * src-tauri/src/commands/capability_scope_tests.rs requires every URL in that
 * list to pass the `opener:allow-open-url` scope, so a new or changed link
 * fails one side or the other until the scope and the list agree.
 *
 * Run: npx vitest run src/__tests__/OpenerLinks.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { openUrl } from '@tauri-apps/plugin-opener';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { ConsentScreen } from '@/components/ConsentScreen';
import { Login } from '@/components/Login';
import { Settings } from '@/components/Settings';
import { UpdateRequired } from '@/components/UpdateRequired';
import { Pricing } from '@/screens/Pricing';
import { Profile } from '@/screens/Profile';
import { defaultSettings, useAppStore } from '@/store/app-store';
import { resetUpdater } from '@/session/updater';
import { resetSessionData } from '@/session/session-data';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/plugin-opener', () => ({ openUrl: vi.fn().mockResolvedValue(undefined) }));
vi.mock('@tauri-apps/plugin-process', () => ({ relaunch: vi.fn(), exit: vi.fn() }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));

const mockedInvoke = vi.mocked(invoke);
const mockedOpenUrl = vi.mocked(openUrl);

const fixture = JSON.parse(
  readFileSync(resolve(import.meta.dirname, 'fixtures/opener-urls.json'), 'utf8'),
) as { opened: string[] };

/** Every URL any test in this file saw handed to openUrl. */
const observed = new Set<string>();

/** The calls since the last reset; each must be exactly `[url]`. */
function openedUrls(): string[] {
  return mockedOpenUrl.mock.calls.map((args) => {
    expect(args, 'openUrl must be called with the URL alone (no `with`)').toHaveLength(1);
    const url = String(args[0]);
    observed.add(url);
    return url;
  });
}

beforeEach(() => {
  mockedOpenUrl.mockReset();
  mockedOpenUrl.mockResolvedValue(undefined);
  mockedInvoke.mockReset();
  mockedInvoke.mockImplementation(async (cmd: string) => {
    if (cmd === 'check_biometric_available') return { available: false, enabled: false, method: 'none' };
    if (cmd === 'get_app_version') return '1.4.47';
    return undefined;
  });
  resetUpdater();
  resetSessionData();
  useAppStore.getState().logout();
  useAppStore.setState({ isAuthenticated: true, notice: null, settings: { ...defaultSettings } });
});

describe('every external link goes through openUrl with its URL', () => {
  it('Consent: Terms of Service and Privacy Policy', async () => {
    render(<ConsentScreen onAccept={vi.fn()} onDecline={vi.fn()} />);
    await userEvent.click(screen.getByRole('button', { name: /terms of service/i }));
    await userEvent.click(screen.getByRole('button', { name: /privacy policy/i }));
    expect(openedUrls()).toEqual(['https://birdo.app/terms', 'https://birdo.app/privacy']);
  });

  it('Login: Forgot password', async () => {
    useAppStore.setState({ isAuthenticated: false });
    render(<Login />);
    await userEvent.click(screen.getByRole('button', { name: 'Forgot password?' }));
    await waitFor(() => expect(mockedOpenUrl).toHaveBeenCalled());
    expect(openedUrls()).toEqual(['https://auth.birdo.app/reset-password']);
  });

  it('Login: a refused open says where to go instead', async () => {
    useAppStore.setState({ isAuthenticated: false });
    mockedOpenUrl.mockRejectedValueOnce(new Error('Not allowed to open url'));
    render(<Login />);
    await userEvent.click(screen.getByRole('button', { name: 'Forgot password?' }));
    expect(await screen.findByText(/Visit auth\.birdo\.app to reset your password/)).toBeInTheDocument();
    openedUrls();
  });

  it('Settings: Privacy Policy, Terms of Service, Manage on web', async () => {
    render(<Settings />);
    await userEvent.click(screen.getByRole('button', { name: /Privacy Policy/ }));
    await userEvent.click(screen.getByRole('button', { name: /Terms of Service/ }));
    await userEvent.click(screen.getByRole('button', { name: /Manage on web/ }));
    expect(openedUrls()).toEqual([
      'https://birdo.app/privacy',
      'https://birdo.app/terms',
      'https://dashboard.birdo.app',
    ]);
  });

  it("Update wall: 'Download manually' opens the backend's updateUrl", async () => {
    // The canonical 426 body's details.updateUrl (api::upgrade_gate).
    render(<UpdateRequired info={{ requiredVersion: '1.4.48', downloadUrl: 'https://birdo.app/clients' }} />);
    await userEvent.click(screen.getByRole('button', { name: 'Download manually' }));
    expect(openedUrls()).toEqual(['https://birdo.app/clients']);
  });

  it("Update wall: a refused open falls back to a notice naming birdo.app", async () => {
    mockedOpenUrl.mockRejectedValueOnce(new Error('Not allowed to open url'));
    render(<UpdateRequired info={{ downloadUrl: 'https://birdo.app/clients' }} />);
    await userEvent.click(screen.getByRole('button', { name: 'Download manually' }));
    await waitFor(() =>
      expect(useAppStore.getState().notice?.text).toBe(
        "Couldn't open your browser. Visit birdo.app to download the latest version.",
      ),
    );
    openedUrls();
  });

  it('Pricing: Upgrade opens billing', async () => {
    useAppStore.setState({ account: { ...useAppStore.getState().account, plan: 'RECON' } });
    render(<Pricing />);
    const upgrades = screen.getAllByRole('button', { name: /Upgrade/ });
    expect(upgrades.length).toBeGreaterThan(0);
    await userEvent.click(upgrades[0]);
    expect(openedUrls()).toEqual(['https://dashboard.birdo.app/billing']);
  });

  it('Profile: Manage Subscription opens billing for a paid plan', async () => {
    useAppStore.setState({
      planStatus: 'ready',
      account: { ...useAppStore.getState().account, plan: 'SOVEREIGN', status: 'active' },
    });
    render(<Profile />);
    await userEvent.click(screen.getByRole('button', { name: /Manage Subscription/ }));
    expect(openedUrls()).toEqual(['https://dashboard.birdo.app/billing']);
  });

  // Declared last, so it runs after every call site above (a file's tests run
  // in order): the links the UI has are exactly the list the Rust scope test
  // checks. Running this test alone, it fails - nothing has been observed.
  it('the URLs observed above are exactly fixtures/opener-urls.json `opened`', () => {
    expect([...observed].sort()).toEqual([...fixture.opened].sort());
  });
});
