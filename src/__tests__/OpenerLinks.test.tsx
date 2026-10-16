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
 * MR-2015: and no call site is missed. `DRIVEN_CALL_SITES` counts, per file,
 * the opener calls the tests here drive; the last test counts them in the
 * source (every file under src/ but the tests), so a new call, or a new file
 * that imports the opener, fails until a test here drives it.
 *
 * The scope (birdo.app, auth. and dashboard.; MR-2015, documented rather than
 * widened): the one URL here that comes from the server is the 426's
 * `updateUrl`, and birdo-web sends exactly https://birdo.app/clients on every
 * path that answers 426 (backend/src/vpn/vpn.controller.ts). One on any other
 * host is refused by the scope, and the update wall says where to go instead
 * (the fallback notice tested below). A server that starts sending another
 * host widens the scope in the same release, here and in default.json.
 *
 * Run: npx vitest run src/__tests__/OpenerLinks.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { openUrl } from '@tauri-apps/plugin-opener';
import { readdirSync, readFileSync } from 'node:fs';
import { relative, resolve } from 'node:path';
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

  it('Update wall: an updateUrl on a host outside the scope falls back to the same notice', async () => {
    // The opener plugin refuses it (the capability scope); the mock stands in.
    mockedOpenUrl.mockRejectedValueOnce(new Error('Not allowed to open url https://downloads.birdo.app/x'));
    render(<UpdateRequired info={{ downloadUrl: 'https://downloads.birdo.app/x' }} />);
    await userEvent.click(screen.getByRole('button', { name: 'Download manually' }));
    await waitFor(() =>
      expect(useAppStore.getState().notice?.text).toBe(
        "Couldn't open your browser. Visit birdo.app to download the latest version.",
      ),
    );
    // Not one of the links the app has: kept out of `observed`.
    mockedOpenUrl.mockReset();
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

/**
 * MR-2015: the opener calls the tests above drive, per file (paths under
 * src/). A call site the tests do not drive is a link no test proves the
 * scope lets through.
 */
const DRIVEN_CALL_SITES: Record<string, number> = {
  'components/ConsentScreen.tsx': 2, // Terms, Privacy
  'components/Login.tsx': 1, // Forgot password
  'components/Settings.tsx': 3, // Privacy, Terms, Manage on web
  'components/UpdateRequired.tsx': 1, // Download manually (the 426 updateUrl)
  'screens/Pricing.tsx': 1, // Upgrade
  'screens/Profile.tsx': 1, // Manage Subscription
};

const SRC = resolve(import.meta.dirname, '..');

/** Every source file under src/, tests left out. */
function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const path = resolve(dir, entry.name);
    if (entry.isDirectory()) return entry.name === '__tests__' || entry.name === '__mocks__' ? [] : sourceFiles(path);
    return /\.(ts|tsx)$/.test(entry.name) && !/\.test\.(ts|tsx)$/.test(entry.name) ? [path] : [];
  });
}

/** The opener calls in `source`: each name it imports from the plugin, called. */
function openerCalls(source: string): number {
  const named = [...source.matchAll(/import\s*\{([^}]*)\}\s*from\s*['"]@tauri-apps\/plugin-opener['"]/g)];
  const names = named.flatMap((m) =>
    m[1]
      .split(',')
      .map((part) => part.trim().split(/\s+as\s+/).pop()?.trim() ?? '')
      .filter(Boolean),
  );
  const calls = names.reduce(
    (n, name) => n + (source.match(new RegExp(`\\b${name}\\(`, 'g'))?.length ?? 0),
    0,
  );
  // Any other way in (a namespace or default import, a dynamic import) is a
  // call site this count cannot see: counted as one so it fails.
  const other = source.match(/from\s*['"]@tauri-apps\/plugin-opener['"]|import\(\s*['"]@tauri-apps\/plugin-opener['"]\s*\)/g)?.length ?? 0;
  return calls + Math.max(0, other - named.length);
}

describe('MR-2015: every opener call site in the app is one a test above drives', () => {
  it('the opener calls counted in the source are exactly DRIVEN_CALL_SITES', () => {
    const found: Record<string, number> = {};
    for (const file of sourceFiles(SRC)) {
      const n = openerCalls(readFileSync(file, 'utf8'));
      if (n > 0) found[relative(SRC, file).replace(/\\/g, '/')] = n;
    }
    expect(found).toEqual(DRIVEN_CALL_SITES);
  });

  it('the counter sees aliased, plain, namespace and dynamic imports', () => {
    expect(openerCalls("import { openUrl } from '@tauri-apps/plugin-opener';\nopenUrl('a'); openUrl('b');")).toBe(2);
    expect(openerCalls("import { openUrl as go } from '@tauri-apps/plugin-opener';\ngo('a');")).toBe(1);
    expect(openerCalls("import * as opener from '@tauri-apps/plugin-opener';")).toBe(1);
    expect(openerCalls("const m = await import('@tauri-apps/plugin-opener');")).toBe(1);
    expect(openerCalls("import { openUrl } from '@tauri-apps/plugin-opener';")).toBe(0);
  });
});
