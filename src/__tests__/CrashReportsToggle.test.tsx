/**
 * Settings › Privacy › Crash reports (audit C-3 / D-12) and the kill-switch
 * rows' copy and lockdown toggle (D-7 / D-21).
 *
 * Crash reporting is opt-in: the row reads the persisted choice and writes it
 * through the dedicated `set_crash_reports_enabled` command, which applies it
 * live on the Rust side (no restart). The lockdown ("always-on") toggle is
 * Windows-only and persisted without a live reapply.
 *
 * Run: npx vitest run src/__tests__/CrashReportsToggle.test.tsx
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { Settings } from '@/components/Settings';
import { SETTINGS_UNVERIFIED_COPY } from '@/lib/errors';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/plugin-opener', () => ({ openUrl: vi.fn().mockResolvedValue(undefined) }));

function stripMotion(props: Record<string, unknown>) {
  const {
    initial: _i,
    animate: _a,
    exit: _e,
    transition: _t,
    whileHover: _h,
    whileTap: _p,
    ...rest
  } = props;
  return rest;
}
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: React.PropsWithChildren<Record<string, unknown>>) => (
      <div {...(stripMotion(props) as React.HTMLAttributes<HTMLDivElement>)}>{children}</div>
    ),
    button: ({ children, ...props }: React.PropsWithChildren<Record<string, unknown>>) => (
      <button {...(stripMotion(props) as React.ButtonHTMLAttributes<HTMLButtonElement>)}>
        {children}
      </button>
    ),
  },
  AnimatePresence: ({ children }: React.PropsWithChildren) => <>{children}</>,
}));

const updateSettings = vi.fn();
const mockStoreState = {
  connectionState: 'disconnected',
  settings: {
    killSwitchEnabled: true,
    autoConnect: false,
    autostart: false,
    startMinimized: false,
    notifications: true,
    showIpInNotification: false,
    showLocationInNotification: false,
    splitTunnelingEnabled: false,
    splitTunnelApps: [],
    customDns: null,
    protocol: 'wireguard',
    localNetworkSharing: false,
    wireGuardPort: 'auto',
    wireGuardMtu: 0,
    stealthMode: false,
    quantumProtection: true,
    preferredServerId: null,
    lockdownMode: true,
    crashReportsEnabled: false,
  },
  updateSettings,
  hydrateSettings: vi.fn(),
  showNotice: vi.fn(),
  // Loaded from Rust, so a landed save has nothing to mark (round 6, P3-4).
  settingsHydrated: true,
  windowCorner: 'bottom-left',
  setWindowCorner: vi.fn(),
  pushRoute: vi.fn(),
  // What the Custom DNS row reads (the server's per-plan flag, item 40).
  account: { plan: null },
  customDnsByPlan: {},
};

vi.mock('@/store/app-store', () => {
  const useAppStore = vi.fn((selector) => selector(mockStoreState));
  (useAppStore as unknown as { getState: () => typeof mockStoreState }).getState = () =>
    mockStoreState;
  return { useAppStore };
});
vi.mock('zustand/react/shallow', () => ({ useShallow: (fn: unknown) => fn }));

const mockedInvoke = vi.mocked(invoke);
const realUserAgent = navigator.userAgent;

function setUserAgent(ua: string) {
  Object.defineProperty(window.navigator, 'userAgent', { value: ua, configurable: true });
}

beforeEach(() => {
  mockedInvoke.mockReset();
  updateSettings.mockReset();
  mockStoreState.settings.crashReportsEnabled = false;
  mockStoreState.settings.killSwitchEnabled = true;
  mockedInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case 'get_app_version':
        return Promise.resolve('1.0.0');
      case 'check_biometric_available':
        return Promise.resolve({ available: false, enabled: false, method: 'none' });
      default:
        return Promise.resolve(undefined);
    }
  });
});

afterEach(() => setUserAgent(realUserAgent));

describe('Crash reports toggle', () => {
  // Owner, 2026-10-21: no description under a setting. What crash reports
  // send is disclosed where the choice is first made (ConsentScreen); the
  // Settings row is its title and its switch.
  it('reads OFF by default; the row is its title and switch, with no description', async () => {
    render(<Settings />);
    const row = await screen.findByRole('switch', { name: /crash reports/i });
    expect(row).toHaveAttribute('aria-checked', 'false');
    expect(row).toHaveTextContent(/^Crash Reports$/);
    expect(row).toHaveAccessibleDescription('');
    expect(screen.queryByText(/Off by default/)).not.toBeInTheDocument();
    expect(screen.queryByText(/crash and error reports/)).not.toBeInTheDocument();
    // Applied live on the Rust side, so there is no restart note either.
    expect(screen.queryByText(/restart/i)).not.toBeInTheDocument();
  });

  it('opting in goes through the dedicated command, not a full-object save', async () => {
    render(<Settings />);
    await userEvent.click(await screen.findByRole('switch', { name: /crash reports/i }));
    await waitFor(() => {
      expect(mockedInvoke).toHaveBeenCalledWith('set_crash_reports_enabled', { enabled: true });
    });
    expect(updateSettings).toHaveBeenCalledWith({ crashReportsEnabled: true });
    expect(mockedInvoke).not.toHaveBeenCalledWith('save_settings', expect.anything());
  });

  it('a failed write puts the row back', async () => {
    mockedInvoke.mockImplementation((cmd: string) =>
      cmd === 'set_crash_reports_enabled'
        ? Promise.reject(new Error('disk full'))
        : cmd === 'check_biometric_available'
          ? Promise.resolve({ available: false, enabled: false, method: 'none' })
          : Promise.resolve(undefined),
    );
    render(<Settings />);
    await userEvent.click(await screen.findByRole('switch', { name: /crash reports/i }));
    await waitFor(() => {
      expect(updateSettings).toHaveBeenLastCalledWith({ crashReportsEnabled: false });
    });
  });

  // MR-1516 (review of #364): a save that fails leaves reports OFF in Rust in
  // both directions (`write_crash_choice`), so a failed opt-OUT shows OFF too.
  // It used to put the switch back ON, a state Rust no longer had.
  it('a failed opt-out shows OFF, the state Rust has', async () => {
    mockStoreState.settings.crashReportsEnabled = true;
    mockedInvoke.mockImplementation((cmd: string) =>
      cmd === 'set_crash_reports_enabled'
        ? Promise.reject(new Error('disk full'))
        : cmd === 'check_biometric_available'
          ? Promise.resolve({ available: false, enabled: false, method: 'none' })
          : Promise.resolve(undefined),
    );
    render(<Settings />);
    await userEvent.click(await screen.findByRole('switch', { name: /crash reports/i }));
    await waitFor(() => {
      expect(mockedInvoke).toHaveBeenCalledWith('set_crash_reports_enabled', { enabled: false });
    });
    const crashWrites = () =>
      updateSettings.mock.calls.filter(([partial]) => 'crashReportsEnabled' in (partial as object));
    // The optimistic OFF, then OFF again once the save has failed.
    await waitFor(() => expect(crashWrites()).toHaveLength(2));
    expect(crashWrites()).toEqual([[{ crashReportsEnabled: false }], [{ crashReportsEnabled: false }]]);
  });
});

describe('a settings file that cannot be verified (review of #222, round 3)', () => {
  const unverified = {
    code: 'settings_unverified',
    message: 'the settings file could not be verified, so it was left as it is',
    retryable: true,
    retry_after_secs: null,
  };

  it.each([
    ['crash reports', /crash reports/i, 'set_crash_reports_enabled'],
    ['Launch at Login', /launch at login/i, 'set_autostart'],
  ])('%s say so and offer the reset, like every other setting', async (_label, name, command) => {
    mockStoreState.showNotice.mockClear();
    mockedInvoke.mockImplementation((cmd: string) =>
      cmd === command
        ? Promise.reject(unverified)
        : cmd === 'check_biometric_available'
          ? Promise.resolve({ available: false, enabled: false, method: 'none' })
          : Promise.resolve(undefined),
    );
    render(<Settings />);
    await userEvent.click(await screen.findByRole('switch', { name }));
    await waitFor(() => {
      expect(mockStoreState.showNotice).toHaveBeenCalledWith(
        expect.objectContaining({ text: SETTINGS_UNVERIFIED_COPY, actionLabel: 'Reset settings' }),
      );
    });
  });
});

describe('Kill switch row and the always-on toggle', () => {
  // Owner, 2026-10-21: no description under a setting. The kill switch row
  // used to carry the D-7 scope sentence and the give-up caveat; both went,
  // and the row promises nothing at all (still no "never leaks").
  it.each([
    ['Linux', 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'],
    ['Windows', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'],
  ])('%s: the row is its title and its switch, and promises nothing', async (_os, ua) => {
    setUserAgent(ua);
    const { container } = render(<Settings />);
    const row = await screen.findByRole('switch', { name: /^kill switch/i });
    expect(row).toHaveTextContent(/^Kill Switch$/);
    expect(row).toHaveAccessibleDescription('');
    expect(screen.queryByText(/blocks traffic until it reconnects/)).not.toBeInTheDocument();
    expect(screen.queryByText(/the app stops blocking/)).not.toBeInTheDocument();
    expect(container.textContent ?? '').not.toMatch(/never leak|nothing leaves|tells you/i);
  });

  it('offers the always-on toggle on Windows, persisted without a live reapply', async () => {
    setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36');
    render(<Settings />);
    const row = await screen.findByRole('switch', { name: /always-on kill switch/i });
    expect(row).toHaveAttribute('aria-checked', 'true');
    await userEvent.click(row);
    await waitFor(() => {
      expect(mockedInvoke).toHaveBeenCalledWith(
        'save_settings',
        expect.objectContaining({
          settings: expect.objectContaining({ lockdown_mode: false }),
        }),
      );
    });
    expect(mockedInvoke).not.toHaveBeenCalledWith('reapply_vpn_settings');
    expect(mockedInvoke).not.toHaveBeenCalledWith('set_killswitch_live', expect.anything());
  });

  it('hides the always-on toggle off Windows', async () => {
    setUserAgent('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36');
    render(<Settings />);
    await screen.findByRole('switch', { name: /^kill switch/i });
    expect(screen.queryByRole('switch', { name: /always-on kill switch/i })).not.toBeInTheDocument();
  });
});
