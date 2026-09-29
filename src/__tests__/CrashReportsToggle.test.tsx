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

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/plugin-shell', () => ({ open: vi.fn().mockResolvedValue(undefined) }));

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
  windowCorner: 'bottom-left',
  setWindowCorner: vi.fn(),
  pushRoute: vi.fn(),
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
  it('reads OFF by default and says what would be sent', async () => {
    render(<Settings />);
    const row = await screen.findByRole('switch', { name: /crash reports/i });
    expect(row).toHaveAttribute('aria-checked', 'false');
    expect(screen.getByText(/Off by default/)).toBeInTheDocument();
    // Second-pass #7: error reports are disclosed too, and nothing says "only".
    expect(screen.getByText(/crash and error reports/)).toBeInTheDocument();
    expect(screen.getByText(/No account details, IP address or browsing data/)).toBeInTheDocument();
    expect(screen.queryByText(/crash details/i)).not.toBeInTheDocument();
    // Applied live on the Rust side, so there is no restart note.
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
});

describe('Kill switch copy and the always-on toggle', () => {
  it('scopes the promise to while the app is running (no "never leaks")', async () => {
    const { container } = render(<Settings />);
    await screen.findByRole('switch', { name: /^kill switch/i });
    expect(
      screen.getByText(
        'If the tunnel drops unexpectedly, the app blocks traffic until it reconnects. Protection applies while the app is running.',
      ),
    ).toBeInTheDocument();
    expect(container.textContent ?? '').not.toMatch(/never leak|nothing leaves/i);
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
