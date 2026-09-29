/**
 * Settings › Privacy › Crash reports (audit C-3 / D-12).
 *
 * Crash reporting is opt-in: the row reads the persisted choice and writes it
 * through the dedicated `set_crash_reports_enabled` command, which applies it
 * live on the Rust side (no restart).
 *
 * Run: npx vitest run src/__tests__/CrashReportsToggle.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
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

describe('Crash reports toggle', () => {
  it('reads OFF by default and says what would be sent', async () => {
    render(<Settings />);
    const row = await screen.findByRole('switch', { name: /crash reports/i });
    expect(row).toHaveAttribute('aria-checked', 'false');
    expect(screen.getByText(/Off by default/)).toBeInTheDocument();
    expect(screen.getByText(/No account details or browsing data/)).toBeInTheDocument();
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
