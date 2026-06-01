/**
 * Speed Test section tests.
 *
 * Verifies that the Settings component's speed-test UI correctly
 * invokes the Rust backend, disables the button while running,
 * and renders results in the expected format.
 *
 * Run: npx vitest run src/__tests__/SpeedTest.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { Settings } from '@/components/Settings';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/api/app', () => ({
  getVersion: vi.fn().mockResolvedValue('1.0.0'),
}));

// Mock framer-motion to avoid animation issues in tests
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: React.PropsWithChildren<Record<string, unknown>>) => {
      const { initial: _initial, animate: _animate, exit: _exit, ...rest } = props as Record<string, unknown>;
      return <div {...(rest as React.HTMLAttributes<HTMLDivElement>)}>{children}</div>;
    },
  },
  AnimatePresence: ({ children }: React.PropsWithChildren) => <>{children}</>,
}));

// Mock zustand store
vi.mock('@/store/app-store', () => ({
  useAppStore: vi.fn((selector) =>
    selector({
      settings: {
        killSwitchEnabled: false,
        autoConnect: false,
        autostart: false,
        startMinimized: false,
        notifications: true,
        splitTunnelingEnabled: false,
        splitTunnelApps: [],
        customDns: null,
        protocol: 'wireguard',
        localNetworkSharing: false,
        wireGuardPort: 'auto',
        wireGuardMtu: 0,
        stealthMode: true,
        quantumProtection: true,
        preferredServerId: null,
      },
      updateSettings: vi.fn(),
      account: {
        email: 'test@birdo.app',
        plan: 'operative',
        accountId: 'acct_test',
        maxDevices: 5,
        activeDevices: 1,
        expiresAt: null,
        bandwidthUsed: 0,
        bandwidthLimit: 0,
        status: 'active',
      },
      servers: [],
      multiHopRoutes: [],
      setMultiHopRoutes: vi.fn(),
      portForwards: [],
      setPortForwards: vi.fn(),
      theme: 'system',
      setTheme: vi.fn(),
    })
  ),
}));

vi.mock('zustand/react/shallow', () => ({
  useShallow: (fn: unknown) => fn,
}));

const mockedInvoke = vi.mocked(invoke);

// The Settings screen is now a single scrollable list (no tabs); the Speed
// Test section's "Run" button is rendered directly.
async function renderToolsTab() {
  await act(async () => {
    render(<Settings />);
    await Promise.resolve();
    await Promise.resolve();
  });
  await waitFor(() => {
    expect(screen.getByText('Run')).toBeInTheDocument();
  });
}

// The rebuilt Settings fires several commands on mount (get_settings,
// get_app_version, get_killswitch_status, check_biometric_available). Route by
// command name so the speed-test result isn't swallowed by a mount call, and
// let each test override only run_speed_test_command via `speedTestImpl`.
let speedTestImpl: () => Promise<unknown> = () =>
  Promise.resolve({ downloadMbps: 0, uploadMbps: 0, latencyMs: 0 });

beforeEach(() => {
  mockedInvoke.mockReset();
  speedTestImpl = () => Promise.resolve({ downloadMbps: 0, uploadMbps: 0, latencyMs: 0 });
  mockedInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case 'run_speed_test_command':
        return speedTestImpl();
      case 'get_app_version':
        return Promise.resolve('1.0.0');
      case 'get_killswitch_status':
        return Promise.resolve({ enabled: false, active: false, blocking_connections: 0 });
      case 'check_biometric_available':
        return Promise.resolve({ available: false, enabled: false, method: 'none' });
      default:
        return Promise.resolve(undefined);
    }
  });
});

describe('Speed Test section', () => {
  it('renders the Run button', async () => {
    await renderToolsTab();
    expect(screen.getByText('Run')).toBeInTheDocument();
  });

  it('invokes run_speed_test_command when Run is clicked', async () => {
    speedTestImpl = () =>
      Promise.resolve({ downloadMbps: 95.3, uploadMbps: 42.1, latencyMs: 12 });

    await renderToolsTab();
    await act(async () => {
      await userEvent.click(screen.getByText('Run'));
      await Promise.resolve();
    });

    await waitFor(() => {
      expect(mockedInvoke).toHaveBeenCalledWith('run_speed_test_command');
    });
  });

  it('disables button while speed test is running', async () => {
    // Pending promise to keep the test "running"; the button label swaps to
    // "Running…" and the element gains the disabled attribute.
    let resolve: (v: unknown) => void;
    speedTestImpl = () => new Promise((r) => { resolve = r; });

    await renderToolsTab();
    const btn = screen.getByText('Run');
    await act(async () => {
      await userEvent.click(btn);
    });

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /running/i })).toBeDisabled();
    });

    // Cleanup: resolve the dangling promise
    await act(async () => {
      resolve!({ downloadMbps: 0, uploadMbps: 0, latencyMs: 0 });
      await Promise.resolve();
    });
  });

  it('displays results in download/upload/ping format', async () => {
    speedTestImpl = () =>
      Promise.resolve({ downloadMbps: 95.3, uploadMbps: 42.1, latencyMs: 12 });

    await renderToolsTab();
    await act(async () => {
      await userEvent.click(screen.getByText('Run'));
      await Promise.resolve();
    });

    await waitFor(() => {
      expect(
        screen.getByText((content) =>
          content.includes('95.3') &&
          content.includes('42.1') &&
          content.includes('12ms')
        )
      ).toBeInTheDocument();
    });
  });

  it('re-enables button after speed test completes', async () => {
    speedTestImpl = () =>
      Promise.resolve({ downloadMbps: 50.0, uploadMbps: 25.0, latencyMs: 20 });

    await renderToolsTab();
    await act(async () => {
      await userEvent.click(screen.getByText('Run'));
      await Promise.resolve();
    });

    await waitFor(() => {
      expect(screen.getByText('Run')).not.toBeDisabled();
    });
  });

  it('re-enables button after speed test errors', async () => {
    speedTestImpl = () => Promise.reject(new Error('Network error'));

    await renderToolsTab();
    await act(async () => {
      await userEvent.click(screen.getByText('Run'));
      await Promise.resolve();
    });

    await waitFor(() => {
      expect(screen.getByText('Run')).not.toBeDisabled();
    });
  });
});
