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
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
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
      const { initial, animate, exit, ...rest } = props as Record<string, unknown>;
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

beforeEach(() => {
  mockedInvoke.mockReset();
  mockedInvoke.mockResolvedValue(undefined);
});

describe('Speed Test section', () => {
  it('renders the Run button', () => {
    render(<Settings />);
    expect(screen.getByText('Run')).toBeInTheDocument();
  });

  it('invokes run_speed_test_command when Run is clicked', async () => {
    mockedInvoke.mockResolvedValueOnce({
      downloadMbps: 95.3,
      uploadMbps: 42.1,
      latencyMs: 12,
      jitterMs: 3,
    });

    render(<Settings />);
    fireEvent.click(screen.getByText('Run'));

    await waitFor(() => {
      expect(mockedInvoke).toHaveBeenCalledWith('run_speed_test_command');
    });
  });

  it('disables button while speed test is running', async () => {
    // Never-resolving promise to keep the test "running"
    let resolve: (v: unknown) => void;
    mockedInvoke.mockReturnValueOnce(
      new Promise((r) => {
        resolve = r;
      })
    );

    render(<Settings />);
    const btn = screen.getByText('Run');
    fireEvent.click(btn);

    await waitFor(() => {
      expect(btn).toBeDisabled();
    });

    // Cleanup: resolve the dangling promise
    resolve!({
      downloadMbps: 0,
      uploadMbps: 0,
      latencyMs: 0,
      jitterMs: 0,
    });
  });

  it('displays results in download/upload/ping format', async () => {
    mockedInvoke.mockResolvedValueOnce({
      downloadMbps: 95.3,
      uploadMbps: 42.1,
      latencyMs: 12,
      jitterMs: 3,
    });

    render(<Settings />);
    fireEvent.click(screen.getByText('Run'));

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
    mockedInvoke.mockResolvedValueOnce({
      downloadMbps: 50.0,
      uploadMbps: 25.0,
      latencyMs: 20,
      jitterMs: 5,
    });

    render(<Settings />);
    const btn = screen.getByText('Run');
    fireEvent.click(btn);

    await waitFor(() => {
      expect(screen.getByText('Run')).not.toBeDisabled();
    });
  });

  it('re-enables button after speed test errors', async () => {
    mockedInvoke.mockRejectedValueOnce(new Error('Network error'));

    render(<Settings />);
    const btn = screen.getByText('Run');
    fireEvent.click(btn);

    await waitFor(() => {
      expect(screen.getByText('Run')).not.toBeDisabled();
    });
  });
});
