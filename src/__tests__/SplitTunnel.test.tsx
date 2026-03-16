/**
 * Split Tunnel section tests.
 *
 * Verifies the split-tunneling UI in Settings: toggling enabled state,
 * adding/removing apps, and invoking the Rust backend via save_settings.
 *
 * Run: npx vitest run src/__tests__/SplitTunnel.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { invoke } from '@tauri-apps/api/core';
import { Settings } from '@/components/Settings';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/api/app', () => ({
  getVersion: vi.fn().mockResolvedValue('1.0.0'),
}));

vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: React.PropsWithChildren<Record<string, unknown>>) => {
      const { initial, animate, exit, ...rest } = props as Record<string, unknown>;
      return <div {...(rest as React.HTMLAttributes<HTMLDivElement>)}>{children}</div>;
    },
  },
  AnimatePresence: ({ children }: React.PropsWithChildren) => <>{children}</>,
}));

const mockUpdateSettings = vi.fn();
let mockSettings = {
  killSwitchEnabled: false,
  autoConnect: false,
  autostart: false,
  startMinimized: false,
  notifications: true,
  splitTunnelingEnabled: false,
  splitTunnelApps: [] as string[],
  customDns: null,
  protocol: 'wireguard',
  localNetworkSharing: false,
  wireGuardPort: 'auto',
  wireGuardMtu: 0,
  stealthMode: true,
  quantumProtection: true,
  preferredServerId: null,
};

vi.mock('@/store/app-store', () => ({
  useAppStore: vi.fn((selector) =>
    selector({
      settings: mockSettings,
      updateSettings: mockUpdateSettings,
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
  mockUpdateSettings.mockReset();
  mockSettings = {
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
  };
});

describe('Split Tunneling section', () => {
  it('renders the split tunneling toggle', () => {
    render(<Settings />);
    expect(screen.getByText('Split Tunneling')).toBeInTheDocument();
    expect(
      screen.getByText('Exclude certain apps from VPN')
    ).toBeInTheDocument();
  });

  it('shows the app input when split tunneling is enabled', () => {
    mockSettings.splitTunnelingEnabled = true;
    render(<Settings />);
    expect(
      screen.getByPlaceholderText('e.g. chrome.exe')
    ).toBeInTheDocument();
  });

  it('adds a split tunnel app and calls save_settings', async () => {
    mockSettings.splitTunnelingEnabled = true;
    render(<Settings />);

    const input = screen.getByPlaceholderText('e.g. chrome.exe');
    fireEvent.change(input, { target: { value: 'firefox.exe' } });
    fireEvent.keyDown(input, { key: 'Enter' });

    await waitFor(() => {
      expect(mockUpdateSettings).toHaveBeenCalledWith({
        splitTunnelApps: ['firefox.exe'],
      });
    });

    await waitFor(() => {
      expect(mockedInvoke).toHaveBeenCalledWith(
        'save_settings',
        expect.objectContaining({
          settings: expect.objectContaining({
            split_tunnel_apps: ['firefox.exe'],
          }),
        })
      );
    });
  });

  it('removes a split tunnel app and calls save_settings', async () => {
    mockSettings.splitTunnelingEnabled = true;
    mockSettings.splitTunnelApps = ['chrome.exe', 'slack.exe'];
    render(<Settings />);

    const removeBtn = screen.getByLabelText('Remove chrome.exe');
    fireEvent.click(removeBtn);

    await waitFor(() => {
      expect(mockUpdateSettings).toHaveBeenCalledWith({
        splitTunnelApps: ['slack.exe'],
      });
    });

    await waitFor(() => {
      expect(mockedInvoke).toHaveBeenCalledWith(
        'save_settings',
        expect.objectContaining({
          settings: expect.objectContaining({
            split_tunnel_apps: ['slack.exe'],
          }),
        })
      );
    });
  });

  it('does not add duplicate apps', () => {
    mockSettings.splitTunnelingEnabled = true;
    mockSettings.splitTunnelApps = ['chrome.exe'];
    render(<Settings />);

    const input = screen.getByPlaceholderText('e.g. chrome.exe');
    fireEvent.change(input, { target: { value: 'chrome.exe' } });
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(mockUpdateSettings).not.toHaveBeenCalled();
  });

  it('does not add empty app names', () => {
    mockSettings.splitTunnelingEnabled = true;
    render(<Settings />);

    const input = screen.getByPlaceholderText('e.g. chrome.exe');
    fireEvent.change(input, { target: { value: '   ' } });
    fireEvent.keyDown(input, { key: 'Enter' });

    expect(mockUpdateSettings).not.toHaveBeenCalled();
  });

  it('displays existing split tunnel apps', () => {
    mockSettings.splitTunnelingEnabled = true;
    mockSettings.splitTunnelApps = ['chrome.exe', 'slack.exe'];
    render(<Settings />);

    expect(screen.getByText('chrome.exe')).toBeInTheDocument();
    expect(screen.getByText('slack.exe')).toBeInTheDocument();
  });
});
