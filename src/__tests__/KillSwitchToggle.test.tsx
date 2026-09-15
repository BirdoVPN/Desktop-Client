/**
 * Kill-switch toggle → `set_killswitch_live` gate (OPEN-WORK F3).
 *
 * The Rust half (#64) lifts the block on every platform when it receives
 * `set_killswitch_live { enabled: false }`; the frontend gate was still
 * `connectionState === 'connected'`, so turning the kill switch OFF while the
 * tunnel was Reconnecting / Error / Rekeying — the only states in which the
 * reactive block is actually up — never reached Rust. These tests drive the
 * real Settings component (switch → confirm dialog → "Turn off") per state
 * and assert whether the IPC was sent.
 *
 * Run: npx vitest run src/__tests__/KillSwitchToggle.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { Settings, killSwitchLiveApplies } from '@/components/Settings';
import type { ConnectionState } from '@/store/app-store';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/api/app', () => ({
  getVersion: vi.fn().mockResolvedValue('1.0.0'),
}));

// The confirm dialog is a motion.div and its buttons are BirdoButton =
// motion.button; strip the animation props and render plain elements.
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

// Mutable so each test can pick the connection state the toggle is flipped in.
const mockStoreState = {
  connectionState: 'connected' as ConnectionState,
  settings: {
    killSwitchEnabled: true,
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
    stealthMode: false,
    quantumProtection: false,
    preferredServerId: null,
  },
  updateSettings: vi.fn(),
  hydrateSettings: vi.fn(),
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
  portForwards: [],
  setPortForwards: vi.fn(),
  pushRoute: vi.fn(),
};

vi.mock('@/store/app-store', () => {
  const useAppStore = vi.fn((selector) => selector(mockStoreState));
  (useAppStore as unknown as { getState: () => typeof mockStoreState }).getState = () =>
    mockStoreState;
  return { useAppStore };
});

vi.mock('zustand/react/shallow', () => ({
  useShallow: (fn: unknown) => fn,
}));

const mockedInvoke = vi.mocked(invoke);

beforeEach(() => {
  mockedInvoke.mockReset();
  mockStoreState.settings.killSwitchEnabled = true;
  mockedInvoke.mockImplementation((cmd: string) => {
    switch (cmd) {
      case 'get_app_version':
        return Promise.resolve('1.0.0');
      case 'get_killswitch_status':
        return Promise.resolve({ enabled: true, active: false, blocking_connections: 0 });
      case 'check_biometric_available':
        return Promise.resolve({ available: false, enabled: false, method: 'none' });
      default:
        return Promise.resolve(undefined);
    }
  });
});

async function turnKillSwitchOff(state: ConnectionState) {
  mockStoreState.connectionState = state;
  render(<Settings />);
  const row = await screen.findByRole('switch', { name: /kill switch/i });
  await userEvent.click(row);
  // Disabling asks for confirmation first (mobile parity).
  await userEvent.click(await screen.findByRole('button', { name: /turn off/i }));
  // The persist is awaited BEFORE the live-apply (arm() re-reads the file).
  await waitFor(() => {
    expect(mockedInvoke).toHaveBeenCalledWith('save_settings', expect.anything());
  });
}

const liveCalls = () =>
  mockedInvoke.mock.calls.filter(([cmd]) => cmd === 'set_killswitch_live');

const ALL_STATES: ConnectionState[] = [
  'disconnected',
  'connecting',
  'authenticating',
  'stealth_connecting',
  'connected',
  'disconnecting',
  'reconnecting',
  'rekeying',
  'kill_switch_active',
  'error',
];

describe('killSwitchLiveApplies', () => {
  it('OFF applies in every state that can be holding the block, and only skips the two with no session', () => {
    const applies = ALL_STATES.filter((s) => killSwitchLiveApplies(s, false));
    expect(applies).toEqual([
      'connecting',
      'authenticating',
      'stealth_connecting',
      'connected',
      'reconnecting',
      'rekeying',
      'kill_switch_active',
      'error',
    ]);
  });

  it('ON additionally skips the pre-tunnel states, where arm() would block before VPN_SERVER_IP / the LUID exist', () => {
    const applies = ALL_STATES.filter((s) => killSwitchLiveApplies(s, true));
    expect(applies).toEqual(['connected', 'reconnecting', 'rekeying', 'kill_switch_active', 'error']);
  });

  it.each<ConnectionState>(['connecting', 'authenticating', 'stealth_connecting'])(
    'ON during %s is persisted only while OFF still applies (the asymmetry is the point)',
    (state) => {
      expect(killSwitchLiveApplies(state, true)).toBe(false);
      expect(killSwitchLiveApplies(state, false)).toBe(true);
    },
  );
});

describe('Kill switch toggle → set_killswitch_live', () => {
  it.each<ConnectionState>(['reconnecting', 'error', 'rekeying'])(
    'OFF during %s reaches Rust (the block is up in exactly these states)',
    async (state) => {
      await turnKillSwitchOff(state);
      await waitFor(() => {
        expect(mockedInvoke).toHaveBeenCalledWith('set_killswitch_live', { enabled: false });
      });
      expect(liveCalls()).toHaveLength(1);
    },
  );

  it('OFF while connected still reaches Rust (the pre-F3 behaviour is kept)', async () => {
    await turnKillSwitchOff('connected');
    await waitFor(() => {
      expect(mockedInvoke).toHaveBeenCalledWith('set_killswitch_live', { enabled: false });
    });
  });

  it('persists before the live-apply, so arm()/set_killswitch_live read the new preference', async () => {
    await turnKillSwitchOff('reconnecting');
    await waitFor(() => expect(liveCalls()).toHaveLength(1));
    const order = mockedInvoke.mock.calls.map(([cmd]) => cmd);
    expect(order.indexOf('save_settings')).toBeLessThan(order.indexOf('set_killswitch_live'));
  });

  it.each<ConnectionState>(['disconnected', 'disconnecting'])(
    'OFF while %s is persisted only (no session to soften)',
    async (state) => {
      await turnKillSwitchOff(state);
      // Let any stray microtask-scheduled invoke land before asserting absence.
      await new Promise((r) => setTimeout(r, 0));
      expect(liveCalls()).toHaveLength(0);
    },
  );

  it('ON during reconnecting reaches Rust too (arm for the live session)', async () => {
    mockStoreState.settings.killSwitchEnabled = false;
    mockStoreState.connectionState = 'reconnecting';
    render(<Settings />);
    await userEvent.click(await screen.findByRole('switch', { name: /kill switch/i }));
    await waitFor(() => {
      expect(mockedInvoke).toHaveBeenCalledWith('set_killswitch_live', { enabled: true });
    });
  });

  it.each<ConnectionState>(['connecting', 'authenticating', 'stealth_connecting'])(
    'ON during %s is persisted only (arm() before the tunnel exists would block-all with no relay permit)',
    async (state) => {
      mockStoreState.settings.killSwitchEnabled = false;
      mockStoreState.connectionState = state;
      render(<Settings />);
      await userEvent.click(await screen.findByRole('switch', { name: /kill switch/i }));
      await waitFor(() => {
        expect(mockedInvoke).toHaveBeenCalledWith('save_settings', expect.anything());
      });
      await new Promise((r) => setTimeout(r, 0));
      expect(liveCalls()).toHaveLength(0);
    },
  );

  it('OFF during connecting still reaches Rust (the narrowing is ON-only)', async () => {
    await turnKillSwitchOff('connecting');
    await waitFor(() => {
      expect(mockedInvoke).toHaveBeenCalledWith('set_killswitch_live', { enabled: false });
    });
    expect(liveCalls()).toHaveLength(1);
  });
});
