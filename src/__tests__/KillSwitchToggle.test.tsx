/**
 * Kill-switch toggle → `set_killswitch_live` gate (OPEN-WORK F3).
 *
 * The Rust half (#64) lifts the block on every platform when it receives
 * `set_killswitch_live { enabled: false }`; the frontend gate was still
 * `connectionState === 'connected'`, so turning the kill switch OFF while the
 * tunnel was Reconnecting / Error / Rekeying — the only states in which the
 * reactive block is actually up — never reached Rust. These tests drive the
 * real Settings component (switch → confirm dialog → "Turn off") per state
 * and asserts whether the IPC was sent.
 *
 * Updated for the v2 connection states (contract WINDOWS-IPC-V2 §1):
 * `authenticating` / `stealth_connecting` folded into `connecting`, `rekeying`
 * and `kill_switch_active` never existed on the wire, and `switching` is new —
 * a live rebuild, treated like `connecting` for ON. Blocking is its own bit:
 * OFF must reach Rust even in `disconnected` when the always-on block is up.
 * The rule moved to session/settings-persist.ts with the shared write path,
 * and the confirm dialog uses the iOS/Android wording (P1-parity-031).
 *
 * Run: npx vitest run src/__tests__/KillSwitchToggle.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { Settings, KILL_SWITCH_DISABLE_BODY } from '@/components/Settings';
import {
  KILL_SWITCH_OFF_FAILED_COPY,
  KILL_SWITCH_OFF_THIS_CONNECTION_COPY,
  killSwitchLiveApplies,
  setKillSwitch,
} from '@/session/settings-persist';
import { SETTINGS_UNVERIFIED_COPY } from '@/lib/errors';
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
  showNotice: vi.fn(),
  killSwitchBlocking: false,
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
  // The server's per-plan Custom DNS flag (item 40): none, so enabled.
  customDnsByPlan: {},
};

vi.mock('@/store/app-store', () => {
  const useAppStore = vi.fn((selector) => selector(mockStoreState));
  (useAppStore as unknown as { getState: () => typeof mockStoreState }).getState = () =>
    mockStoreState;
  // The session-only OFF (round 4) waits for the next dial through this.
  (useAppStore as unknown as { subscribe: () => () => void }).subscribe = vi.fn(() => () => {});
  return { useAppStore };
});

vi.mock('zustand/react/shallow', () => ({
  useShallow: (fn: unknown) => fn,
}));

const mockedInvoke = vi.mocked(invoke);

beforeEach(() => {
  mockedInvoke.mockReset();
  mockStoreState.settings.killSwitchEnabled = true;
  mockStoreState.killSwitchBlocking = false;
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
  // Disabling asks for confirmation first, in the shared iOS/Android words.
  expect(await screen.findByText(KILL_SWITCH_DISABLE_BODY)).toBeInTheDocument();
  await userEvent.click(await screen.findByRole('button', { name: /turn off anyway/i }));
  await waitFor(() => {
    expect(mockedInvoke).toHaveBeenCalledWith('save_settings', expect.anything());
  });
}

const liveCalls = () =>
  mockedInvoke.mock.calls.filter(([cmd]) => cmd === 'set_killswitch_live');

/** An OFF goes out before its save and once more after it (round 4). */
const TWO_OFFS = [
  ['set_killswitch_live', { enabled: false }],
  ['set_killswitch_live', { enabled: false }],
];

const ALL_STATES: ConnectionState[] = [
  'disconnected',
  'connecting',
  'connected',
  'disconnecting',
  'reconnecting',
  'switching',
  'error',
];

describe('killSwitchLiveApplies', () => {
  it('OFF applies in every state that can be holding the block, and only skips the two with no session', () => {
    const applies = ALL_STATES.filter((s) => killSwitchLiveApplies(s, false));
    expect(applies).toEqual(['connecting', 'connected', 'reconnecting', 'switching', 'error']);
  });

  it('OFF while disconnected reaches Rust when the always-on block is up (the one case it must land)', () => {
    expect(killSwitchLiveApplies('disconnected', false, true)).toBe(true);
    expect(killSwitchLiveApplies('disconnected', false, false)).toBe(false);
    // ON never needs pushing with no session: the next dial arms it.
    expect(killSwitchLiveApplies('disconnected', true, true)).toBe(false);
  });

  it('ON additionally skips the pre-tunnel states, where arm() would block before VPN_SERVER_IP / the LUID exist', () => {
    const applies = ALL_STATES.filter((s) => killSwitchLiveApplies(s, true));
    expect(applies).toEqual(['connected', 'reconnecting', 'error']);
  });

  it.each<ConnectionState>(['connecting', 'switching'])(
    'ON during %s is persisted only while OFF still applies (the asymmetry is the point)',
    (state) => {
      expect(killSwitchLiveApplies(state, true)).toBe(false);
      expect(killSwitchLiveApplies(state, false)).toBe(true);
    },
  );
});

describe('Kill switch toggle → set_killswitch_live', () => {
  it.each<ConnectionState>(['reconnecting', 'error', 'switching'])(
    'OFF during %s reaches Rust (the block is up in exactly these states)',
    async (state) => {
      await turnKillSwitchOff(state);
      await waitFor(() => expect(liveCalls()).toEqual(TWO_OFFS));
    },
  );

  it('OFF while connected still reaches Rust (the pre-F3 behaviour is kept)', async () => {
    await turnKillSwitchOff('connected');
    await waitFor(() => {
      expect(mockedInvoke).toHaveBeenCalledWith('set_killswitch_live', { enabled: false });
    });
  });

  it('an ON persists before its live-apply, so arm() reads the new preference', async () => {
    mockStoreState.settings.killSwitchEnabled = false;
    mockStoreState.connectionState = 'connected';
    render(<Settings />);
    await userEvent.click(await screen.findByRole('switch', { name: /kill switch/i }));
    await waitFor(() => expect(liveCalls()).toHaveLength(1));
    const order = mockedInvoke.mock.calls.map(([cmd]) => cmd);
    expect(order.indexOf('save_settings')).toBeLessThan(order.indexOf('set_killswitch_live'));
  });

  // Round 4 of the review of #222 (P3-4): the OFF waited for its save — and
  // the save for a reapply in flight, up to REAPPLY_WAIT_MS — with the block
  // up all the while. It reads no file, so it goes out first.
  it('an OFF goes out without waiting for its save, and once more when the save lands', async () => {
    let landSave: () => void = () => {};
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation((cmd: string, args?: unknown) =>
      cmd === 'save_settings'
        ? new Promise<undefined>((resolve) => {
            landSave = () => resolve(undefined);
          })
        : base(cmd, args as never),
    );
    await turnKillSwitchOff('reconnecting');
    expect(liveCalls()).toEqual([['set_killswitch_live', { enabled: false }]]);
    const order = mockedInvoke.mock.calls.map(([cmd]) => cmd);
    expect(order.indexOf('set_killswitch_live')).toBeLessThan(order.indexOf('save_settings'));

    // A dial that finished before the save (a reapply's rebuild, say) armed
    // from the file that still said ON: the push after the save turns it off.
    landSave();
    await waitFor(() => expect(liveCalls()).toEqual(TWO_OFFS));
  });

  it('a newer choice stops an older OFF from pushing again after its save', async () => {
    let landSave: () => void = () => {};
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation((cmd: string, args?: unknown) =>
      cmd === 'save_settings' && !(args as { settings: { killswitch_enabled: boolean } }).settings.killswitch_enabled
        ? new Promise<undefined>((resolve) => {
            landSave = () => resolve(undefined);
          })
        : base(cmd, args as never),
    );
    mockStoreState.connectionState = 'connected';
    const off = setKillSwitch(false);
    await setKillSwitch(true);
    landSave();
    await off;
    expect(liveCalls()).toEqual([
      ['set_killswitch_live', { enabled: false }],
      ['set_killswitch_live', { enabled: true }],
    ]);
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

  it.each<ConnectionState>(['connecting', 'switching'])(
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
    await waitFor(() => expect(liveCalls()).toEqual(TWO_OFFS));
  });
});

describe('Kill switch OFF when something fails (review of #222, round 3)', () => {
  const unverified = {
    code: 'settings_unverified',
    message: 'the settings file could not be verified, so it was left as it is',
    retryable: true,
    retry_after_secs: null,
  };
  const failSave = () => {
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation((cmd: string, args?: unknown) =>
      cmd === 'save_settings' ? Promise.reject(unverified) : base(cmd, args as never),
    );
  };

  // Round 4 (P3-1): the notice says the OFF holds for this connection only,
  // and still offers the reset. The toggle itself: SettingsPersistence.test.
  it('a refused save still lets the OFF lift the block, and says it holds for this connection only', async () => {
    mockStoreState.showNotice.mockClear();
    failSave();
    await turnKillSwitchOff('reconnecting');
    await waitFor(() => {
      expect(mockStoreState.showNotice).toHaveBeenCalledWith(
        expect.objectContaining({
          text: KILL_SWITCH_OFF_THIS_CONNECTION_COPY,
          actionLabel: 'Reset settings',
        }),
      );
    });
    expect(liveCalls()).toEqual([['set_killswitch_live', { enabled: false }]]);
  });

  it('a refused OFF with no session to push to says why the setting did not stick', async () => {
    mockStoreState.showNotice.mockClear();
    failSave();
    await turnKillSwitchOff('disconnected');
    await waitFor(() => {
      expect(mockStoreState.showNotice).toHaveBeenCalledWith(
        expect.objectContaining({ text: SETTINGS_UNVERIFIED_COPY }),
      );
    });
    expect(liveCalls()).toHaveLength(0);
  });

  it('a refused save of an ON is not pushed', async () => {
    failSave();
    mockStoreState.settings.killSwitchEnabled = false;
    mockStoreState.connectionState = 'connected';
    render(<Settings />);
    await userEvent.click(await screen.findByRole('switch', { name: /kill switch/i }));
    await waitFor(() => {
      expect(mockedInvoke).toHaveBeenCalledWith('save_settings', expect.anything());
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(liveCalls()).toHaveLength(0);
  });

  it('an OFF that could not be applied says to disconnect, not to wait for the next connection', async () => {
    mockStoreState.showNotice.mockClear();
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation((cmd: string, args?: unknown) =>
      cmd === 'set_killswitch_live'
        ? Promise.reject({ code: 'killswitch_failed', message: 'x', retryable: true, retry_after_secs: null })
        : base(cmd, args as never),
    );
    await turnKillSwitchOff('reconnecting');
    await waitFor(() => {
      expect(mockStoreState.showNotice).toHaveBeenCalledWith(
        expect.objectContaining({ text: KILL_SWITCH_OFF_FAILED_COPY }),
      );
    });
  });
});
