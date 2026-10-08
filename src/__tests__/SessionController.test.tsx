/**
 * The session controller (W2-001, W2-002, W2-003, W2-006, W2-009).
 *
 * Everything that watches or drives the VPN used to live in Dashboard, which
 * unmounts on every tab switch and under the biometric cover and the update
 * wall. These tests drive the REAL controller against a scripted Rust side
 * (invoke + emitted events) and the real store:
 *
 *  - Rust pushes `vpn-status-changed`; a slower `get_vpn_status` resync that
 *    read an OLDER state (lower `seq`) must never undo it;
 *  - with no events at all, the low-rate resync still catches up;
 *  - `session-expired` (and a command failing with `session_expired`) routes
 *    to Login with a reason;
 *  - tray Disconnect acts in `reconnecting` (it used to act only in
 *    `connected`), tray Quick Connect dials the user's own server;
 *  - Auto-Connect runs once per session, to the user's server;
 *  - and the controller keeps working under the biometric cover (App-level).
 *
 * Run: npx vitest run src/__tests__/SessionController.test.tsx
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, waitFor, act, screen } from '@testing-library/react';
import { invoke } from '@tauri-apps/api/core';
import { VpnSessionController, RESYNC_INTERVAL_MS } from '@/session/controller';
import { useAppStore, defaultSettings, type Server } from '@/store/app-store';
import { resetSessionData } from '@/session/session-data';
import { signOut } from '@/session/session';
import {
  forgetKillSwitchChoices,
  KILL_SWITCH_OFF_THIS_CONNECTION_COPY,
  persistSettings,
  setKillSwitch,
} from '@/session/settings-persist';
import { CONSENT_VERSION } from '@/lib/consent';

vi.mock('@tauri-apps/api/core');

// A scripted Tauri event bus: the test emits exactly what Rust would.
const handlers = new Map<string, Set<(e: { payload: unknown }) => void>>();
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async (name: string, cb: (e: { payload: unknown }) => void) => {
    if (!handlers.has(name)) handlers.set(name, new Set());
    handlers.get(name)!.add(cb);
    return () => handlers.get(name)?.delete(cb);
  }),
}));
function emit(name: string, payload?: unknown) {
  act(() => {
    handlers.get(name)?.forEach((cb) => cb({ payload }));
  });
}

const sendNotification = vi.fn();
vi.mock('@tauri-apps/plugin-notification', () => ({
  isPermissionGranted: vi.fn().mockResolvedValue(true),
  requestPermission: vi.fn().mockResolvedValue('granted'),
  sendNotification: (...args: unknown[]) => sendNotification(...args),
}));

const mockedInvoke = vi.mocked(invoke);

const server = (id: string, load: number, extra: Partial<Server> = {}) => ({
  id,
  name: `Node ${id}`,
  country: 'Germany',
  countryCode: 'DE',
  city: 'Frankfurt',
  load,
  isOnline: true,
  accessible: true,
  ...extra,
});

/** What `get_vpn_status` answers; tests reassign it. */
let status: Record<string, unknown>;
let rustSettings: Record<string, unknown>;
let servers: unknown[];

beforeEach(() => {
  handlers.clear();
  sendNotification.mockClear();
  resetSessionData();
  useAppStore.getState().logout();
  useAppStore.setState({
    isAuthenticated: true,
    sessionEndedReason: null,
    statusSeq: -1,
    settings: { ...defaultSettings, notifications: true },
    settingsHydrated: false,
    lastServerId: null,
  });
  status = { state: 'disconnected', seq: 1, kill_switch_blocking: false, error: null };
  rustSettings = { auto_connect: false, killswitch_enabled: true, lockdown_mode: true };
  servers = [server('a', 50), server('b', 10), server('c', 30)];
  mockedInvoke.mockReset();
  mockedInvoke.mockImplementation(async (cmd: string) => {
    switch (cmd) {
      case 'get_vpn_status':
        return status;
      case 'get_vpn_stats':
        return { bytes_in: 0, bytes_out: 0, uptime_seconds: 0, current_latency_ms: null };
      case 'get_settings':
        return rustSettings;
      case 'get_servers':
        return servers;
      case 'get_subscription_status':
        return { plan: 'OPERATIVE', status: 'active' };
      case 'get_admin_status':
        return true;
      default:
        return undefined;
    }
  });
});

afterEach(() => {
  vi.useRealTimers();
});

const callsTo = (cmd: string) => mockedInvoke.mock.calls.filter(([c]) => c === cmd);

describe('status sync: Rust events first, resync as the fallback', () => {
  it('applies a pushed status and ignores an older resync that arrives after it (W2-009)', async () => {
    render(<VpnSessionController />);
    await waitFor(() => expect(useAppStore.getState().statusSeq).toBe(1));

    emit('vpn-status-changed', { state: 'connected', seq: 5, kill_switch_blocking: false, error: null });
    expect(useAppStore.getState().connectionState).toBe('connected');

    // A resync whose read happened before that change (seq 4) lands late.
    status = { state: 'connecting', seq: 4, kill_switch_blocking: false, error: null };
    emit('app-shown');
    await waitFor(() => expect(callsTo('get_vpn_status').length).toBeGreaterThanOrEqual(2));
    await act(async () => {});
    expect(useAppStore.getState().connectionState).toBe('connected');
    expect(useAppStore.getState().statusSeq).toBe(5);
  });

  it('with no events at all, the periodic resync still catches up', async () => {
    vi.useFakeTimers();
    render(<VpnSessionController />);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(useAppStore.getState().connectionState).toBe('disconnected');

    status = { state: 'reconnecting', seq: 2, kill_switch_blocking: true, error: null };
    await act(async () => {
      await vi.advanceTimersByTimeAsync(RESYNC_INTERVAL_MS);
    });
    expect(useAppStore.getState().connectionState).toBe('reconnecting');
    expect(useAppStore.getState().killSwitchBlocking).toBe(true);
  });

  it('notifies from Rust transitions with no Connect screen mounted (the tray-resident case)', async () => {
    render(<VpnSessionController />);
    await waitFor(() => expect(useAppStore.getState().statusSeq).toBe(1));
    emit('vpn-status-changed', { state: 'connected', seq: 2, server_id: 'b', error: null });
    emit('vpn-status-changed', { state: 'reconnecting', seq: 3, server_id: 'b', error: null });
    await waitFor(() =>
      expect(sendNotification).toHaveBeenCalledWith(
        expect.objectContaining({ title: 'BirdoVPN — Reconnecting…' }),
      ),
    );
  });
});

describe('give-up (REVIEW-WIN-009)', () => {
  it('a give-up that reaches the UI as connected → error still says reconnecting stopped', async () => {
    render(<VpnSessionController />);
    await waitFor(() => expect(useAppStore.getState().statusSeq).toBe(1));
    emit('vpn-status-changed', { state: 'connected', seq: 2, server_id: 'b', error: null });
    // The breaker trip's `reconnecting` (seq 3) was coalesced away.
    emit('vpn-status-changed', {
      state: 'error',
      seq: 4,
      gaveUp: { attempts: 0 },
      error: { code: 'adapter_failed', message: '', retryable: true, retry_after_secs: null },
    });
    await waitFor(() =>
      expect(sendNotification).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'BirdoVPN — Connection error',
          body: expect.stringContaining('BirdoVPN stopped reconnecting'),
        }),
      ),
    );
  });
});

describe('session expiry (W2-006, contract §3.3)', () => {
  it('the session-expired event routes to Login and says why', async () => {
    render(<VpnSessionController />);
    emit('session-expired', { reason: 'revoked' });
    expect(useAppStore.getState().isAuthenticated).toBe(false);
    expect(useAppStore.getState().sessionEndedReason).toBe('revoked');
  });

  it('a command rejecting with session_expired does the same', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'get_subscription_status') {
        throw { code: 'session_expired', message: 'Refresh rejected', retryable: false, retry_after_secs: null };
      }
      if (cmd === 'get_vpn_status') return status;
      return undefined;
    });
    render(<VpnSessionController />);
    await waitFor(() => expect(useAppStore.getState().isAuthenticated).toBe(false));
    expect(useAppStore.getState().sessionEndedReason).toBe('expired');
    // REVIEW-WIN-012: and Rust is told, so no tunnel or reconnect loop
    // outlives the session behind the Login screen. Once, however many
    // commands fail the same way.
    expect(callsTo('end_expired_session')).toHaveLength(1);
  });

  it('the session-expired EVENT does not echo back to Rust (Rust already ended it)', async () => {
    render(<VpnSessionController />);
    emit('session-expired', { reason: 'expired' });
    expect(useAppStore.getState().isAuthenticated).toBe(false);
    expect(callsTo('end_expired_session')).toHaveLength(0);
  });
});

describe('tray actions run in Rust (W1-023, W2-003)', () => {
  // Rust performs tray Quick Connect / Disconnect itself so they work with the
  // window hidden; the events are notifications only. Acting on them here as
  // well dialled twice (a wasted key and /vpn/connect per click).
  it('does not act on tray events, in any state', async () => {
    useAppStore.setState({ lastServerId: 'c' });
    render(<VpnSessionController />);
    await waitFor(() => expect(useAppStore.getState().serversStatus).toBe('ready'));
    emit('vpn-status-changed', { state: 'reconnecting', seq: 9, kill_switch_blocking: true, error: null });
    emit('tray-disconnect');
    emit('vpn-status-changed', { state: 'error', seq: 10, error: { code: 'server_unreachable', message: '' } });
    emit('tray-quick-connect');
    await new Promise((r) => setTimeout(r, 50));
    expect(callsTo('disconnect_vpn')).toHaveLength(0);
    expect(callsTo('connect_vpn')).toHaveLength(0);
    expect(callsTo('quick_connect')).toHaveLength(0);
  });

  it("mirrors the user's server into preferred_server_id so the tray dials it", async () => {
    useAppStore.setState({ lastServerId: 'c' });
    render(<VpnSessionController />);
    await waitFor(() =>
      expect(callsTo('save_settings').some(([, a]) =>
        (a as { settings: { preferred_server_id: string | null } }).settings.preferred_server_id === 'c')).toBe(true),
    );
  });

  it("never writes settings before Rust's copy has loaded (it would replace them with defaults)", async () => {
    let releaseSettings: (v: unknown) => void = () => {};
    const settingsLoaded = new Promise((r) => { releaseSettings = r; });
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd, args) => {
      if (cmd === 'get_settings') { await settingsLoaded; return rustSettings; }
      return base(cmd, args);
    });
    useAppStore.setState({ lastServerId: 'c' });
    render(<VpnSessionController />);
    await new Promise((r) => setTimeout(r, 50));
    expect(callsTo('save_settings')).toHaveLength(0);
    releaseSettings(undefined);
    await waitFor(() => expect(callsTo('save_settings').length).toBeGreaterThan(0));
  });

  it("the next account's session waits for its own settings before mirroring (REVIEW-WIN-007)", async () => {
    // Session one was hydrated; signing out must not carry that over.
    useAppStore.setState({ settingsHydrated: true, lastServerId: 'c' });
    useAppStore.getState().logout();
    useAppStore.setState({ isAuthenticated: true });

    let releaseSettings: (v: unknown) => void = () => {};
    const settingsLoaded = new Promise((r) => { releaseSettings = r; });
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd, args) => {
      if (cmd === 'get_settings') { await settingsLoaded; return rustSettings; }
      return base(cmd, args);
    });
    // The new user picks a server before their settings have loaded.
    useAppStore.setState({ lastServerId: 'a' });
    render(<VpnSessionController />);
    await new Promise((r) => setTimeout(r, 50));
    expect(callsTo('save_settings')).toHaveLength(0);
    releaseSettings(undefined);
    await waitFor(() =>
      expect(callsTo('save_settings').some(([, a]) =>
        (a as { settings: { preferred_server_id: string | null } }).settings.preferred_server_id === 'a')).toBe(true),
    );
  });

  it('does not rewrite settings when Rust already has the same server', async () => {
    rustSettings = { ...rustSettings, preferred_server_id: 'c' };
    useAppStore.setState({ lastServerId: 'c' });
    render(<VpnSessionController />);
    await waitFor(() => expect(useAppStore.getState().settingsHydrated).toBe(true));
    await new Promise((r) => setTimeout(r, 50));
    expect(callsTo('save_settings')).toHaveLength(0);
  });
});

describe('Auto-Connect (W2-002)', () => {
  it('connects once per session, to the user\'s server rather than the least-loaded node', async () => {
    rustSettings = { ...rustSettings, auto_connect: true };
    useAppStore.setState({ lastServerId: 'a' });
    const { rerender } = render(<VpnSessionController />);
    await waitFor(() => expect(callsTo('connect_vpn')).toEqual([['connect_vpn', { serverId: 'a' }]]));
    expect(callsTo('quick_connect')).toHaveLength(0);

    // The tunnel drops back to disconnected and the app re-renders (the old
    // Dashboard re-ran auto-connect on every return to the Connect tab).
    emit('vpn-status-changed', { state: 'disconnected', seq: 50, error: null });
    rerender(<VpnSessionController />);
    await act(async () => {});
    expect(callsTo('connect_vpn')).toHaveLength(1);
  });

  it('without a remembered server, picks the fastest (lowest load), the Rust/iOS rule', async () => {
    rustSettings = { ...rustSettings, auto_connect: true };
    render(<VpnSessionController />);
    await waitFor(() => expect(callsTo('connect_vpn')).toEqual([['connect_vpn', { serverId: 'b' }]]));
  });

  // Round 7 (N3): a start-up that could not verify the file leaves the
  // settings unloaded; a save that lands later marks them loaded (24dc7f2).
  // By then the user may have connected and disconnected on purpose.
  it('a mid-run load of the settings never auto-connects after a connect or a disconnect (round 7, N3)', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      switch (cmd) {
        case 'get_vpn_status':
          return status;
        case 'get_settings':
          throw { code: 'settings_unverified', message: 'unverified', retryable: true, retry_after_secs: null };
        case 'get_servers':
          return servers;
        default:
          return undefined;
      }
    });
    useAppStore.setState({ settings: { ...defaultSettings, autoConnect: true } });
    render(<VpnSessionController />);
    await waitFor(() => expect(useAppStore.getState().serversStatus).toBe('ready'));
    expect(useAppStore.getState().settingsHydrated).toBe(false);
    emit('vpn-status-changed', { state: 'connected', seq: 10, error: null });
    emit('vpn-status-changed', { state: 'disconnected', seq: 11, error: null });
    await act(async () => {});
    act(() => useAppStore.setState({ settingsHydrated: true }));
    await act(async () => {});
    expect(callsTo('connect_vpn')).toHaveLength(0);
    expect(callsTo('quick_connect')).toHaveLength(0);
  });

  it('stays off when the setting is off', async () => {
    render(<VpnSessionController />);
    await waitFor(() => expect(useAppStore.getState().serversStatus).toBe('ready'));
    await act(async () => {});
    expect(callsTo('connect_vpn')).toHaveLength(0);
    expect(callsTo('quick_connect')).toHaveLength(0);
  });
});

describe("sign-out ends the session's kill switch choices (follow-up 3 to the review of #222)", () => {
  it("a same-run sign-in shows the saved kill switch, not the last session's this-connection OFF", async () => {
    forgetKillSwitchChoices();
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd, args) => {
      // The file cannot be verified: an OFF holds for this connection only.
      if (cmd === 'save_settings') {
        throw {
          code: 'settings_unverified',
          message: 'the settings file could not be verified, so it was left as it is',
          retryable: true,
          retry_after_secs: null,
        };
      }
      return base(cmd, args);
    });
    // Mounted the way App mounts it: for as long as someone is signed in.
    function SignedIn() {
      return useAppStore((s) => s.isAuthenticated) ? <VpnSessionController /> : null;
    }
    render(<SignedIn />);
    await waitFor(() => expect(useAppStore.getState().statusSeq).toBe(1));
    await waitFor(() => expect(useAppStore.getState().settingsHydrated).toBe(true));
    act(() => useAppStore.setState({ connectionState: 'connected' }));
    await act(async () => {
      await setKillSwitch(false);
    });
    expect(useAppStore.getState().notice?.text).toBe(KILL_SWITCH_OFF_THIS_CONNECTION_COPY);
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);

    await act(async () => {
      await signOut();
    });
    expect(useAppStore.getState().isAuthenticated).toBe(false);
    // Signed in again in the same run: the settings are re-read, and the
    // file says ON. There is no connection for an OFF to be off for.
    act(() => useAppStore.setState({ isAuthenticated: true }));
    await waitFor(() => expect(callsTo('get_settings')).toHaveLength(2));
    await waitFor(() => expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true));
  });

  // Review of #255, L2: an OFF still in flight at sign-out, whose save is
  // refused only after the next session has re-read the settings. It was
  // still the latest choice, so it put that session's toggle OFF over the
  // saved ON, and the next save of anything wrote the OFF into the file.
  it('an OFF still in flight at sign-out writes nothing into the next session when its refusal lands', async () => {
    forgetKillSwitchChoices();
    let refuseSave: () => void = () => {};
    let held = true;
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd, args) => {
      if (cmd === 'save_settings' && held) {
        held = false;
        return new Promise((_, reject) => {
          refuseSave = () =>
            reject({
              code: 'settings_unverified',
              message: 'the settings file could not be verified, so it was left as it is',
              retryable: true,
              retry_after_secs: null,
            });
        });
      }
      return base(cmd, args);
    });
    function SignedIn() {
      return useAppStore((s) => s.isAuthenticated) ? <VpnSessionController /> : null;
    }
    render(<SignedIn />);
    await waitFor(() => expect(useAppStore.getState().statusSeq).toBe(1));
    await waitFor(() => expect(useAppStore.getState().settingsHydrated).toBe(true));
    act(() => useAppStore.setState({ connectionState: 'connected' }));
    let off: Promise<void> = Promise.resolve();
    await act(async () => {
      off = setKillSwitch(false);
    });
    expect(callsTo('save_settings')).toHaveLength(1);

    await act(async () => {
      await signOut();
    });
    act(() => useAppStore.setState({ isAuthenticated: true }));
    await waitFor(() => expect(callsTo('get_settings')).toHaveLength(2));
    await waitFor(() => expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true));

    await act(async () => {
      refuseSave();
      await off;
    });
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true);
    expect(useAppStore.getState().notice?.text).not.toBe(KILL_SWITCH_OFF_THIS_CONNECTION_COPY);
    // The next save of anything writes the file's ON, not the last session's OFF.
    await act(async () => {
      expect(await persistSettings({ autoConnect: true })).toBe(true);
    });
    const saved = callsTo('save_settings').map(([, a]) => (a as { settings: Record<string, unknown> }).settings);
    expect(saved).toHaveLength(2);
    expect(saved[1]).toMatchObject({ killswitch_enabled: true, auto_connect: true });
  });
});

describe('session data is loaded once, not per tab visit (W2-023)', () => {
  it('fetches servers once and writes pings once per batch of five', async () => {
    servers = Array.from({ length: 7 }, (_, i) => server(`s${i}`, i, { hostname: `h${i}.example` }));
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'get_servers') return servers;
      if (cmd === 'ping_server') return 42;
      if (cmd === 'get_vpn_status') return status;
      return undefined;
    });
    const merge = vi.spyOn(useAppStore.getState(), 'mergeServerPings');
    render(<VpnSessionController />);
    await waitFor(() => expect(Object.keys(useAppStore.getState().serverPings)).toHaveLength(7));
    expect(callsTo('get_servers')).toHaveLength(1);
    expect(merge).toHaveBeenCalledTimes(2); // ceil(7 / 5)
  });
});

describe('App: the controller runs under the biometric cover (W2-001, W2-026)', () => {
  it('keeps tracking the tunnel while the app is locked', async () => {
    vi.doMock('@tauri-apps/api/window', () => ({
      getCurrentWindow: () => ({
        isVisible: async () => false,
        onScaleChanged: async () => () => {},
        setDecorations: async () => {},
        setSize: async () => {},
        setPosition: async () => {},
        minimize: async () => {},
        close: async () => {},
      }),
      currentMonitor: async () => null,
      primaryMonitor: async () => null,
    }));
    vi.doMock('@tauri-apps/plugin-process', () => ({ exit: vi.fn(), relaunch: vi.fn() }));
    vi.doMock('@tauri-apps/plugin-shell', () => ({ open: vi.fn() }));
    mockedInvoke.mockImplementation(async (cmd: string) => {
      switch (cmd) {
        case 'check_biometric_available':
          return { available: true, enabled: true, method: 'windows_hello' };
        case 'get_auth_state':
          return { is_authenticated: true, email: 'user@example.com', account_id: null, plan: null };
        case 'get_vpn_status':
          return { state: 'connected', seq: 3, error: null };
        default:
          return undefined;
      }
    });
    useAppStore.setState({ acceptedConsentVersion: CONSENT_VERSION });
    const { default: App } = await import('@/App');
    render(<App />);
    expect(await screen.findByText('BirdoVPN is locked')).toBeInTheDocument();
    // Hidden at launch (Start Minimized): no Windows Hello prompt yet.
    expect(callsTo('authenticate_biometric')).toHaveLength(0);

    await waitFor(() => expect(useAppStore.getState().connectionState).toBe('connected'));
    // A drop published by Rust (e.g. after a tray Disconnect, which Rust performs
    // itself) still reaches the store under the cover.
    emit('vpn-status-changed', { state: 'disconnected', seq: 999, kill_switch_blocking: false, error: null });
    await waitFor(() => expect(useAppStore.getState().connectionState).toBe('disconnected'));
  });
});

/** birdo-web #590: the Free allowance, inside and after its grace window. */
describe('the Free data allowance', () => {
  it('a grace warning is a notice with View plans and a system notification; the tunnel is untouched', async () => {
    render(<VpnSessionController />);
    await waitFor(() => expect(useAppStore.getState().statusSeq).toBe(1));
    emit('vpn-status-changed', { state: 'connected', seq: 2, kill_switch_blocking: false, error: null });

    emit('quota-warning', { secondsRemaining: 540 });
    const notice = useAppStore.getState().notice;
    expect(notice?.text).toBe('Free data allowance used — your connection ends in 9 min.');
    expect(notice?.actionLabel).toBe('View plans');
    await waitFor(() =>
      expect(sendNotification).toHaveBeenCalledWith({
        title: 'BirdoVPN — Free data allowance used',
        body: 'Free data allowance used — your connection ends in 9 min.',
      }),
    );
    act(() => notice?.onAction?.());
    expect(useAppStore.getState().navStack).toEqual(['pricing']);
    expect(useAppStore.getState().connectionState).toBe('connected');
    expect(callsTo('disconnect_vpn')).toHaveLength(0);
  });

  it('when the server ends the session, the error says why', async () => {
    render(<VpnSessionController />);
    await waitFor(() => expect(useAppStore.getState().statusSeq).toBe(1));
    emit('vpn-status-changed', { state: 'connected', seq: 2, kill_switch_blocking: false, error: null });
    emit('vpn-status-changed', {
      state: 'error',
      seq: 3,
      kill_switch_blocking: false,
      error: { code: 'quota_exceeded', message: 'x', retryable: false, retry_after_secs: null },
    });
    expect(useAppStore.getState().vpnError?.code).toBe('quota_exceeded');
    expect(useAppStore.getState().giveUp).toBeNull();
    await waitFor(() =>
      expect(sendNotification).toHaveBeenCalledWith({
        title: 'BirdoVPN — Connection error',
        body: "You've used this month's free data allowance. Upgrade to keep using BirdoVPN.",
      }),
    );
  });
});
