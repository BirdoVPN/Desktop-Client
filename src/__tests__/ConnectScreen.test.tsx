/**
 * The Connect screen as a view over the store.
 *
 *  - Disconnect is available in EVERY state that has a dial, a tunnel or a
 *    block (W2-003, W2-004, W2-005, W2-025): the button used to be disabled
 *    and read "Connecting…" through a five-minute reconnect loop, and read
 *    "Connect" over a machine the kill switch was firewalling.
 *  - The pill speaks the canonical vocabulary and never an engine phase
 *    (P1-parity-006, -017) — pinned as a table over every state.
 *  - Background errors are shown with the canonical copy and a way forward
 *    (W2-008, P1-parity-020/021/040); the kill-switch chips (P1-parity-019).
 *  - Locked servers explain the upgrade; offline ones say so (W2-015);
 *    Multi-Hop's route is frozen while a session is up (W2-010);
 *    the synthetic anonymous address is never shown (P1-parity-007).
 *
 * Run: npx vitest run src/__tests__/ConnectScreen.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { Dashboard } from '@/components/Dashboard';
import { connectCta, statusPill } from '@/lib/vpn-display';
import { parseVpnStatus, type VpnState } from '@/lib/ipc';
import { PQ_FAILED_COPY, REVOKED_COPY } from '@/lib/errors';
import { defaultSettings, useAppStore, type Server } from '@/store/app-store';

vi.mock('@tauri-apps/api/core');
const mockedInvoke = vi.mocked(invoke);

const S = (id: string, extra: Partial<Server> = {}): Server => ({
  id,
  name: `Node ${id}`,
  country: 'Germany',
  countryCode: 'DE',
  city: 'Frankfurt',
  load: 10,
  isPremium: false,
  isHighSpeed: false,
  isPortForwarding: false,
  isOnline: true,
  isAccessible: true,
  ...extra,
});

function setStatus(fields: Record<string, unknown>) {
  const st = parseVpnStatus({ seq: null, kill_switch_blocking: false, error: null, ...fields });
  if (!st) throw new Error('bad fixture');
  useAppStore.setState({ statusSeq: -1 });
  useAppStore.getState().applyVpnStatus(st);
}

beforeEach(() => {
  mockedInvoke.mockReset();
  mockedInvoke.mockResolvedValue(undefined);
  useAppStore.getState().logout();
  useAppStore.setState({
    isAuthenticated: true,
    isAdmin: true,
    settings: { ...defaultSettings, killSwitchEnabled: false },
    servers: [S('a'), S('b', { load: 5 })],
    serversStatus: 'ready',
    account: { ...useAppStore.getState().account, plan: 'OPERATIVE' },
  });
});

const cta = () => screen.getByTestId('connect-button');
const callsTo = (cmd: string) => mockedInvoke.mock.calls.filter(([c]) => c === cmd);

describe('connectCta — the action per state (pure)', () => {
  const none = { blocking: false, multiHopArmed: false, multiHopReady: false };
  it.each<[VpnState, string, string]>([
    ['disconnected', 'connect', 'Connect'],
    ['connecting', 'disconnect', 'Cancel'],
    ['connected', 'disconnect', 'Disconnect'],
    ['switching', 'disconnect', 'Disconnect'],
    ['reconnecting', 'disconnect', 'Disconnect'],
    ['disconnecting', 'none', 'Disconnecting…'],
    ['error', 'connect', 'Connect'],
  ])('%s → %s (%s)', (state, action, label) => {
    expect(connectCta(state, none)).toMatchObject({ action, label });
  });

  it.each<VpnState>(['disconnected', 'error'])('%s WHILE BLOCKING → Disconnect, never Connect', (state) => {
    expect(connectCta(state, { ...none, blocking: true })).toMatchObject({ action: 'disconnect', look: 'stop' });
  });

  it('only "disconnecting" (already doing it) is ever without an action on a live session', () => {
    const states: VpnState[] = ['connecting', 'connected', 'switching', 'reconnecting', 'error'];
    for (const s of states) {
      for (const blocking of [false, true]) {
        if (s === 'error' && !blocking) continue;
        expect(connectCta(s, { ...none, blocking }).action).toBe('disconnect');
      }
    }
  });
});

describe('statusPill — the canonical vocabulary (P1-parity-006)', () => {
  it.each<[VpnState, string, string]>([
    ['disconnected', 'Not connected', 'neutral'],
    ['connecting', 'Connecting…', 'warning'],
    ['connected', 'Protected', 'success'],
    ['switching', 'Switching server…', 'warning'],
    ['reconnecting', 'Reconnecting…', 'warning'],
    ['disconnecting', 'Disconnecting…', 'warning'],
    ['error', 'Connection error', 'danger'],
  ])('%s → "%s" (%s)', (state, text, tone) => {
    expect(statusPill(state)).toMatchObject({ text, tone });
  });

  it('never exposes an engine phase or a bare "Error"', () => {
    const all: VpnState[] = ['disconnected', 'connecting', 'connected', 'switching', 'reconnecting', 'disconnecting', 'error'];
    for (const s of all) {
      expect(statusPill(s).text).not.toMatch(/^(Authenticating|Rekeying|Error|Kill Switch)$/);
    }
  });

  it('a Multi-Hop session reads "Protected · Multi-Hop" (P1-parity-017)', () => {
    expect(statusPill('connected', true).text).toBe('Protected · Multi-Hop');
  });
});

describe('Dashboard: Disconnect is always reachable', () => {
  it.each<[string, Record<string, unknown>]>([
    ['connecting (cancels the dial)', { state: 'connecting' }],
    ['connected', { state: 'connected', server_id: 'a' }],
    ['switching', { state: 'switching', server_id: 'a' }],
    ['reconnecting (the loop the tray could not stop)', { state: 'reconnecting', kill_switch_blocking: true }],
    ['error while the kill switch holds the block', { state: 'error', kill_switch_blocking: true }],
    ['always-on block with no tunnel', { state: 'disconnected', kill_switch_blocking: true }],
  ])('%s: the main button is enabled and disconnects', async (_name, fields) => {
    setStatus(fields);
    render(<Dashboard />);
    expect(cta()).toBeEnabled();
    await userEvent.click(cta());
    await waitFor(() => expect(callsTo('disconnect_vpn')).toHaveLength(1));
    expect(callsTo('connect_vpn')).toHaveLength(0);
  });

  it('a blocking state says so, in the canonical chip', () => {
    setStatus({ state: 'reconnecting', kill_switch_blocking: true });
    render(<Dashboard />);
    expect(screen.getByText('Kill Switch — all traffic blocked')).toBeInTheDocument();
  });

  it('disconnected, no block: Connect dials the fastest server when nothing is chosen (W2-028)', async () => {
    setStatus({ state: 'disconnected' });
    render(<Dashboard />);
    expect(screen.getByText('Fastest server')).toBeInTheDocument();
    await userEvent.click(cta());
    await waitFor(() => expect(callsTo('connect_vpn')).toEqual([['connect_vpn', { serverId: 'b' }]]));
  });
});

describe('Dashboard: errors with a way forward', () => {
  it('a background error shows the canonical copy, not a bare pill (W2-008)', () => {
    setStatus({ state: 'error', error: { code: 'pq_failed', message: 'PQ negotiation failed', retryable: true } });
    render(<Dashboard />);
    expect(screen.getByText(PQ_FAILED_COPY)).toBeInTheDocument();
    expect(screen.queryByText('PQ negotiation failed')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Open Settings' })).toBeInTheDocument();
  });

  it('revoked reads as revoked, never "Session expired" (P1-parity-021)', () => {
    setStatus({ state: 'error', error: { code: 'revoked', message: 'x' } });
    render(<Dashboard />);
    expect(screen.getByText(REVOKED_COPY)).toBeInTheDocument();
    expect(screen.queryByText(/session expired/i)).not.toBeInTheDocument();
  });

  it('a reconnect give-up explains what stopped and that the block is still up (P1-parity-020)', () => {
    setStatus({ state: 'reconnecting' });
    const giveUp = parseVpnStatus({
      state: 'error',
      seq: null,
      kill_switch_blocking: true,
      gaveUp: { attempts: 10 },
      error: { code: 'server_unreachable', message: '' },
    })!;
    useAppStore.getState().applyVpnStatus(giveUp);
    render(<Dashboard />);
    expect(
      screen.getByText(/BirdoVPN stopped reconnecting after 10 attempts: the tunnel came up but never reached this server/),
    ).toBeInTheDocument();
    expect(screen.getByText(/The kill switch is still blocking traffic/)).toBeInTheDocument();
  });

  it('"Kill Switch arms once connected" while it is on but idle (P1-parity-019)', () => {
    useAppStore.setState({ settings: { ...defaultSettings, killSwitchEnabled: true } });
    setStatus({ state: 'disconnected' });
    render(<Dashboard />);
    expect(screen.getByText('Kill Switch arms once connected')).toBeInTheDocument();
  });
});

describe('Dashboard: the server sheet', () => {
  it('a plan-locked row is reachable and explains the upgrade; an offline row says "Offline" (W2-015)', async () => {
    useAppStore.setState({
      servers: [S('a'), S('locked', { isAccessible: false, minPlan: 'SOVEREIGN' }), S('down', { isOnline: false })],
    });
    setStatus({ state: 'disconnected' });
    render(<Dashboard />);
    await userEvent.click(screen.getByTestId('server-selector'));
    const sheet = await screen.findByRole('dialog', { name: 'Choose a server' });
    const locked = within(sheet).getByRole('button', { name: /Locked — requires the Sovereign plan/ });
    expect(locked).not.toBeDisabled();
    await userEvent.click(locked);
    expect(useAppStore.getState().notice?.text).toBe('This server requires the Sovereign plan. Upgrade to unlock.');
    expect(within(sheet).getByText('Offline')).toBeInTheDocument();
  });

  it('a failed server load opens to an error with Retry, not "No servers match" (W2-014)', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'get_servers') throw 'offline';
      return undefined;
    });
    useAppStore.setState({ servers: [], serversStatus: 'error' });
    setStatus({ state: 'disconnected' });
    render(<Dashboard />);
    expect(screen.getByText("Couldn't load servers")).toBeInTheDocument();
    // The card opens the sheet (it used to do nothing on an empty list) and
    // retries on the way.
    await userEvent.click(screen.getByTestId('server-selector'));
    const sheet = await screen.findByRole('dialog');
    expect(await within(sheet).findByText("Couldn't load servers")).toBeInTheDocument();
    const before = callsTo('get_servers').length;
    await userEvent.click(within(sheet).getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(callsTo('get_servers').length).toBe(before + 1));
  });
});

describe('Dashboard: Multi-Hop and identity', () => {
  it('the route cannot be edited on a live session, and the pill says Multi-Hop (W2-010, P1-017)', async () => {
    useAppStore.setState({
      account: { ...useAppStore.getState().account, plan: 'SOVEREIGN' },
      settings: { ...defaultSettings, killSwitchEnabled: false, multiHopEnabled: true, multiHopEntryNodeId: 'a', multiHopExitNodeId: 'b' },
    });
    setStatus({
      state: 'connected',
      multi_hop: { entry_id: 'a', entry_name: 'Node a', exit_id: 'b', exit_name: 'Node b' },
    });
    render(<Dashboard />);
    expect(screen.getByText('Protected · Multi-Hop')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /Entry server: Node a/ })).toBeDisabled();
    expect(screen.getByText('Disconnect to change your route.')).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: /Multi-Hop/ }));
    expect(useAppStore.getState().settings.multiHopEnabled).toBe(true);
    expect(callsTo('save_settings')).toHaveLength(0);
  });

  it('an unknown plan shows no lock and routes to no upsell (W2-011)', async () => {
    useAppStore.setState({ account: { ...useAppStore.getState().account, plan: null } });
    setStatus({ state: 'disconnected' });
    render(<Dashboard />);
    await userEvent.click(screen.getByRole('button', { name: 'Multi-Hop' }));
    expect(useAppStore.getState().navStack).toEqual([]);
  });

  it('never renders the synthetic anonymous address (P1-parity-007)', () => {
    useAppStore.setState({ userEmail: 'anon_123456789012345678901234@anonymous.local' });
    setStatus({ state: 'disconnected' });
    const { container } = render(<Dashboard />);
    expect(screen.getByText('Anonymous account')).toBeInTheDocument();
    expect(container.textContent).not.toContain('anon_');
    expect(container.textContent).not.toContain('1234567890');
  });
});
