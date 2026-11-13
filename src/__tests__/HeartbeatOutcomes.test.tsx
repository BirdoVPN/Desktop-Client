/**
 * MR-1638, the UI half: what each heartbeat reason ends up as on screen.
 *
 * The heartbeat reply never reaches TypeScript. Rust decodes it and decides
 * (`reconnect_policy::heartbeat_verdict`), and `contract_tests.rs` pins that
 * decision for every `$defs/HeartbeatReason` in every shape birdo-web sends
 * it (`heartbeat_cases`). What crosses IPC is only the outcome:
 *
 *  - inside the Free plan's grace window, a `quota-warning` event carrying
 *    the seconds left (`auto_reconnect.rs`, `QuotaWarning`);
 *  - when the server ended the session, an `error` status whose code is
 *    `revoked` or `quota_exceeded` (`end_by_server` → `give_up`, no `gaveUp`);
 *  - otherwise nothing (`Fine`, and `ServerGoingOffline`, which only logs).
 *
 * This file pins the other half, per reason: that outcome, as Rust emits it,
 * drives the REAL controller to the decided UI. The event name, the payload
 * key and the error codes are read out of the Rust source rather than typed
 * again here, so a rename on either side fails this file instead of silently
 * dropping the grace notice or the plan offer. The reasons are read out of
 * the vendored schema, so a reason a re-vendor adds fails here until someone
 * decides what the UI does with it (and adds it to `heartbeat_cases` too).
 *
 * The OUTCOMES below mirror `heartbeat_cases`' `live` column; keep the two in
 * step. The teardown probe's column (`after_teardown`) re-dials or ends with
 * the same two codes, so it reaches the UI as one of these same outcomes.
 *
 * Run: npx vitest run src/__tests__/HeartbeatOutcomes.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, waitFor, act } from '@testing-library/react';
import { invoke } from '@tauri-apps/api/core';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { VpnSessionController } from '@/session/controller';
import { useAppStore, defaultSettings } from '@/store/app-store';
import { resetSessionData } from '@/session/session-data';
import { CONSENT_VERSION } from '@/lib/consent';
import { QUOTA_EXCEEDED_COPY, REVOKED_COPY, quotaGraceMessage, vpnErrorCopy } from '@/lib/errors';

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
const callsTo = (cmd: string) => mockedInvoke.mock.calls.filter(([c]) => c === cmd);

// ── What Rust emits, read out of the Rust source ───────────────────────────

const TAURI = resolve(__dirname, '../../src-tauri');
const rustSource = (path: string) => readFileSync(resolve(TAURI, path), 'utf8').replace(/\r\n/g, '\n');
const camel = (snake: string) => snake.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
const snake = (pascal: string) => pascal.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();

/** `QUOTA_WARNING_EVENT` and the one field of `QuotaWarning`, as serde names it on the wire. */
function quotaWarningWire(): { event: string; secondsKey: string } {
  const src = rustSource('src/vpn/auto_reconnect.rs');
  const event = /const QUOTA_WARNING_EVENT: &str = "([^"]+)";/.exec(src)?.[1];
  const struct = /#\[serde\(rename_all = "camelCase"\)\]\s*struct QuotaWarning \{([^}]*)\}/.exec(src)?.[1];
  if (!event || struct === undefined) {
    throw new Error('auto_reconnect.rs: QUOTA_WARNING_EVENT or a camelCase QuotaWarning not found');
  }
  const fields = struct
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('//'))
    .map((l) => /^(?:pub\s+)?(\w+)\s*:/.exec(l)?.[1])
    .filter((f): f is string => Boolean(f));
  expect(fields).toEqual(['seconds_remaining']);
  return { event, secondsKey: camel(fields[0]) };
}

type EndCode = 'Revoked' | 'QuotaExceeded';

/** The wire name of an `IpcErrorCode` variant (`ipc_error.rs`, `rename_all = "snake_case"`). */
function ipcCodeWire(variant: EndCode): string {
  const src = rustSource('src/commands/ipc_error.rs');
  const body = /#\[serde\(rename_all = "snake_case"\)\]\s*pub enum IpcErrorCode \{([\s\S]*?)\n\}/.exec(src)?.[1];
  if (body === undefined) throw new Error('ipc_error.rs: a snake_case IpcErrorCode not found');
  expect(body).toMatch(new RegExp(`^\\s*${variant},`, 'm'));
  return snake(variant);
}

/** `$defs/HeartbeatReason.enum` of the vendored contract. */
function contractReasons(): string[] {
  const schema = JSON.parse(rustSource('contract/vpn-protocol.schema.json')) as {
    $defs: Record<string, { enum?: string[] }>;
  };
  return schema.$defs.HeartbeatReason.enum ?? [];
}

// ── The outcome of each reason (heartbeat_cases' `live` column) ────────────

// birdo-web VpnService.heartbeat's sentences, which Rust passes on for a revoke.
const HB_NOT_FOUND = 'Connection not found. Please reconnect.';
const HB_REVOKED = 'Connection has been revoked. Please reconnect.';
// reconnect_policy::quota_exceeded_error().
const RUST_QUOTA_EXCEEDED = "You've used this month's free data allowance. Upgrade to keep using BirdoVPN.";

type Outcome =
  | { kind: 'nothing' }
  | { kind: 'grace'; secondsRemaining: number }
  | { kind: 'end'; code: EndCode; message: string };

interface ReasonCase {
  reason: string;
  /** Which of the server's shapes for this reason (as `heartbeat_cases` lists them). */
  shape: string;
  outcome: Outcome;
}

const nothing: Outcome = { kind: 'nothing' };
const grace = (secondsRemaining: number): Outcome => ({ kind: 'grace', secondsRemaining });
const revoked = (message: string): Outcome => ({ kind: 'end', code: 'Revoked', message });
const quotaEnded: Outcome = { kind: 'end', code: 'QuotaExceeded', message: RUST_QUOTA_EXCEEDED };

const CASES: ReasonCase[] = [
  { reason: 'ok', shape: 'live', outcome: nothing },
  { reason: 'ok', shape: 'live, inside the Free grace window (540 s)', outcome: grace(540) },
  { reason: 'server_offline', shape: 'valid: the key lives, its server is not ONLINE', outcome: nothing },
  { reason: 'server_offline', shape: 'valid, inside the Free grace window (60 s)', outcome: grace(60) },
  { reason: 'server_offline', shape: 'invalid: the key went with a drained server', outcome: revoked(HB_NOT_FOUND) },
  { reason: 'revoked', shape: 'a deactivated row', outcome: revoked(HB_REVOKED) },
  { reason: 'revoked', shape: 'a removal record', outcome: revoked(HB_NOT_FOUND) },
  { reason: 'evicted', shape: 'a removal record', outcome: revoked(HB_NOT_FOUND) },
  { reason: 'reaped', shape: 'a removal record', outcome: revoked(HB_NOT_FOUND) },
  { reason: 'quota_exceeded', shape: 'ended at this check-in', outcome: quotaEnded },
  { reason: 'quota_exceeded', shape: 'a removal record', outcome: quotaEnded },
  { reason: 'not_found', shape: 'no record of why', outcome: revoked(HB_NOT_FOUND) },
];

/** What the UI shows for an ending: the copy by code, never by the server's sentence. */
const END_UI: Record<EndCode, { message: string; action: string }> = {
  Revoked: { message: REVOKED_COPY, action: 'connect' },
  QuotaExceeded: { message: QUOTA_EXCEEDED_COPY, action: 'view_plans' },
};

// ── The harness (as SessionController.test.tsx) ─────────────────────────────

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
    acceptedConsentVersion: CONSENT_VERSION,
  });
  mockedInvoke.mockReset();
  mockedInvoke.mockImplementation(async (cmd: string) => {
    switch (cmd) {
      case 'get_vpn_status':
        return { state: 'disconnected', seq: 1, kill_switch_blocking: false, error: null };
      case 'get_vpn_stats':
        return { bytes_in: 0, bytes_out: 0, uptime_seconds: 0, current_latency_ms: null };
      case 'get_settings':
        return { auto_connect: false, killswitch_enabled: true, lockdown_mode: true };
      case 'get_servers':
        return [];
      case 'get_subscription_status':
        return { plan: 'RECON', status: 'active' };
      default:
        return undefined;
    }
  });
});

/** A connected session, as Rust reports it before the heartbeat answers. */
async function connected() {
  render(<VpnSessionController />);
  await waitFor(() => expect(useAppStore.getState().statusSeq).toBe(1));
  emit('vpn-status-changed', { state: 'connected', seq: 2, kill_switch_blocking: false, error: null });
  expect(useAppStore.getState().connectionState).toBe('connected');
  sendNotification.mockClear();
}

/** Emit what Rust emits for `outcome`, the names taken from the Rust source. */
function rustEmits(outcome: Outcome) {
  if (outcome.kind === 'grace') {
    const { event, secondsKey } = quotaWarningWire();
    emit(event, { [secondsKey]: outcome.secondsRemaining });
  } else if (outcome.kind === 'end') {
    emit('vpn-status-changed', {
      state: 'error',
      seq: 3,
      kill_switch_blocking: false,
      error: { code: ipcCodeWire(outcome.code), message: outcome.message, retryable: false, retry_after_secs: null },
    });
  }
}

// ── The tests ───────────────────────────────────────────────────────────────

describe('heartbeat reasons: what the UI does (MR-1638)', () => {
  it('every reason in the vendored contract has a decided outcome here', () => {
    const reasons = contractReasons();
    expect(reasons.length).toBeGreaterThan(0);
    expect([...new Set(CASES.map((c) => c.reason))].sort()).toEqual([...reasons].sort());
  });

  it('the grace event and the two ending codes are the names the UI listens for', () => {
    expect(quotaWarningWire()).toEqual({ event: 'quota-warning', secondsKey: 'secondsRemaining' });
    expect(ipcCodeWire('Revoked')).toBe('revoked');
    expect(ipcCodeWire('QuotaExceeded')).toBe('quota_exceeded');
  });

  for (const c of CASES) {
    it(`${c.reason} (${c.shape}): ${c.outcome.kind === 'end' ? c.outcome.code : c.outcome.kind}`, async () => {
      const o = c.outcome;
      await connected();
      rustEmits(o);
      const s = useAppStore.getState();

      switch (o.kind) {
        case 'nothing':
          // Nothing crossed IPC: the session and the screen are as they were.
          expect(s.connectionState).toBe('connected');
          expect(s.notice).toBeNull();
          expect(s.vpnError).toBeNull();
          break;

        case 'grace': {
          // Still live: a notice with the minutes left and the way to a plan,
          // a system notification, and the tunnel untouched.
          const text = quotaGraceMessage(o.secondsRemaining);
          expect(s.connectionState).toBe('connected');
          expect(s.vpnError).toBeNull();
          expect(s.notice?.text).toBe(text);
          expect(text).toContain(`${Math.ceil(o.secondsRemaining / 60)} min`);
          expect(s.notice?.actionLabel).toBe('View plans');
          await waitFor(() => expect(sendNotification).toHaveBeenCalledWith(expect.objectContaining({ body: text })));
          act(() => s.notice?.onAction?.());
          expect(useAppStore.getState().navStack).toEqual(['pricing']);
          expect(callsTo('disconnect_vpn')).toHaveLength(0);
          break;
        }

        case 'end': {
          // The server ended it: an error by code (not a give-up), worded by
          // code, offered the decided way on, and never re-dialled from here.
          const ui = END_UI[o.code];
          expect(s.connectionState).toBe('error');
          expect(s.vpnError?.code).toBe(ipcCodeWire(o.code));
          expect(s.giveUp).toBeNull();
          expect(vpnErrorCopy(s.vpnError!, s.killSwitchBlocking)).toEqual(ui);
          await waitFor(() =>
            expect(sendNotification).toHaveBeenCalledWith({
              title: 'BirdoVPN — Connection error',
              body: ui.message,
            }),
          );
          expect(callsTo('connect_vpn')).toHaveLength(0);
          expect(callsTo('connect_multi_hop')).toHaveLength(0);
          break;
        }
      }
    });
  }
});
