/**
 * IPC contract tests — v2 (contracts/WINDOWS-IPC-V2.md).
 *
 * W2-040: the old layer 1 called `invoke(x, payload)` on the MOCK and asserted
 * the mock had been called with `payload` — a tautology that could never fail.
 * Everything here exercises the REAL code on each side of the boundary:
 *
 *  1. Rust → UI: the v2 payloads (`VpnStatus`, `IpcError`, `session-expired`)
 *     as the contract writes them, fed through the parsers every component
 *     reads through. Both casings, because the contract says "stays
 *     snake_case as today" while today's `VpnStatus` is camelCase.
 *  2. UI → Rust: the argument objects our real action functions send, and the
 *     `save_settings` payload checked field-by-field against the Rust
 *     `AppSettings` struct read out of src-tauri. Port Forwarding's add is
 *     driven through the real screen and checked against the Rust command's
 *     parameter names.
 *  3. The command registry: every command the UI invokes (scanned from the
 *     source, so the list cannot drift) is registered in main.rs.
 *
 * Run: npx vitest run src/__tests__/ipc-contracts.test.ts
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { createElement } from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { parseServers, parseSessionExpired, parseVpnStats, parseVpnStatus, toIpcError } from '@/lib/ipc';
import { connectMultiHop, connectToServer, disconnectVpn } from '@/session/vpn-actions';
import { persistSettings } from '@/session/settings-persist';
import { useAppStore, type Server } from '@/store/app-store';
import { settingsToRust } from '@/utils/helpers';
import { PortForward } from '@/screens/PortForward';

vi.mock('@tauri-apps/api/core');
const mockedInvoke = vi.mocked(invoke);

beforeEach(() => {
  mockedInvoke.mockReset();
  mockedInvoke.mockResolvedValue(undefined);
  useAppStore.getState().logout();
  useAppStore.setState({ isAuthenticated: true });
});

// ── 1. Rust → UI ────────────────────────────────────────────────────────────

/** Contract §1, every field, snake_case as the contract table spells it. */
const V2_STATUS_SNAKE = {
  state: 'reconnecting',
  phase: 'handshaking',
  reconnect_attempt: 3,
  reconnect_max: 10,
  kill_switch_blocking: true,
  error: { code: 'server_unreachable', message: 'Handshake timed out', retryable: true, retry_after_secs: null },
  server_id: 'de-fra-1',
  multi_hop: { entry_id: 'ch-1', entry_name: 'Zurich', exit_id: 'de-fra-1', exit_name: 'Frankfurt' },
  seq: 42,
  bytes_sent: 1024,
  bytes_received: 2048,
  connected_at: '2026-09-30T10:00:00Z',
  server_name: 'Frankfurt #1',
  stealth_active: false,
  quantum_active: true,
  pq_mode: 'bilateral',
  dns_degraded: ['Ethernet: 192.0.2.53 still set'],
};

/** The same, as it arrives if Rust keeps `rename_all = "camelCase"`. */
const V2_STATUS_CAMEL = {
  state: 'reconnecting',
  phase: 'handshaking',
  reconnectAttempt: 3,
  reconnectMax: 10,
  killSwitchBlocking: true,
  error: { code: 'server_unreachable', message: 'Handshake timed out', retryable: true, retryAfterSecs: null },
  serverId: 'de-fra-1',
  multiHop: { entryId: 'ch-1', entryName: 'Zurich', exitId: 'de-fra-1', exitName: 'Frankfurt' },
  seq: 42,
  bytesSent: 1024,
  bytesReceived: 2048,
  connectedAt: '2026-09-30T10:00:00Z',
  serverName: 'Frankfurt #1',
  stealthActive: false,
  quantumActive: true,
  pqMode: 'bilateral',
  dnsDegraded: ['Ethernet: 192.0.2.53 still set'],
};

describe('VpnStatus (contract §1) → parseVpnStatus', () => {
  it.each([
    ['snake_case', V2_STATUS_SNAKE],
    ['camelCase', V2_STATUS_CAMEL],
  ])('reads every v2 field from a %s payload', (_casing, payload) => {
    expect(parseVpnStatus(payload)).toEqual({
      state: 'reconnecting',
      phase: 'handshaking',
      reconnectAttempt: 3,
      reconnectMax: 10,
      killSwitchBlocking: true,
      error: { code: 'server_unreachable', message: 'Handshake timed out', retryable: true, retry_after_secs: null },
      serverId: 'de-fra-1',
      multiHop: { entryId: 'ch-1', entryName: 'Zurich', exitId: 'de-fra-1', exitName: 'Frankfurt' },
      seq: 42,
      bytesSent: 1024,
      bytesReceived: 2048,
      connectedAt: '2026-09-30T10:00:00Z',
      serverName: 'Frankfurt #1',
      stealthActive: false,
      quantumActive: true,
      dnsDegraded: ['Ethernet: 192.0.2.53 still set'],
      gaveUp: null,
    });
  });

  it('reads the give-up mark Rust sets on the final error status, in both casings (REVIEW-WIN-009)', () => {
    const base = { state: 'error', error: { code: 'server_unreachable', message: '' } };
    expect(parseVpnStatus({ ...base, gaveUp: { attempts: 10 } })?.gaveUp).toEqual({ attempts: 10 });
    expect(parseVpnStatus({ ...base, gave_up: { attempts: 0 } })?.gaveUp).toEqual({ attempts: 0 });
    expect(parseVpnStatus({ ...base, gaveUp: null })?.gaveUp).toBeNull();
    expect(parseVpnStatus(base)?.gaveUp).toBeNull();
  });

  it('accepts every v2 state, including the new `switching`', () => {
    for (const state of ['disconnected', 'connecting', 'connected', 'disconnecting', 'reconnecting', 'switching', 'error']) {
      expect(parseVpnStatus({ state })?.state).toBe(state);
    }
  });

  it('maps the v1 states a not-yet-updated backend can still send', () => {
    expect(parseVpnStatus({ state: 'authenticating' })).toMatchObject({ state: 'connecting', phase: 'authenticating' });
    expect(parseVpnStatus({ state: 'stealth_connecting' })).toMatchObject({ state: 'connecting', phase: 'starting_stealth' });
    expect(parseVpnStatus({ state: 'rekeying' })?.state).toBe('connected');
    expect(parseVpnStatus({ state: 'kill_switch_active' })).toMatchObject({ state: 'disconnected', killSwitchBlocking: true });
  });

  it('a pre-v2 payload leaves the v2 fields explicitly unknown, never "fine"', () => {
    const st = parseVpnStatus({ state: 'connected', bytesSent: 1, bytesReceived: 2 })!;
    expect(st.seq).toBeNull();
    expect(st.error).toBeUndefined();
    expect(st.dnsDegraded).toBeUndefined();
    expect(st.killSwitchBlocking).toBe(false);
  });

  it('rejects what is not a status instead of throwing or guessing', () => {
    for (const bad of [null, undefined, 'connected', 42, [], {}, { state: 'teleporting' }, { state: 3 }]) {
      expect(parseVpnStatus(bad)).toBeNull();
    }
  });

  it('get_vpn_stats (snake_case VpnStats) → parseVpnStats', () => {
    expect(
      parseVpnStats({ bytes_in: 10, bytes_out: 20, packets_in: 1, packets_out: 2, uptime_seconds: 61, current_latency_ms: 33 }),
    ).toEqual({ bytesIn: 10, bytesOut: 20, uptimeSeconds: 61, latencyMs: 33 });
    expect(parseVpnStats({ uptime_seconds: 5, current_latency_ms: null })?.latencyMs).toBeNull();
  });

  it('get_servers (camelCase ServerInfo) → parseServers, dropping rows without an id', () => {
    const servers = parseServers([
      { id: 'a', name: 'A', country: 'Germany', countryCode: 'DE', city: 'Berlin', load: 10, isOnline: false, accessible: false, minPlan: 'SOVEREIGN' },
      { id: 'b', name: 'B', country: 'France', country_code: 'FR', city: 'Paris', is_online: true },
      { name: 'no id' },
    ]);
    expect(servers.map((s) => s.id)).toEqual(['a', 'b']);
    expect(servers[0]).toMatchObject({ countryCode: 'DE', isOnline: false, isAccessible: false, minPlan: 'SOVEREIGN' });
    expect(servers[1]).toMatchObject({ countryCode: 'FR', isOnline: true, isAccessible: true, load: 0 });
  });
});

describe('IpcError (contract §2) → toIpcError', () => {
  it('reads the v2 error object as the contract spells it', () => {
    expect(
      toIpcError({ code: 'rate_limited', message: 'Too many requests', retryable: true, retry_after_secs: 30 }),
    ).toEqual({ code: 'rate_limited', message: 'Too many requests', retryable: true, retry_after_secs: 30 });
  });

  it('turns a legacy String error into code "unknown" (commands outside the contract list)', () => {
    expect(toIpcError('Failed to save settings')).toEqual({
      code: 'unknown',
      message: 'Failed to save settings',
      retryable: true,
      retry_after_secs: null,
    });
  });

  it('never classifies free text: a pin warning mentioning "connection" stays unknown', () => {
    expect(toIpcError('your connection is being intercepted').code).toBe('unknown');
  });

  it('an unrecognised code is "unknown", not a crash or a pass-through', () => {
    expect(toIpcError({ code: 'quantum_flux', message: 'x' }).code).toBe('unknown');
  });

  it('handles an Error and garbage', () => {
    expect(toIpcError(new Error('boom'))).toMatchObject({ code: 'unknown', message: 'boom' });
    expect(toIpcError(undefined)).toMatchObject({ code: 'unknown', message: '' });
  });
});

describe('session-expired (contract §3.3)', () => {
  it('reads the reason, treating anything unrecognised as expiry', () => {
    expect(parseSessionExpired({ reason: 'revoked' })).toBe('revoked');
    expect(parseSessionExpired({ reason: 'expired' })).toBe('expired');
    expect(parseSessionExpired(null)).toBe('expired');
  });
});

// ── 2. UI → Rust ────────────────────────────────────────────────────────────

const SERVER: Server = {
  id: 'de-fra-1',
  name: 'Frankfurt #1',
  country: 'Germany',
  countryCode: 'DE',
  city: 'Frankfurt',
  load: 10,
  isPremium: false,
  isHighSpeed: false,
  isPortForwarding: false,
  isOnline: true,
  isAccessible: true,
};

const callsTo = (cmd: string) => mockedInvoke.mock.calls.filter(([c]) => c === cmd);

describe('what the real actions send', () => {
  it('connect_vpn { serverId }', async () => {
    await connectToServer(SERVER);
    expect(callsTo('connect_vpn')).toEqual([['connect_vpn', { serverId: 'de-fra-1' }]]);
  });

  it('connect_multi_hop { entryNodeId, exitNodeId }', async () => {
    await connectMultiHop('ch-1', 'de-fra-1');
    expect(callsTo('connect_multi_hop')).toEqual([
      ['connect_multi_hop', { entryNodeId: 'ch-1', exitNodeId: 'de-fra-1' }],
    ]);
  });

  it('disconnect_vpn takes no arguments', async () => {
    await disconnectVpn();
    expect(callsTo('disconnect_vpn')).toEqual([['disconnect_vpn']]);
  });

  it('save_settings { settings } carries the full object, never a partial', async () => {
    await persistSettings({ autoConnect: true });
    const [[, args]] = callsTo('save_settings') as [[string, { settings: Record<string, unknown> }]];
    expect(Object.keys(args.settings).sort()).toEqual(Object.keys(settingsToRust(useAppStore.getState().settings)).sort());
    expect(args.settings.auto_connect).toBe(true);
  });

  // P1-dk-ipc-contract-test-tautology: the add is driven through the real
  // screen, and its argument names are held against the Rust command's own
  // parameters (Tauri matches them by name). The old assertion called the
  // mock with `{ request: { internalPort, protocol } }` and checked that the
  // mock had been called with it, while the screen sent `{ port, protocol }`.
  it('create_port_forward { port, protocol }, as PortForward sends it and Rust names it', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) =>
      cmd === 'get_port_forwards' ? [] : cmd === 'create_port_forward' ? { success: false } : undefined,
    );
    render(createElement(PortForward));
    await userEvent.type(await screen.findByPlaceholderText('e.g. 8080'), '25565');
    await userEvent.click(screen.getByRole('button', { name: 'udp' }));
    await userEvent.click(screen.getByRole('button', { name: /Add rule/ }));
    await waitFor(() => expect(callsTo('create_port_forward')).toHaveLength(1));

    const [[, args]] = callsTo('create_port_forward') as [[string, Record<string, unknown>]];
    expect(args).toEqual({ port: 25565, protocol: 'udp' });
    expect(Object.keys(args).sort()).toEqual(rustCommandArgs('vpn_port_forward.rs', 'create_port_forward'));
  });
});

/**
 * The renderer-supplied parameters of a Rust `#[tauri::command]`, as the
 * camelCase keys Tauri expects: everything but the injected `State<…>` and
 * `AppHandle`.
 */
function rustCommandArgs(file: string, command: string): string[] {
  const src = readFileSync(findUp(`src-tauri/src/commands/${file}`), 'utf8');
  const head = `pub async fn ${command}(`;
  const start = src.indexOf(head);
  if (start === -1) throw new Error(`${head} not found in commands/${file}`);
  const params = src.slice(start + head.length, src.indexOf(')', start));
  return [...params.matchAll(/(\w+)\s*:\s*(State<[^>]*>|[\w:<>']+)/g)]
    .filter(([, , type]) => !type.startsWith('State<') && type !== 'AppHandle')
    .map(([, name]) => name.replace(/_(\w)/g, (_, c: string) => c.toUpperCase()))
    .sort();
}

function findUp(rel: string): string {
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = resolve(dir, rel);
    if (existsSync(candidate)) return candidate;
    const parent = resolve(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  return resolve(process.cwd(), rel);
}

/** `pub <field>: <type>` lines of the Rust `AppSettings`, with whether serde defaults each. */
function rustAppSettingsFields(): { name: string; defaulted: boolean }[] {
  const src = readFileSync(findUp('src-tauri/src/commands/settings.rs'), 'utf8');
  const start = src.indexOf('pub struct AppSettings');
  if (start === -1) throw new Error('pub struct AppSettings not found in commands/settings.rs');
  const body = src.slice(start, src.indexOf('\n}', start));
  const fields: { name: string; defaulted: boolean }[] = [];
  let pendingDefault = false;
  for (const line of body.split('\n')) {
    const t = line.trim();
    if (t.startsWith('#[serde(') && t.includes('default')) pendingDefault = true;
    const m = /^pub ([a-z_][a-z0-9_]*):\s*(.+?),?$/.exec(t);
    if (m) {
      // serde treats a missing Option<_> as None even without a default.
      fields.push({ name: m[1], defaulted: pendingDefault || m[2].startsWith('Option<') });
      pendingDefault = false;
    }
  }
  return fields;
}

describe('save_settings payload ↔ Rust AppSettings (commands/settings.rs)', () => {
  const fields = rustAppSettingsFields();
  const written = Object.keys(settingsToRust(useAppStore.getState().settings));

  it('parses a non-trivial field list', () => {
    expect(fields.length).toBeGreaterThan(15);
  });

  it('writes only fields Rust knows (a stray key is silently dropped by serde)', () => {
    const known = new Set(fields.map((f) => f.name));
    expect(written.filter((k) => !known.has(k))).toEqual([]);
  });

  it('writes every field Rust has no default for (save_settings REPLACES the struct)', () => {
    const required = fields.filter((f) => !f.defaulted).map((f) => f.name);
    expect(required.filter((k) => !written.includes(k))).toEqual([]);
  });

  it('round-trips the flags whose serde default would silently flip a user choice', () => {
    for (const k of ['lockdown_mode', 'quantum_protection', 'killswitch_enabled', 'dns_filtering', 'crash_reports_enabled']) {
      expect(written).toContain(k);
    }
  });
});

// ── 3. The command registry ─────────────────────────────────────────────────

/**
 * Every command the UI invokes. Kept by hand so a reviewer sees the IPC
 * surface in one place, and pinned against the source scan below so it can
 * never go stale again (set_tray_state, set_window_position,
 * get_killswitch_status and get_multi_hop_routes were listed long after the
 * UI stopped calling them, or before it ever did).
 */
const FRONTEND_COMMANDS = [
  // Authentication
  'login',
  'login_anonymous',
  'register_anonymous',
  'native_oauth_login',
  'logout',
  'get_auth_state',
  'verify_2fa',
  'delete_account',
  'deletion_preflight',
  'export_user_data',
  // A command answered session_expired: Rust ends the session too (REVIEW-WIN-012)
  'end_expired_session',
  // VPN operations
  'connect_vpn',
  'disconnect_vpn',
  'get_vpn_status',
  'get_vpn_stats',
  'quick_connect',
  'reapply_vpn_settings',
  'get_admin_status',
  'connect_multi_hop',
  // Servers
  'get_servers',
  'ping_server',
  // Settings
  'get_settings',
  'save_settings',
  'set_autostart',
  'set_crash_reports_enabled',
  // Kill switch
  'set_killswitch_live',
  // Kill Switch Exceptions
  'list_installed_apps',
  // Updater (pinned Rust client — commands/updater.rs)
  'get_app_version',
  'check_for_updates',
  'install_update',
  'get_required_update',
  // Account data
  'get_subscription_status',
  'get_usage_stats',
  'get_client_config',
  // Port forwarding
  'get_port_forwards',
  'create_port_forward',
  'delete_port_forward',
  // Vouchers
  'redeem_voucher',
  // Speed test
  'run_speed_test_command',
  // Hide App Contents (Windows Hello / Touch ID)
  'check_biometric_available',
  'set_biometric_enabled',
  'authenticate_biometric',
  // Deep link captured at cold start
  'take_pending_deep_link',
  // The window up from the tray: re-consent behind Start Minimized (REVIEW-WIN2-010)
  'show_main_window',
] as const;

function sourceFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name === '__tests__' || name === '__mocks__') continue;
      out.push(...sourceFiles(p));
    } else if (/\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name)) {
      out.push(p);
    }
  }
  return out;
}

/**
 * Commands passed to `invoke(...)` / `command(...)` anywhere in src (not
 * tests), plus vpn-actions' `run(pending, 'cmd', …)` wrapper.
 */
function scannedCommands(): string[] {
  const found = new Set<string>();
  const patterns = [
    /\b(?:invoke|command)(?:<[^>]*>)?\(\s*'([a-z_][a-z0-9_]*)'/g,
    /\brun\(\s*'[a-z]+',\s*'([a-z_][a-z0-9_]*)'/g,
  ];
  for (const file of sourceFiles(findUp('src'))) {
    const text = readFileSync(file, 'utf8');
    for (const re of patterns) for (const m of text.matchAll(re)) found.add(m[1]);
  }
  return [...found].sort();
}

function loadRegisteredCommands(): string[] {
  const src = readFileSync(findUp('src-tauri/src/main.rs'), 'utf8');
  const marker = 'generate_handler![';
  const start = src.indexOf(marker);
  if (start === -1) throw new Error('generate_handler![ block not found in main.rs');
  const from = start + marker.length;
  const end = src.indexOf(']', from);
  if (end === -1) throw new Error('generate_handler![ block was not terminated in main.rs');
  const commands: string[] = [];
  for (const rawLine of src.slice(from, end).split('\n')) {
    const line = rawLine.replace(/\/\/.*$/, '');
    for (const token of line.split(',')) {
      const entry = token.trim();
      if (!entry) continue;
      const ident = entry.split('::').pop()!.trim();
      if (/^[a-z_][a-z0-9_]*$/.test(ident)) commands.push(ident);
    }
  }
  return commands;
}

describe('IPC Contract: command registry cross-check (frontend ↔ Rust)', () => {
  const registered = loadRegisteredCommands();
  const registeredSet = new Set(registered);

  it('parses a non-trivial command set from main.rs generate_handler!', () => {
    // Guards the parser: an empty extraction would make every ⊆ below vacuous.
    expect(registered.length).toBeGreaterThan(20);
  });

  it('registers no command twice in generate_handler!', () => {
    expect(registered.filter((cmd, i) => registered.indexOf(cmd) !== i)).toEqual([]);
  });

  it('the hand-kept list is exactly what the source invokes', () => {
    expect([...FRONTEND_COMMANDS].sort()).toEqual(scannedCommands());
  });

  it.each(FRONTEND_COMMANDS)("frontend command '%s' is registered in main.rs generate_handler!", (cmd) => {
    expect(registeredSet.has(cmd)).toBe(true);
  });
});
