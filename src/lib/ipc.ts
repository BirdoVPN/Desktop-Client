/**
 * The Rust ⇄ UI wire contract, v2 (`CLIENT-OVERHAUL-2026-09-30/contracts/WINDOWS-IPC-V2.md`).
 *
 * Every payload that crosses IPC is `unknown` until one of the parsers below has
 * looked at it. `invoke<T>` is an unchecked cast, and wire drift has already
 * shipped real bugs here (the snake_case `server_name` that was permanently
 * undefined, `isOnline` falling through to its default for every server, a
 * `{ name }` status cast to a full `Server`). So the rule is: a component never
 * reads a raw IPC object, it reads what a parser returned.
 *
 * CASING. The contract says the status JSON "stays snake_case as today", but
 * today's `VpnStatus` is `#[serde(rename_all = "camelCase")]` (commands/vpn.rs),
 * so which spelling the v2 fields arrive in depends on a choice the Rust lane
 * makes. `pick()` reads the camelCase key and then the snake_case one for every
 * field, so the UI is correct under either.
 */
import type { Server } from '@/store/app-store';

// ── Errors ─────────────────────────────────────────────────────────────────

/** Contract §2. Extend only by adding codes; the UI maps unknown ones to 'unknown'. */
export type IpcErrorCode =
  | 'network_offline'
  | 'server_unreachable'
  | 'server_unavailable'
  | 'session_expired'
  | 'revoked'
  | 'device_limit'
  | 'subscription_required'
  | 'upgrade_required'
  | 'rate_limited'
  | 'invalid_credentials'
  | 'two_factor_required'
  | 'two_factor_invalid'
  | 'cert_pin_failed'
  | 'stealth_failed'
  | 'pq_failed'
  | 'killswitch_failed'
  | 'adapter_failed'
  | 'not_elevated'
  | 'cancelled'
  | 'server_error'
  | 'unknown';

const ERROR_CODES: ReadonlySet<string> = new Set<IpcErrorCode>([
  'network_offline',
  'server_unreachable',
  'server_unavailable',
  'session_expired',
  'revoked',
  'device_limit',
  'subscription_required',
  'upgrade_required',
  'rate_limited',
  'invalid_credentials',
  'two_factor_required',
  'two_factor_invalid',
  'cert_pin_failed',
  'stealth_failed',
  'pq_failed',
  'killswitch_failed',
  'adapter_failed',
  'not_elevated',
  'cancelled',
  'server_error',
  'unknown',
]);

/** The wire shape, field for field (contract §2). */
export interface IpcError {
  code: IpcErrorCode;
  /** Sanitised by Rust, but still secondary: the UI shows `errorCopy(code)`. */
  message: string;
  retryable: boolean;
  retry_after_secs: number | null;
}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Read `camel` first, then `snake` — see the casing note at the top. */
function pick(o: Obj, camel: string, snake: string): unknown {
  return o[camel] !== undefined ? o[camel] : o[snake];
}

const str = (v: unknown): string | null => (typeof v === 'string' ? v : null);
const num = (v: unknown): number | null =>
  typeof v === 'number' && Number.isFinite(v) ? v : null;
const bool = (v: unknown, fallback = false): boolean => (typeof v === 'boolean' ? v : fallback);

/**
 * Normalise anything a command can reject with into an `IpcError`.
 *
 * Accepts the v2 object, a legacy `String` error (the commands outside the
 * contract's list keep those for now), an `Error`, and garbage. A legacy string
 * becomes `code: 'unknown'` exactly as the contract specifies: classifying free
 * text by substring is the thing v2 exists to retire (W2-012 — "connect" in a
 * certificate-pinning warning read as "unable to reach the server").
 */
export function toIpcError(e: unknown): IpcError {
  if (isObj(e) && typeof e.code === 'string') {
    const code = ERROR_CODES.has(e.code) ? (e.code as IpcErrorCode) : 'unknown';
    return {
      code,
      message: str(e.message) ?? '',
      retryable: bool(e.retryable, true),
      retry_after_secs: num(pick(e, 'retryAfterSecs', 'retry_after_secs')),
    };
  }
  const message =
    typeof e === 'string' ? e : e instanceof Error ? e.message : isObj(e) ? str(e.message) ?? '' : '';
  return { code: 'unknown', message, retryable: true, retry_after_secs: null };
}

// ── VPN status ─────────────────────────────────────────────────────────────

export type VpnState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'disconnecting'
  | 'reconnecting'
  | 'switching'
  | 'error';

const VPN_STATES: ReadonlySet<string> = new Set<VpnState>([
  'disconnected',
  'connecting',
  'connected',
  'disconnecting',
  'reconnecting',
  'switching',
  'error',
]);

export type VpnPhase =
  | 'authenticating'
  | 'negotiating_pq'
  | 'starting_stealth'
  | 'handshaking'
  | 'configuring';

const VPN_PHASES: ReadonlySet<string> = new Set<VpnPhase>([
  'authenticating',
  'negotiating_pq',
  'starting_stealth',
  'handshaking',
  'configuring',
]);

/** The route a Multi-Hop session is actually on (contract §1 `multi_hop`). */
export interface LiveMultiHop {
  entryId: string;
  entryName: string;
  exitId: string;
  exitName: string;
}

/** A parsed `get_vpn_status` result / `vpn-status-changed` payload. */
export interface VpnStatus {
  state: VpnState;
  phase: VpnPhase | null;
  reconnectAttempt: number | null;
  reconnectMax: number | null;
  killSwitchBlocking: boolean;
  /**
   * `undefined` = the field was ABSENT (a pre-v2 backend), which must not be
   * read as "no error": it would wipe the error a failed command just reported.
   */
  error: IpcError | null | undefined;
  serverId: string | null;
  multiHop: LiveMultiHop | null;
  /** `null` on a pre-v2 backend: nothing to order by, so it is applied as-is. */
  seq: number | null;
  bytesSent: number;
  bytesReceived: number;
  connectedAt: string | null;
  serverName: string | null;
  stealthActive: boolean;
  quantumActive: boolean;
  /** `undefined` = unknown (older backend), never "fine" — see Dashboard's banner. */
  dnsDegraded: string[] | undefined;
}

/**
 * States a v1 backend can still send while the two lanes land. v2 folds the
 * first two into `connecting` (the detail moves to `phase`), and never sends
 * the last two — they were in the union but no Rust path produced them (W2-004).
 */
const LEGACY_STATES: Record<string, { state: VpnState; phase?: VpnPhase; blocking?: boolean }> = {
  authenticating: { state: 'connecting', phase: 'authenticating' },
  stealth_connecting: { state: 'connecting', phase: 'starting_stealth' },
  rekeying: { state: 'connected' },
  kill_switch_active: { state: 'disconnected', blocking: true },
};

function parseMultiHop(v: unknown): LiveMultiHop | null {
  if (!isObj(v)) return null;
  const entryId = str(pick(v, 'entryId', 'entry_id'));
  const exitId = str(pick(v, 'exitId', 'exit_id'));
  if (!entryId || !exitId) return null;
  return {
    entryId,
    exitId,
    entryName: str(pick(v, 'entryName', 'entry_name')) ?? '',
    exitName: str(pick(v, 'exitName', 'exit_name')) ?? '',
  };
}

/** Returns null for anything that is not a recognisable status (never throws). */
export function parseVpnStatus(raw: unknown): VpnStatus | null {
  if (!isObj(raw) || typeof raw.state !== 'string') return null;
  const legacy = LEGACY_STATES[raw.state];
  if (!legacy && !VPN_STATES.has(raw.state)) return null;
  const state: VpnState = legacy ? legacy.state : (raw.state as VpnState);

  const rawPhase = str(raw.phase);
  const phase = rawPhase && VPN_PHASES.has(rawPhase) ? (rawPhase as VpnPhase) : legacy?.phase ?? null;

  const rawError = raw.error;
  const error = rawError === undefined ? undefined : rawError === null ? null : toIpcError(rawError);

  const blocking = pick(raw, 'killSwitchBlocking', 'kill_switch_blocking');
  const degraded = pick(raw, 'dnsDegraded', 'dns_degraded');

  return {
    state,
    phase,
    reconnectAttempt: num(pick(raw, 'reconnectAttempt', 'reconnect_attempt')),
    reconnectMax: num(pick(raw, 'reconnectMax', 'reconnect_max')),
    killSwitchBlocking: bool(blocking, legacy?.blocking ?? false),
    error,
    serverId: str(pick(raw, 'serverId', 'server_id')),
    multiHop: parseMultiHop(pick(raw, 'multiHop', 'multi_hop')),
    seq: num(raw.seq),
    bytesSent: num(pick(raw, 'bytesSent', 'bytes_sent')) ?? 0,
    bytesReceived: num(pick(raw, 'bytesReceived', 'bytes_received')) ?? 0,
    connectedAt: str(pick(raw, 'connectedAt', 'connected_at')),
    serverName: str(pick(raw, 'serverName', 'server_name')),
    stealthActive: bool(pick(raw, 'stealthActive', 'stealth_active')),
    quantumActive: bool(pick(raw, 'quantumActive', 'quantum_active')),
    dnsDegraded: Array.isArray(degraded)
      ? degraded.filter((d): d is string => typeof d === 'string')
      : undefined,
  };
}

/** `get_vpn_stats` (snake_case on the wire; commands/vpn.rs `VpnStats`). */
export interface VpnStats {
  bytesIn: number;
  bytesOut: number;
  uptimeSeconds: number;
  latencyMs: number | null;
}

export function parseVpnStats(raw: unknown): VpnStats | null {
  if (!isObj(raw)) return null;
  return {
    bytesIn: num(pick(raw, 'bytesIn', 'bytes_in')) ?? 0,
    bytesOut: num(pick(raw, 'bytesOut', 'bytes_out')) ?? 0,
    uptimeSeconds: num(pick(raw, 'uptimeSeconds', 'uptime_seconds')) ?? 0,
    latencyMs: num(pick(raw, 'currentLatencyMs', 'current_latency_ms')),
  };
}

/** `session-expired` (contract §3.3). An unrecognised reason is treated as expiry. */
export function parseSessionExpired(raw: unknown): 'expired' | 'revoked' {
  return isObj(raw) && raw.reason === 'revoked' ? 'revoked' : 'expired';
}

// ── Servers ────────────────────────────────────────────────────────────────

/**
 * `get_servers` → `Server`. The Rust `ServerInfo` is camelCase; snake_case is
 * read second. A row without an id is dropped rather than rendered with an
 * undefined key (and an undefined `lastServerId` if the user picked it).
 */
export function parseServer(raw: unknown): Server | null {
  if (!isObj(raw)) return null;
  const id = str(raw.id);
  if (!id) return null;
  const minPlan = str(pick(raw, 'minPlan', 'min_plan'));
  return {
    id,
    name: str(raw.name) ?? '',
    country: str(raw.country) ?? '',
    countryCode: str(pick(raw, 'countryCode', 'country_code')) ?? '',
    city: str(raw.city) ?? '',
    hostname: str(raw.hostname) ?? undefined,
    ipAddress: str(pick(raw, 'ipAddress', 'ip_address')) ?? undefined,
    port: num(raw.port) ?? undefined,
    load: num(raw.load) ?? 0,
    isPremium: bool(pick(raw, 'isPremium', 'is_premium')),
    minPlan: minPlan ?? undefined,
    isHighSpeed: bool(pick(raw, 'isHighSpeed', 'is_high_speed')),
    isPortForwarding: bool(pick(raw, 'isPortForwarding', 'is_port_forwarding')),
    isOnline: bool(pick(raw, 'isOnline', 'is_online'), true),
    isAccessible: bool(raw.accessible, true),
  };
}

export function parseServers(raw: unknown): Server[] {
  if (!Array.isArray(raw)) return [];
  return raw.map(parseServer).filter((s): s is Server => s !== null);
}

/**
 * The best server: online and accessible, lowest load, then name, then id.
 * The SAME rule as Rust's `pick_quick_connect_server` (vpn.rs), so the Connect
 * button, auto-connect and the tray land on the same node (W2-028); both sides
 * run `src-tauri/src/commands/fixtures/best_server.json` (REVIEW-WIN-008).
 *
 * Names and ids compare with `<`, by UTF-16 code unit, never `localeCompare`:
 * Rust compares the same code units, while a locale-aware order follows the
 * user's locale and disagreed with Rust on ties.
 */
export function pickBestServer(servers: readonly Server[]): Server | null {
  let best: Server | null = null;
  for (const s of servers) {
    if (!s.isOnline || !s.isAccessible) continue;
    if (!best || compareBestServer(s, best) < 0) best = s;
  }
  return best;
}

function compareBestServer(a: Server, b: Server): number {
  if (a.load !== b.load) return a.load - b.load;
  if (a.name !== b.name) return a.name < b.name ? -1 : 1;
  if (a.id !== b.id) return a.id < b.id ? -1 : 1;
  return 0;
}
