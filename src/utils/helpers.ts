/**
 * Convert a 2-letter ISO country code to a flag emoji.
 * Uses Unicode Regional Indicator symbols.
 * Mirrors the Android FlagUtils.kt implementation.
 */
export function countryCodeToFlag(countryCode: string): string {
  if (!countryCode || countryCode.length !== 2) return '🌐';

  const upper = countryCode.toUpperCase();
  if (!/^[A-Z]{2}$/.test(upper)) return '🌐';

  // Regex above guarantees two ASCII letters, so codePointAt returns numbers,
  // but satisfy the compiler without non-null assertions.
  const cp0 = upper.codePointAt(0) ?? 0x41;
  const cp1 = upper.codePointAt(1) ?? 0x41;
  const first = cp0 - 0x41 + 0x1f1e6;
  const second = cp1 - 0x41 + 0x1f1e6;

  return String.fromCodePoint(first) + String.fromCodePoint(second);
}

/**
 * Bytes for the stats tiles: KB/MB with one decimal, GB with two — the iOS /
 * Android `FormatUtils` rule (W2-031), so the same session reads the same on
 * every client.
 */
export function formatBytes(bytes: number): string {
  if (!(bytes > 0)) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const places = i === 0 ? 0 : i >= 3 ? 2 : 1;
  return `${(bytes / Math.pow(1024, i)).toFixed(places)} ${units[i]}`;
}

/** Session duration as MM:SS under an hour, H:MM:SS above (iOS HomeView). */
export function formatUptime(seconds: number): string {
  const total = Math.max(0, Math.floor(seconds));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (v: number) => String(v).padStart(2, '0');
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}

/**
 * A date as "MMM d, yyyy" (P1-parity canonical; was `yyyy-MM-dd`). A bare
 * `yyyy-MM-dd` is a calendar date, not an instant, so it is formatted in UTC —
 * reading it as local midnight would show the day before for anyone west of
 * Greenwich.
 */
export function formatDate(raw: string | null | undefined): string | null {
  const v = (raw ?? '').trim();
  if (!v) return null;
  const dateOnly = /^\d{4}-\d{2}-\d{2}$/.test(v);
  const parsed = new Date(dateOnly ? `${v}T00:00:00Z` : v);
  if (Number.isNaN(parsed.getTime())) return null;
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    ...(dateOnly ? { timeZone: 'UTC' } : {}),
  }).format(parsed);
}

/**
 * Anonymous accounts carry a synthetic email `anon_<24-digit-id>@anonymous.local`,
 * and the 24 digits are the account's ONLY recovery credential. Every surface
 * that shows an identity must go through this, so the synthetic address (and
 * the credential inside it) is never rendered raw — the Connect screen's top
 * bar used to print the first ~20 characters of it (P1-parity-007).
 */
const ANON_EMAIL_RE = /^anon_(\d{24})@anonymous\.local$/i;
export function anonAccountNumber(email: string | null | undefined): string | null {
  if (!email) return null;
  const m = ANON_EMAIL_RE.exec(email.trim());
  return m ? m[1] : null;
}

/** What `get_auth_state` says about anonymity (Rust `AuthState`, item 86). */
export interface AuthStateAnonymity {
  is_anonymous?: boolean | null;
  account_number?: string | null;
}

/**
 * The store patch for item 86's fields, with only what the server SAID: an
 * absent field leaves the store alone, so a cycle whose profile fetch failed
 * does not erase a good answer.
 */
export function anonymityPatch(st: AuthStateAnonymity): { isAnonymous?: boolean; accountNumber?: string } {
  const patch: { isAnonymous?: boolean; accountNumber?: string } = {};
  if (typeof st.is_anonymous === 'boolean') patch.isAnonymous = st.is_anonymous;
  if (typeof st.account_number === 'string' && /^\d{24}$/.test(st.account_number)) {
    patch.accountNumber = st.account_number;
  }
  return patch;
}

/**
 * Whether the signed-in account is anonymous, and its number (Account API
 * contract item 86). The server's `isAnonymous` / `accountNumber` are used
 * when it sends them; a backend that predates them is read from the synthetic
 * email, as before. The synthetic email always means anonymous — it exists
 * only on anonymous accounts — so it is never rendered whatever else is said.
 */
export function resolveAnonymousAccount(
  account: { isAnonymous: boolean | null; accountNumber: string | null },
  email: string | null,
): { isAnon: boolean; accountNumber: string | null } {
  const fromEmail = anonAccountNumber(email);
  const isAnon = fromEmail !== null || account.isAnonymous === true;
  return { isAnon, accountNumber: isAnon ? account.accountNumber ?? fromEmail : null };
}

/** "123456789012…" → "1234 5678 9012 …": six groups of four, space-separated (canonical). */
export function formatAccountNumber(digits: string): string {
  return digits.replace(/\D/g, '').replace(/(\d{4})(?=\d)/g, '$1 ');
}

/** The masked form shown by default: every group hidden but the last. */
export function maskAccountNumber(digits: string): string {
  return formatAccountNumber(digits).replace(/\d(?=.*\s)/g, '•');
}

/**
 * Validate an IPv4 address string.
 * Rejects loopback, link-local, multicast, and wildcard addresses (matching Android InputValidator).
 */
export function isValidDnsAddress(ip: string): { valid: boolean; error?: string } {
  const parts = ip.split('.');
  if (parts.length !== 4) return { valid: false, error: 'Enter a valid IPv4 address (e.g. 1.1.1.1)' };

  // Validate each octet: must be a number 0-255 with no leading zeros
  const nums: number[] = [];
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (isNaN(n) || n < 0 || n > 255 || String(n) !== parts[i]) {
      return { valid: false, error: 'Enter a valid IPv4 address (e.g. 1.1.1.1)' };
    }
    nums.push(n);
  }

  const [a, b] = nums;

  // Reject loopback (127.x.x.x)
  if (a === 127) return { valid: false, error: 'Loopback addresses are not allowed' };
  // Reject link-local (169.254.x.x)
  if (a === 169 && b === 254) return { valid: false, error: 'Link-local addresses are not allowed' };
  // Reject multicast (224-239.x.x.x)
  if (a >= 224 && a <= 239) return { valid: false, error: 'Multicast addresses are not allowed' };
  // Reject wildcard (0.0.0.0)
  if (nums.every((n) => n === 0)) return { valid: false, error: 'Wildcard address is not allowed' };
  // Reject broadcast (255.255.255.255)
  if (nums.every((n) => n === 255)) return { valid: false, error: 'Broadcast address is not allowed' };

  return { valid: true };
}

/**
 * Whether a valid Custom DNS address is on a private network (10/8,
 * 172.16/12, 192.168/16): the user's own resolver, a Pi-hole for instance.
 * Rust reaches one outside the tunnel, and only with Local Network Sharing on
 * (`wfp_policy::split_resolvers`, REVIEW-WIN2-006).
 */
export function isPrivateDnsAddress(ip: string): boolean {
  if (!isValidDnsAddress(ip).valid) return false;
  const [a, b] = ip.split('.').map(Number);
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
}

/**
 * Validate a WireGuard port number.
 */
export function isValidPort(port: string): boolean {
  const n = Number(port);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

/** WireGuard MTU range the tunnel builder accepts. */
export function isValidMtu(mtu: string): boolean {
  const n = Number(mtu);
  return Number.isInteger(n) && n >= 1280 && n <= 1500;
}

// ── Settings snake_case ↔ camelCase mapping ────────────────────────

/**
 * Platform gate for Windows-only features (split tunneling is enforced via
 * WFP, which has no Linux/macOS implementation yet). The Tauri webview UA
 * reliably contains "Windows" on Windows builds.
 */
export function isWindowsPlatform(): boolean {
  return typeof navigator !== 'undefined' && navigator.userAgent.includes('Windows');
}

/** Shape returned by the Rust `get_settings` command (snake_case). */
export interface RustSettings {
  killswitch_enabled: boolean;
  auto_connect: boolean;
  autostart: boolean;
  start_minimized: boolean;
  notifications_enabled: boolean;
  preferred_server_id: string | null;
  split_tunneling_enabled: boolean;
  split_tunnel_apps: string[];
  custom_dns: string[] | null;
  local_network_sharing: boolean;
  wireguard_port: string;
  wireguard_mtu: number;
  multi_hop_enabled: boolean;
  multi_hop_entry_node_id: string | null;
  multi_hop_exit_node_id: string | null;
  stealth_mode: boolean;
  quantum_protection: boolean;
  // BirdoShield (D18). Optional on the READ side only: the Rust struct omits
  // the key while it is false (`skip_serializing_if`) so a pre-D18 settings
  // file keeps its HMAC; settingsToRust always writes it.
  dns_filtering?: boolean;
  // LOCKDOWN (always-on kill switch). MUST round-trip: `save_settings` replaces
  // the whole Rust struct, so any field missing here is silently rewritten to
  // its serde default on every save — which made `false` unrepresentable and
  // force-reset lockdown on each settings write. Add any future Rust
  // AppSettings field here too, for the same reason.
  lockdown_mode: boolean;
  // Crash reports (opt-in, C-3). Optional on the READ side for the same reason
  // as dns_filtering: Rust omits the key while it is false.
  crash_reports_enabled?: boolean;
}

import type { AppSettings } from '../store/app-store';

/** Convert Rust snake_case settings to store camelCase. */
export function settingsFromRust(rs: RustSettings): AppSettings {
  return {
    killSwitchEnabled: rs.killswitch_enabled ?? true,
    autoConnect: rs.auto_connect ?? false,
    autostart: rs.autostart ?? false,
    startMinimized: rs.start_minimized ?? false,
    notifications: rs.notifications_enabled ?? true,
    // Frontend-only notification detail sub-toggles: the Rust backend doesn't
    // round-trip these, so default them here. The store's hydrateSettings
    // preserves any localStorage-persisted value on top of this.
    showIpInNotification: false,
    showLocationInNotification: false,
    preferredServerId: rs.preferred_server_id ?? null,
    splitTunnelingEnabled: rs.split_tunneling_enabled ?? false,
    splitTunnelApps: rs.split_tunnel_apps ?? [],
    customDns: rs.custom_dns ?? null,
    // Rust has no on/off flag: a non-empty list IS "on" on the wire.
    customDnsEnabled: (rs.custom_dns ?? []).length > 0,
    protocol: 'wireguard',
    localNetworkSharing: rs.local_network_sharing ?? false,
    wireGuardPort: rs.wireguard_port ?? 'auto',
    wireGuardMtu: rs.wireguard_mtu ?? 0,
    multiHopEnabled: rs.multi_hop_enabled ?? false,
    multiHopEntryNodeId: rs.multi_hop_entry_node_id ?? null,
    multiHopExitNodeId: rs.multi_hop_exit_node_id ?? null,
    stealthMode: rs.stealth_mode ?? false,
    // BirdoShield is opt-in; the key is absent (not false) while off.
    dnsFiltering: rs.dns_filtering ?? false,
    // Post-quantum is ON by default (matches Rust `AppSettings::default()`); the
    // `?? true` only applies if the field is absent from an older settings file.
    quantumProtection: rs.quantum_protection ?? true,
    // Matches the Rust serde default (default_true) for older settings files.
    lockdownMode: rs.lockdown_mode ?? true,
    // Opt-in; absent (not false) while off, and absent on every pre-opt-in file.
    crashReportsEnabled: rs.crash_reports_enabled ?? false,
  };
}

/** Convert store camelCase settings to Rust snake_case for `save_settings`. */
export function settingsToRust(s: AppSettings): RustSettings {
  return {
    killswitch_enabled: s.killSwitchEnabled,
    auto_connect: s.autoConnect,
    autostart: s.autostart,
    start_minimized: s.startMinimized,
    notifications_enabled: s.notifications,
    preferred_server_id: s.preferredServerId,
    split_tunneling_enabled: s.splitTunnelingEnabled,
    split_tunnel_apps: s.splitTunnelApps,
    // Switched off = null on the wire, whatever addresses are kept locally.
    custom_dns: s.customDnsEnabled && (s.customDns ?? []).length > 0 ? s.customDns : null,
    local_network_sharing: s.localNetworkSharing,
    wireguard_port: s.wireGuardPort,
    wireguard_mtu: s.wireGuardMtu,
    multi_hop_enabled: s.multiHopEnabled,
    multi_hop_entry_node_id: s.multiHopEntryNodeId,
    multi_hop_exit_node_id: s.multiHopExitNodeId,
    stealth_mode: s.stealthMode,
    quantum_protection: s.quantumProtection,
    dns_filtering: s.dnsFiltering,
    lockdown_mode: s.lockdownMode,
    // Always written, so a full save can never silently drop the user's choice.
    crash_reports_enabled: s.crashReportsEnabled,
  };
}
