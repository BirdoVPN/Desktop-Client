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
 * Format bytes to a human-readable string (B, KB, MB, GB, TB).
 */
export function formatBytes(bytes: number): string {
  if (bytes <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / Math.pow(1024, i)).toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

/**
 * Format seconds to HH:MM:SS.
 */
export function formatUptime(seconds: number): string {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = Math.floor(seconds % 60);
  return [h, m, s].map((v) => String(v).padStart(2, '0')).join(':');
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
 * Validate a WireGuard port number.
 */
export function isValidPort(port: string): boolean {
  const n = Number(port);
  return Number.isInteger(n) && n >= 1 && n <= 65535;
}

/**
 * Validate a WireGuard MTU value.
 */
export function isValidMtu(mtu: string): boolean {
  const n = Number(mtu);
  return Number.isInteger(n) && n >= 1280 && n <= 1500;
}

/**
 * Extract a user-facing message from an unknown error value.
 */
export function extractErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Map raw Rust/backend VPN errors to user-friendly messages.
 * Prevents leaking server IPs, hostnames, or internal details in the UI.
 */
export function friendlyVpnError(error: unknown): string {
  const original = extractErrorMessage(error).trim();
  const raw = original.toLowerCase();
  if (raw.includes('multi-hop is temporarily unavailable') || raw.includes('multi-hop unavailable')) return 'Multi-Hop unavailable on this route. Try a different entry or exit server.';
  if (raw.includes('mesh') && raw.includes('forwarding')) return 'Failed to set up Multi-Hop forwarding between servers. Try a different exit.';
  if (raw.includes('sovereign')) return 'Multi-Hop requires a Sovereign subscription.';
  if (raw.includes('connection refused') || raw.includes('connect to')) return 'Unable to reach the VPN server. Please try another server.';
  if (raw.includes('handshake') || raw.includes('timeout')) return 'Connection timed out. The server may be busy — try again or switch servers.';
  if (raw.includes('authentication') || raw.includes('unauthorized') || raw.includes('401')) return 'Authentication failed. Please log in again.';
  if (raw.includes('access denied') || raw.includes('forbidden') || raw.includes('403')) return 'Access denied for this connection. Please check your subscription, device limit, or account permissions.';
  if (raw.includes('no servers') || raw.includes('server list')) return 'No servers available. Check your internet connection.';
  if (raw.includes('already connected') || raw.includes('already active')) return 'VPN is already connected.';
  if (raw.includes('dns') || raw.includes('resolve')) return 'DNS resolution failed. Check your network settings.';
  if (raw.includes('permission') || raw.includes('elevation') || raw.includes('privilege')) return 'Administrator permission is required for this operation.';
  if (raw.includes('wintun') || raw.includes('loadlibrary') || raw.includes('driver') || raw.includes('adapter') || raw.includes('tunnel')) return 'Could not start the VPN network adapter. Try reinstalling, or temporarily disable antivirus blocking the Wintun driver.';
  if (raw.includes('kill switch') || raw.includes('killswitch')) return 'Kill switch error. Please disconnect and try again.';
  if (raw.includes('subscription') || raw.includes('plan') || raw.includes('device limit')) return 'Subscription limit reached. Upgrade your plan or disconnect other devices.';

  // Fallback: surface the server's OWN message when it reads like a clean,
  // user-facing sentence. The backend's connect rejections (e.g. "Failed to
  // configure VPN server. Please try again.", "All VPN servers are currently
  // offline…") and the Rust layer's errors are already PII-sanitized, so
  // showing them tells the user the actual reason instead of an opaque
  // "Connection failed". Guard against empty / oversized / obviously-technical
  // strings (stack traces, raw "error:" dumps) which we'd rather not surface.
  const looksTechnical = /\b(panic|thread '|stack backtrace|os error|0x[0-9a-f]{4}|undefined|null pointer|\bat\s+[A-Za-z]:\\)/i.test(
    original,
  );
  if (original && original.length <= 160 && /\s/.test(original) && !looksTechnical) {
    // Ensure it ends with sentence punctuation for a tidy toast.
    return /[.!?]$/.test(original) ? original : `${original}.`;
  }
  return 'Connection failed. Please try again.';
}

// ── Settings snake_case ↔ camelCase mapping ────────────────────────

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
    protocol: 'wireguard',
    localNetworkSharing: rs.local_network_sharing ?? false,
    wireGuardPort: rs.wireguard_port ?? 'auto',
    wireGuardMtu: rs.wireguard_mtu ?? 0,
    multiHopEnabled: rs.multi_hop_enabled ?? false,
    multiHopEntryNodeId: rs.multi_hop_entry_node_id ?? null,
    multiHopExitNodeId: rs.multi_hop_exit_node_id ?? null,
    stealthMode: rs.stealth_mode ?? false,
    // Post-quantum is ON by default (matches Rust `AppSettings::default()`); the
    // `?? true` only applies if the field is absent from an older settings file.
    quantumProtection: rs.quantum_protection ?? true,
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
    custom_dns: s.customDns,
    local_network_sharing: s.localNetworkSharing,
    wireguard_port: s.wireGuardPort,
    wireguard_mtu: s.wireGuardMtu,
    multi_hop_enabled: s.multiHopEnabled,
    multi_hop_entry_node_id: s.multiHopEntryNodeId,
    multi_hop_exit_node_id: s.multiHopExitNodeId,
    stealth_mode: s.stealthMode,
    quantum_protection: s.quantumProtection,
  };
}
