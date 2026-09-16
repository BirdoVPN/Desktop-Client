import { describe, it, expect } from 'vitest';
import { settingsFromRust, settingsToRust, friendlyVpnError, type RustSettings } from './helpers';

// A complete RustSettings payload; individual tests override single fields
// (and cast to RustSettings when deliberately omitting one to exercise the
// `?? default` fallbacks for older settings files).
const base: RustSettings = {
  killswitch_enabled: true,
  auto_connect: false,
  autostart: false,
  start_minimized: false,
  notifications_enabled: true,
  preferred_server_id: null,
  split_tunneling_enabled: false,
  split_tunnel_apps: [],
  custom_dns: null,
  local_network_sharing: false,
  wireguard_port: 'auto',
  wireguard_mtu: 0,
  multi_hop_enabled: false,
  multi_hop_entry_node_id: null,
  multi_hop_exit_node_id: null,
  stealth_mode: false,
  quantum_protection: true,
  lockdown_mode: true,
};

describe('settingsFromRust — v1.3.30/31 default guarantees', () => {
  it('defaults post-quantum ON when the field is absent (older settings file)', () => {
    const { quantum_protection: _omit, ...withoutPq } = base;
    const out = settingsFromRust(withoutPq as RustSettings);
    expect(out.quantumProtection).toBe(true);
  });

  it('preserves an explicit post-quantum=false (a real user choice)', () => {
    const out = settingsFromRust({ ...base, quantum_protection: false });
    expect(out.quantumProtection).toBe(false);
  });

  it('defaults kill switch ON when the field is absent', () => {
    const { killswitch_enabled: _omit, ...withoutKs } = base;
    const out = settingsFromRust(withoutKs as RustSettings);
    expect(out.killSwitchEnabled).toBe(true);
  });

  it('maps the remaining fields snake_case → camelCase', () => {
    const out = settingsFromRust({
      ...base,
      wireguard_port: '51820',
      wireguard_mtu: 1380,
      stealth_mode: true,
      multi_hop_enabled: true,
    });
    expect(out.wireGuardPort).toBe('51820');
    expect(out.wireGuardMtu).toBe(1380);
    expect(out.stealthMode).toBe(true);
    expect(out.multiHopEnabled).toBe(true);
  });
});

describe('BirdoShield (D18) dns_filtering ↔ dnsFiltering', () => {
  it('defaults OFF when the key is absent — the Rust struct omits it while false, and pre-D18 files never had it', () => {
    // `base` deliberately has no dns_filtering: that IS the wire shape for OFF.
    expect('dns_filtering' in base).toBe(false);
    expect(settingsFromRust(base).dnsFiltering).toBe(false);
  });

  it('maps an explicit dns_filtering: true to dnsFiltering: true', () => {
    expect(settingsFromRust({ ...base, dns_filtering: true }).dnsFiltering).toBe(true);
  });

  it('settingsToRust always writes dns_filtering, so a save cannot silently drop the choice', () => {
    const on = settingsFromRust({ ...base, dns_filtering: true });
    expect(settingsToRust(on).dns_filtering).toBe(true);
    const off = settingsFromRust(base);
    expect(settingsToRust(off).dns_filtering).toBe(false);
  });

  it('round-trips through both directions without touching neighbouring flags', () => {
    const rs = settingsToRust(settingsFromRust({ ...base, dns_filtering: true, stealth_mode: true }));
    expect(rs.dns_filtering).toBe(true);
    expect(rs.stealth_mode).toBe(true);
    expect(rs.quantum_protection).toBe(true);
    expect(rs.lockdown_mode).toBe(true);
  });
});

describe('friendlyVpnError — surfaces the real reason', () => {
  it('maps known patterns to friendly copy', () => {
    expect(friendlyVpnError('Device limit reached (1 devices for RECON plan)')).toMatch(
      /Subscription limit|device/i,
    );
    expect(friendlyVpnError('handshake did not complete')).toMatch(/timed out|busy/i);
  });

  it("surfaces the server's clean message instead of the generic fallback", () => {
    // This is exactly the message the live outage produced — it must reach the user.
    expect(friendlyVpnError('Failed to configure VPN server. Please try again.')).toBe(
      'Failed to configure VPN server. Please try again.',
    );
    expect(
      friendlyVpnError('All VPN servers are currently offline. Please try again shortly.'),
    ).toBe('All VPN servers are currently offline. Please try again shortly.');
  });

  it('adds trailing punctuation to a clean fragment', () => {
    expect(friendlyVpnError('Server is rebooting')).toBe('Server is rebooting.');
  });

  it('falls back to generic for empty or obviously-technical errors', () => {
    expect(friendlyVpnError('')).toBe('Connection failed. Please try again.');
    expect(
      friendlyVpnError("thread 'main' panicked at src/x.rs:1:1: boom"),
    ).toBe('Connection failed. Please try again.');
    expect(friendlyVpnError('connect: os error 10061')).toBe(
      'Connection failed. Please try again.',
    );
  });
});
