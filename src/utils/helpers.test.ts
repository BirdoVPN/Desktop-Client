import { describe, it, expect } from 'vitest';
import { settingsFromRust, type RustSettings } from './helpers';

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
