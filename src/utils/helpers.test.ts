import { describe, it, expect } from 'vitest';
import {
  settingsFromRust,
  settingsToRust,
  formatBytes,
  formatUptime,
  formatDate,
  anonAccountNumber,
  anonymityPatch,
  formatAccountNumber,
  isValidMtu,
  maskAccountNumber,
  resolveAnonymousAccount,
  type RustSettings,
} from './helpers';

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

describe('crash reports (C-3) crash_reports_enabled ↔ crashReportsEnabled', () => {
  it('defaults OFF when the key is absent — Rust omits it while false, and no pre-opt-in file has it', () => {
    expect('crash_reports_enabled' in base).toBe(false);
    expect(settingsFromRust(base).crashReportsEnabled).toBe(false);
  });

  it('maps an explicit true, and settingsToRust always writes the key so a full save cannot drop the choice', () => {
    const on = settingsFromRust({ ...base, crash_reports_enabled: true });
    expect(on.crashReportsEnabled).toBe(true);
    expect(settingsToRust(on).crash_reports_enabled).toBe(true);
    expect(settingsToRust(settingsFromRust(base)).crash_reports_enabled).toBe(false);
  });
});

// friendlyVpnError (substring-matching free text) is gone: errors are mapped by
// their v2 code in lib/errors.ts (W2-012), tested in lib/errors.test.ts.

describe('Custom DNS on/off (P1-parity-042): Rust has no flag, so off = null on the wire', () => {
  it('a non-empty list from Rust reads as ON', () => {
    const s = settingsFromRust({ ...base, custom_dns: ['1.1.1.1'] });
    expect(s.customDnsEnabled).toBe(true);
    expect(s.customDns).toEqual(['1.1.1.1']);
  });

  it('switched OFF sends null but the addresses stay in the store', () => {
    const s = { ...settingsFromRust({ ...base, custom_dns: ['1.1.1.1', '8.8.8.8'] }), customDnsEnabled: false };
    expect(settingsToRust(s).custom_dns).toBeNull();
    expect(s.customDns).toEqual(['1.1.1.1', '8.8.8.8']);
  });

  it('switched ON with no addresses sends null, never an empty list', () => {
    const s = { ...settingsFromRust(base), customDnsEnabled: true, customDns: [] };
    expect(settingsToRust(s).custom_dns).toBeNull();
  });
});

describe('formatting (iOS / Android FormatUtils parity, W2-031)', () => {
  it('uptime is MM:SS under an hour and H:MM:SS above', () => {
    expect(formatUptime(0)).toBe('00:00');
    expect(formatUptime(65)).toBe('01:05');
    expect(formatUptime(3599)).toBe('59:59');
    expect(formatUptime(3600)).toBe('1:00:00');
    expect(formatUptime(3 * 3600 + 7 * 60 + 9)).toBe('3:07:09');
  });

  it('bytes: KB and MB with one decimal, GB with two', () => {
    expect(formatBytes(0)).toBe('0 B');
    expect(formatBytes(512)).toBe('512 B');
    expect(formatBytes(1536)).toBe('1.5 KB');
    expect(formatBytes(5 * 1024 * 1024)).toBe('5.0 MB');
    expect(formatBytes(1.5 * 1024 ** 3)).toBe('1.50 GB');
  });

  it('dates read "MMM d, yyyy", and a bare calendar date is not shifted a day by the timezone', () => {
    expect(formatDate('2026-07-31')).toBe('Jul 31, 2026');
    expect(formatDate('')).toBeNull();
    expect(formatDate('not a date')).toBeNull();
    expect(formatDate('2026-01-05T12:00:00Z')).toMatch(/^Jan [45], 2026$/);
  });

  it('MTU accepts 1280–1500 only', () => {
    expect(isValidMtu('1280')).toBe(true);
    expect(isValidMtu('1500')).toBe(true);
    expect(isValidMtu('1279')).toBe(false);
    expect(isValidMtu('14')).toBe(false);
  });
});

describe('anonymous identity (P1-parity-007)', () => {
  const synthetic = 'anon_123456789012345678901234@anonymous.local';

  it('recognises the synthetic address and extracts the account number', () => {
    expect(anonAccountNumber(synthetic)).toBe('123456789012345678901234');
    expect(anonAccountNumber('someone@example.com')).toBeNull();
    expect(anonAccountNumber(null)).toBeNull();
  });

  it('formats the account number in six space-separated groups of four', () => {
    expect(formatAccountNumber('123456789012345678901234')).toBe('1234 5678 9012 3456 7890 1234');
    expect(formatAccountNumber('1234|5678')).toBe('1234 5678');
  });

  it('masks every group but the last by default (Account API item 86)', () => {
    expect(maskAccountNumber('123456789012345678901234')).toBe('•••• •••• •••• •••• •••• 1234');
  });
});

/** Account API contract 2026-10-01, item 86: `/auth/me` on an old and a new server. */
describe('anonymous account resolution (item 86)', () => {
  const synthetic = 'anon_123456789012345678901234@anonymous.local';
  const unknown = { isAnonymous: null, accountNumber: null };

  it('an old server (no new fields) is read from the email, as before', () => {
    expect(anonymityPatch({})).toEqual({});
    expect(resolveAnonymousAccount(unknown, synthetic)).toEqual({
      isAnon: true,
      accountNumber: '123456789012345678901234',
    });
    expect(resolveAnonymousAccount(unknown, 'me@example.com')).toEqual({ isAnon: false, accountNumber: null });
  });

  it("a new server's fields win, and the number comes from accountNumber", () => {
    const patch = anonymityPatch({ is_anonymous: true, account_number: '999988887777666655554444' });
    expect(patch).toEqual({ isAnonymous: true, accountNumber: '999988887777666655554444' });
    // Phase 2: the email no longer carries the number at all.
    expect(resolveAnonymousAccount({ isAnonymous: true, accountNumber: '999988887777666655554444' }, null)).toEqual({
      isAnon: true,
      accountNumber: '999988887777666655554444',
    });
    expect(resolveAnonymousAccount({ isAnonymous: false, accountNumber: null }, 'me@example.com')).toEqual({
      isAnon: false,
      accountNumber: null,
    });
  });

  it('a server that sends no number (null, the email carrying none) still reads as anonymous', () => {
    const patch = anonymityPatch({ is_anonymous: true, account_number: null });
    expect(patch).toEqual({ isAnonymous: true });
    expect(resolveAnonymousAccount({ isAnonymous: true, accountNumber: null }, 'member@anonymous.local')).toEqual({
      isAnon: true,
      accountNumber: null,
    });
  });

  it('a synthetic email is never treated as a real one, whatever the server says', () => {
    expect(resolveAnonymousAccount({ isAnonymous: false, accountNumber: null }, synthetic).isAnon).toBe(true);
  });

  it('only the documented 24 digits are taken as an account number', () => {
    expect(anonymityPatch({ is_anonymous: null, account_number: null })).toEqual({});
    expect(anonymityPatch({ account_number: '1234' })).toEqual({});
    expect(anonymityPatch({ account_number: '1234 5678 9012 3456 7890 1234' })).toEqual({});
  });
});
