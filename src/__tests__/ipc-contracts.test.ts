/**
 * L-10: IPC contract integration test scaffold
 *
 * These tests verify that the frontend's invoke() calls match the
 * Rust #[tauri::command] signatures.
 *
 * Two layers:
 *  1. The per-command describe blocks below exercise the invoke() call
 *     SHAPES (command name + argument object) against the shared Tauri mock.
 *  2. The "command registry cross-check" block at the bottom reads the real
 *     Rust `generate_handler!` list out of src-tauri/src/main.rs and asserts
 *     every command the frontend invokes is actually registered there. That
 *     turns this file from a mock-only tautology into a genuine cross-language
 *     contract: a frontend invoke('foo') whose #[tauri::command] was never
 *     wired into generate_handler! now fails CI instead of only blowing up at
 *     runtime with "command foo not found".
 *
 * Run: npx vitest run src/__tests__/ipc-contracts.test.ts
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { invoke } from '@tauri-apps/api/core';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';

// Auto-mock via __mocks__/@tauri-apps/api/core.ts
vi.mock('@tauri-apps/api/core');

const mockedInvoke = vi.mocked(invoke);

beforeEach(() => {
  mockedInvoke.mockReset();
  mockedInvoke.mockResolvedValue(undefined);
});

describe('IPC Contract: Authentication', () => {
  it('login sends correct payload shape', async () => {
    mockedInvoke.mockResolvedValueOnce({
      success: true,
      email: 'test@example.com',
      tokens: { access_token: 'a', refresh_token: 'r' },
    });

    await invoke('login', {
      request: { email: 'test@example.com', password: 'pass123' },
    });

    expect(mockedInvoke).toHaveBeenCalledWith('login', {
      request: { email: 'test@example.com', password: 'pass123' },
    });
  });

  it('logout requires no arguments', async () => {
    await invoke('logout');
    expect(mockedInvoke).toHaveBeenCalledWith('logout');
  });

  it('get_auth_state requires no arguments', async () => {
    mockedInvoke.mockResolvedValueOnce({
      is_authenticated: false,
      email: null,
    });
    await invoke('get_auth_state');
    expect(mockedInvoke).toHaveBeenCalledWith('get_auth_state');
  });
});

describe('IPC Contract: VPN Operations', () => {
  it('connect_vpn sends server_id', async () => {
    mockedInvoke.mockResolvedValueOnce({ success: true });

    await invoke('connect_vpn', { serverId: 'us-east-1' });

    expect(mockedInvoke).toHaveBeenCalledWith('connect_vpn', {
      serverId: 'us-east-1',
    });
  });

  it('disconnect_vpn requires no arguments', async () => {
    await invoke('disconnect_vpn');
    expect(mockedInvoke).toHaveBeenCalledWith('disconnect_vpn');
  });

  it('get_vpn_status returns expected shape', async () => {
    const mockStatus = {
      state: 'connected',
      bytesSent: 1024,
      bytesReceived: 2048,
      connectedAt: '2025-01-01T00:00:00Z',
    };
    mockedInvoke.mockResolvedValueOnce(mockStatus);

    const result = await invoke('get_vpn_status');
    expect(result).toEqual(mockStatus);
  });

  it('quick_connect requires no arguments', async () => {
    mockedInvoke.mockResolvedValueOnce({ success: true });
    await invoke('quick_connect');
    expect(mockedInvoke).toHaveBeenCalledWith('quick_connect');
  });
});

describe('IPC Contract: Kill Switch', () => {
  // enable_killswitch / disable_killswitch were removed from the IPC surface
  // (dead commands — never called by the frontend; kill switch is driven by
  // arm()/disarm() on the connect lifecycle and set_killswitch_live).
  it('get_killswitch_status returns expected shape', async () => {
    const mockStatus = {
      enabled: true,
      active: false,
      blocking_connections: 0,
    };
    mockedInvoke.mockResolvedValueOnce(mockStatus);

    const result = await invoke('get_killswitch_status');
    expect(result).toEqual(mockStatus);
  });
});

describe('IPC Contract: Servers', () => {
  it('get_servers returns array', async () => {
    mockedInvoke.mockResolvedValueOnce([
      {
        id: 'us-1',
        name: 'US East',
        country: 'United States',
        countryCode: 'US',
        city: 'New York',
        load: 42,
        isPremium: false,
        minPlan: 'RECON',
        isHighSpeed: false,
        isPortForwarding: false,
        isOnline: true,
      },
    ]);

    const result = await invoke('get_servers');
    expect(Array.isArray(result)).toBe(true);
  });
});

describe('IPC Contract: Settings', () => {
  it('get_settings returns object', async () => {
    mockedInvoke.mockResolvedValueOnce({
      auto_connect: false,
      kill_switch: true,
      notifications: true,
    });
    const result = await invoke('get_settings');
    expect(result).toBeDefined();
  });

  it('save_settings sends settings object with VPN settings fields', async () => {
    const settings = {
      auto_connect: true,
      kill_switch: true,
      notifications: false,
      local_network_sharing: true,
      wireguard_port: '53',
      wireguard_mtu: 1420,
    };
    await invoke('save_settings', { settings });
    expect(mockedInvoke).toHaveBeenCalledWith('save_settings', { settings });
  });
});

describe('IPC Contract: Account Deletion', () => {
  it('delete_account sends password payload', async () => {
    mockedInvoke.mockResolvedValueOnce(undefined);

    await invoke('delete_account', { request: { password: 'mypassword123' } });

    expect(mockedInvoke).toHaveBeenCalledWith('delete_account', {
      request: { password: 'mypassword123' },
    });
  });

  it('delete_account rejects on 401', async () => {
    mockedInvoke.mockRejectedValueOnce(new Error('Invalid password'));

    await expect(
      invoke('delete_account', { request: { password: 'wrong' } })
    ).rejects.toThrow('Invalid password');
  });
});

describe('IPC Contract: Multi-Hop', () => {
  it('connect_multi_hop sends entry and exit node IDs', async () => {
    mockedInvoke.mockResolvedValueOnce({ success: true });

    await invoke('connect_multi_hop', {
      entryNodeId: 'de-1',
      exitNodeId: 'us-1',
    });

    expect(mockedInvoke).toHaveBeenCalledWith('connect_multi_hop', {
      entryNodeId: 'de-1',
      exitNodeId: 'us-1',
    });
  });

  it('get_multi_hop_routes returns array', async () => {
    mockedInvoke.mockResolvedValueOnce([
      { entryNodeId: 'de-1', exitNodeId: 'us-1', entryCountry: 'Germany', exitCountry: 'United States' },
    ]);

    const result = await invoke('get_multi_hop_routes');
    expect(Array.isArray(result)).toBe(true);
  });
});

describe('IPC Contract: Port Forwarding', () => {
  it('create_port_forward sends port and protocol', async () => {
    mockedInvoke.mockResolvedValueOnce({ id: 'pf-1', externalPort: 8080 });

    await invoke('create_port_forward', {
      request: { internalPort: 8080, protocol: 'tcp' },
    });

    expect(mockedInvoke).toHaveBeenCalledWith('create_port_forward', {
      request: { internalPort: 8080, protocol: 'tcp' },
    });
  });

  it('delete_port_forward sends id', async () => {
    mockedInvoke.mockResolvedValueOnce(undefined);

    await invoke('delete_port_forward', { id: 'pf-1' });

    expect(mockedInvoke).toHaveBeenCalledWith('delete_port_forward', {
      id: 'pf-1',
    });
  });
});

describe('IPC Contract: Vouchers', () => {
  it('redeem_voucher sends the code and returns the redemption result', async () => {
    mockedInvoke.mockResolvedValueOnce({
      ok: true,
      plan: 'OPERATIVE',
      durationDays: 30,
      extended: true,
    });

    const res = await invoke('redeem_voucher', { code: 'BIRD-AAAA-BBBB-CCCC' });

    expect(mockedInvoke).toHaveBeenCalledWith('redeem_voucher', {
      code: 'BIRD-AAAA-BBBB-CCCC',
    });
    expect(res).toMatchObject({ ok: true, plan: 'OPERATIVE', durationDays: 30 });
  });

  it('redeem_voucher surfaces a backend rejection (mapped error string)', async () => {
    mockedInvoke.mockRejectedValueOnce(
      "We couldn't find that voucher code. Double-check it and try again.",
    );

    await expect(invoke('redeem_voucher', { code: 'BAD' })).rejects.toContain(
      "couldn't find",
    );
  });
});

// ───────────────────────────────────────────────────────────────────────────
// REAL contract cross-check: frontend invoke() names ⊆ Rust generate_handler!
// ───────────────────────────────────────────────────────────────────────────

/**
 * Command names the frontend calls via invoke(). Keep this in sync whenever a
 * new invoke() call site is added — every entry MUST have a matching
 * #[tauri::command] registered in src-tauri/src/main.rs's generate_handler!
 * block, or the call rejects at runtime with "command <name> not found".
 *
 * (This is the SSOT the old tests lacked: previously each test only proved the
 * mock echoed back whatever name it was handed — it could never catch a
 * command that the Rust side never registered.)
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
  'export_user_data',
  // VPN operations
  'connect_vpn',
  'disconnect_vpn',
  'get_vpn_status',
  'get_vpn_stats',
  'quick_connect',
  'reapply_vpn_settings',
  'get_admin_status',
  // Server management
  'get_servers',
  'ping_server',
  // Settings
  'get_settings',
  'save_settings',
  'set_autostart',
  // System tray / window
  'set_tray_state',
  'set_window_position',
  // Kill switch
  'get_killswitch_status',
  'set_killswitch_live',
  // Split tunneling
  'list_installed_apps',
  // Auto-updater (pinned Rust client — see src-tauri/src/commands/updater.rs)
  'get_app_version',
  'check_for_updates',
  'install_update',
  'get_required_update',
  // Extended VPN info
  'get_subscription_status',
  'get_usage_stats',
  // Multi-hop (Double VPN)
  'get_multi_hop_routes',
  'connect_multi_hop',
  // Port forwarding
  'get_port_forwards',
  'create_port_forward',
  'delete_port_forward',
  // Vouchers
  'redeem_voucher',
  // Speed test
  'run_speed_test_command',
  // Biometric (Windows Hello)
  'check_biometric_available',
  'set_biometric_enabled',
  'authenticate_biometric',
  // Deep link captured at cold start
  'take_pending_deep_link',
] as const;

/**
 * Parse the Rust `generate_handler![ ... ]` list in src-tauri/src/main.rs and
 * return the registered command idents (the last `::` path segment of each
 * entry). Reads from disk — vitest runs under Node, so node:fs is available
 * even in the jsdom test environment. vitest runs from the repo root (its
 * config's include globs are root-relative), so resolve from process.cwd();
 * fall back to a short upward walk in case a runner starts elsewhere.
 */
function resolveMainRs(): string {
  const rel = 'src-tauri/src/main.rs';
  let dir = process.cwd();
  for (let i = 0; i < 6; i++) {
    const candidate = resolve(dir, rel);
    if (existsSync(candidate)) return candidate;
    const parent = resolve(dir, '..');
    if (parent === dir) break;
    dir = parent;
  }
  // Last resort: return the cwd-relative path so readFileSync throws a clear
  // ENOENT naming the path it looked for, rather than failing silently.
  return resolve(process.cwd(), rel);
}

function loadRegisteredCommands(): string[] {
  const src = readFileSync(resolveMainRs(), 'utf8');

  const marker = 'generate_handler![';
  const start = src.indexOf(marker);
  if (start === -1) {
    throw new Error('generate_handler![ block not found in main.rs');
  }
  const from = start + marker.length;
  const end = src.indexOf(']', from);
  if (end === -1) {
    throw new Error('generate_handler![ block was not terminated in main.rs');
  }

  const commands: string[] = [];
  for (const rawLine of src.slice(from, end).split('\n')) {
    // Drop `// ...` line comments before tokenising.
    const line = rawLine.replace(/\/\/.*$/, '');
    for (const token of line.split(',')) {
      const entry = token.trim();
      if (!entry) continue;
      // `commands::auth::login` -> `login`; a bare `take_pending_deep_link`
      // stays as-is.
      const ident = entry.split('::').pop()!.trim();
      if (/^[a-z_][a-z0-9_]*$/.test(ident)) {
        commands.push(ident);
      }
    }
  }
  return commands;
}

describe('IPC Contract: command registry cross-check (frontend ↔ Rust)', () => {
  const registered = loadRegisteredCommands();
  const registeredSet = new Set(registered);

  it('parses a non-trivial command set from main.rs generate_handler!', () => {
    // Guards the parser itself: if extraction silently returned nothing (the
    // block was renamed/moved), every ⊆ assertion below would vacuously pass.
    expect(registered.length).toBeGreaterThan(20);
  });

  it('registers no command twice in generate_handler!', () => {
    const duplicates = registered.filter(
      (cmd, i) => registered.indexOf(cmd) !== i,
    );
    expect(duplicates).toEqual([]);
  });

  it('every registered command is a valid snake_case ident', () => {
    const invalid = registered.filter((cmd) => !/^[a-z_][a-z0-9_]*$/.test(cmd));
    expect(invalid).toEqual([]);
  });

  it('the frontend command list has no duplicates', () => {
    const duplicates = FRONTEND_COMMANDS.filter(
      (cmd, i) => FRONTEND_COMMANDS.indexOf(cmd) !== i,
    );
    expect(duplicates).toEqual([]);
  });

  it.each(FRONTEND_COMMANDS)(
    "frontend command '%s' is registered in main.rs generate_handler!",
    (cmd) => {
      expect(registeredSet.has(cmd)).toBe(true);
    },
  );
});
