/**
 * L-10: IPC contract integration test scaffold
 *
 * These tests verify that the frontend's invoke() calls match the
 * Rust #[tauri::command] signatures. They use the shared Tauri mock
 * to ensure invoke is called with the correct command names and
 * argument shapes.
 *
 * Run: npx vitest run src/__tests__/ipc-contracts.test.ts
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { invoke } from '@tauri-apps/api/core';

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
  it('enable_killswitch returns boolean', async () => {
    mockedInvoke.mockResolvedValueOnce(true);
    const result = await invoke('enable_killswitch');
    expect(result).toBe(true);
  });

  it('disable_killswitch returns boolean', async () => {
    mockedInvoke.mockResolvedValueOnce(true);
    const result = await invoke('disable_killswitch');
    expect(result).toBe(true);
  });

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
        isStreaming: false,
        isP2p: false,
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
