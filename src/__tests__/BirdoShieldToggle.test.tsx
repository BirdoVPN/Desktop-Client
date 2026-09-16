/**
 * BirdoShield toggle (OPEN-WORK D18) — VPN Settings → Security.
 *
 * The Rust side sends the per-device `dnsFiltering` connect flag on both dial
 * paths from the persisted `dns_filtering` setting; the only thing the
 * frontend owns is getting that setting persisted through the SAME
 * full-object `save_settings` path every other tunnel setting uses, on every
 * plan (no gate), and scheduling the live rebuild when a session is up. These
 * tests drive the real VpnSettings screen and assert exactly that.
 *
 * Run: npx vitest run src/__tests__/BirdoShieldToggle.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { VpnSettings } from '@/screens/VpnSettings';
import type { ConnectionState } from '@/store/app-store';

vi.mock('@tauri-apps/api/core');

// Mutable so each test can pick the plan / connection state the toggle is
// flipped in. `updateSettings` mirrors the real store's shallow patch so the
// `settings` the screen re-reads via getState() carries the new value.
const mockStoreState = {
  connectionState: 'disconnected' as ConnectionState,
  settings: {
    killSwitchEnabled: true,
    autoConnect: false,
    autostart: false,
    startMinimized: false,
    notifications: true,
    showIpInNotification: false,
    showLocationInNotification: false,
    preferredServerId: null,
    splitTunnelingEnabled: false,
    splitTunnelApps: [] as string[],
    customDns: null,
    protocol: 'wireguard' as const,
    localNetworkSharing: false,
    wireGuardPort: 'auto',
    wireGuardMtu: 0,
    multiHopEnabled: false,
    multiHopEntryNodeId: null,
    multiHopExitNodeId: null,
    stealthMode: false,
    quantumProtection: true,
    dnsFiltering: false,
    lockdownMode: true,
  },
  updateSettings: vi.fn((patch: Record<string, unknown>) => {
    Object.assign(mockStoreState.settings, patch);
  }),
  popRoute: vi.fn(),
  pushRoute: vi.fn(),
  account: {
    email: 'test@birdo.app',
    plan: 'RECON',
    accountId: 'acct_test',
    maxDevices: 1,
    activeDevices: 1,
    expiresAt: null,
    bandwidthUsed: 0,
    bandwidthLimit: 0,
    status: 'active',
  },
};

vi.mock('@/store/app-store', () => {
  const useAppStore = vi.fn((selector) => selector(mockStoreState));
  (useAppStore as unknown as { getState: () => typeof mockStoreState }).getState = () =>
    mockStoreState;
  return { useAppStore };
});

vi.mock('zustand/react/shallow', () => ({
  useShallow: (fn: unknown) => fn,
}));

const mockedInvoke = vi.mocked(invoke);

beforeEach(() => {
  mockedInvoke.mockReset();
  mockedInvoke.mockResolvedValue(undefined);
  mockStoreState.updateSettings.mockClear();
  mockStoreState.settings.dnsFiltering = false;
  mockStoreState.settings.stealthMode = false;
  mockStoreState.connectionState = 'disconnected';
  mockStoreState.account.plan = 'RECON';
});


const savedSettings = () =>
  mockedInvoke.mock.calls
    .filter(([cmd]) => cmd === 'save_settings')
    .map(([, args]) => (args as { settings: Record<string, unknown> }).settings);

const reapplyCalls = () =>
  mockedInvoke.mock.calls.filter(([cmd]) => cmd === 'reapply_vpn_settings');

describe('BirdoShield toggle → dns_filtering', () => {
  it('renders OFF by default under Security with the resolver copy, on the free plan (no plan gate)', async () => {
    render(<VpnSettings />);
    const row = await screen.findByRole('switch', { name: /birdoshield/i });
    expect(row).toHaveAttribute('aria-checked', 'false');
    // BirdoListItem renders an interactive <button> only when enabled; a
    // gated row degrades to a static <div>.
    expect(row.tagName).toBe('BUTTON');
    expect(
      screen.getByText(
        "Blocks ads, trackers and malware domains at the VPN's DNS resolver. Applies on your next connection.",
      ),
    ).toBeInTheDocument();
    // Stealth, by contrast, IS plan-gated on RECON — the two rows differ on purpose.
    expect(screen.getByRole('switch', { name: /stealth mode/i }).tagName).toBe('DIV');
  });

  it('ON persists dnsFiltering through the store patch and the full-object save_settings (dns_filtering: true)', async () => {
    render(<VpnSettings />);
    await userEvent.click(await screen.findByRole('switch', { name: /birdoshield/i }));

    expect(mockStoreState.updateSettings).toHaveBeenCalledWith({ dnsFiltering: true });
    await waitFor(() => {
      expect(savedSettings()).toHaveLength(1);
    });
    const saved = savedSettings()[0];
    expect(saved.dns_filtering).toBe(true);
    // The rest of the object rides along untouched (full-object save path).
    expect(saved.stealth_mode).toBe(false);
    expect(saved.quantum_protection).toBe(true);
    expect(saved.killswitch_enabled).toBe(true);
    // Disconnected: nothing to rebuild — the flag applies at the next connect.
    expect(reapplyCalls()).toHaveLength(0);
  });

  it('OFF persists dns_filtering: false (a real user choice, not an omission)', async () => {
    mockStoreState.settings.dnsFiltering = true;
    render(<VpnSettings />);
    const row = await screen.findByRole('switch', { name: /birdoshield/i });
    expect(row).toHaveAttribute('aria-checked', 'true');
    await userEvent.click(row);

    expect(mockStoreState.updateSettings).toHaveBeenCalledWith({ dnsFiltering: false });
    await waitFor(() => {
      expect(savedSettings()).toHaveLength(1);
    });
    expect(savedSettings()[0].dns_filtering).toBe(false);
  });

  it('while connected, schedules the same debounced fail-closed rebuild Stealth uses', async () => {
    mockStoreState.connectionState = 'connected';
    render(<VpnSettings />);
    await userEvent.click(await screen.findByRole('switch', { name: /birdoshield/i }));

    await waitFor(() => {
      expect(savedSettings()).toHaveLength(1);
    });
    // Debounced (900 ms): not yet, then exactly once.
    expect(reapplyCalls()).toHaveLength(0);
    await waitFor(() => expect(reapplyCalls()).toHaveLength(1), { timeout: 3000 });
  });
});
