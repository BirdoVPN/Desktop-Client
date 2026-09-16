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
  // The fleet gate from GET /api/client-config. `true` is the store default —
  // see the availability describe block at the bottom of this file.
  dnsFilteringAvailable: true as boolean | undefined,
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
    customDns: null as string[] | null,
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
  mockStoreState.settings.customDns = null;
  mockStoreState.connectionState = 'disconnected';
  mockStoreState.account.plan = 'RECON';
  mockStoreState.dnsFilteringAvailable = true;
});


/** The exact fleet-gate reason copy the screen renders. */
const UNAVAILABLE_COPY =
  "Not available on your account's server fleet yet. Your preference is kept and applies as soon as it is.";

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
    // No "applies on your next connection" tail: the screen's info note
    // already states the live-reapply behaviour and the two contradicted.
    expect(
      screen.getByText("Blocks ads, trackers and malware domains at the VPN's DNS resolver."),
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

  // PR #160 review, must-fix 1: `build_vpn_config` writes the user's Custom
  // DNS servers into the tunnel ahead of the server's resolver, so with Custom
  // DNS set the filtering resolver is never used. The row must not read ON
  // (reassurance from missing data) and must say why it is unavailable.
  describe('with Custom DNS configured', () => {
    it('reads OFF, is disabled and explains the override — even when dnsFiltering is persisted ON', async () => {
      mockStoreState.settings.customDns = ['9.9.9.9', '149.112.112.112'];
      mockStoreState.settings.dnsFiltering = true;
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row).toHaveAttribute('aria-checked', 'false');
      // Disabled rows degrade to a static <div> (same as Stealth on RECON).
      expect(row.tagName).toBe('DIV');
      expect(
        screen.getByText(
          'Custom DNS overrides BirdoShield. Clear your custom DNS servers under Settings › VPN to use the filtering resolver.',
        ),
      ).toBeInTheDocument();
      expect(
        screen.queryByText("Blocks ads, trackers and malware domains at the VPN's DNS resolver."),
      ).not.toBeInTheDocument();

      // Clicking the disabled row must not persist anything.
      await userEvent.click(row);
      expect(mockStoreState.updateSettings).not.toHaveBeenCalled();
      expect(savedSettings()).toHaveLength(0);
    });

    it('a single custom server is enough to gate the row', async () => {
      mockStoreState.settings.customDns = ['1.1.1.1'];
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row.tagName).toBe('DIV');
    });

    it('an empty custom DNS list does NOT gate the row (matches the Rust `!d.is_empty()` rule)', async () => {
      mockStoreState.settings.customDns = [];
      mockStoreState.settings.dnsFiltering = true;
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row.tagName).toBe('BUTTON');
      expect(row).toHaveAttribute('aria-checked', 'true');
    });
  });

  // PR #160/#403 review follow-up: `dnsFilteringAvailable` on
  // GET /api/client-config is the backend's DNS_FILTERING_ENABLED fleet gate.
  // With it off the backend ignores the connect flag and hands out the normal
  // resolver, so a row the user can switch ON is a lie about what the server
  // will do.
  describe('with the fleet gate off (dnsFilteringAvailable: false)', () => {
    it('reads OFF, is disabled and gives the reason — even when dnsFiltering is persisted ON', async () => {
      mockStoreState.dnsFilteringAvailable = false;
      mockStoreState.settings.dnsFiltering = true;
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row).toHaveAttribute('aria-checked', 'false');
      // Disabled rows degrade to a static <div> (same as Stealth on RECON).
      expect(row.tagName).toBe('DIV');
      expect(screen.getByText(UNAVAILABLE_COPY)).toBeInTheDocument();
      expect(
        screen.queryByText("Blocks ads, trackers and malware domains at the VPN's DNS resolver."),
      ).not.toBeInTheDocument();

      // Clicking the disabled row must not persist anything — and, crucially,
      // must not CLEAR the stored preference either: it has to come back on
      // its own when the gate does.
      await userEvent.click(row);
      expect(mockStoreState.updateSettings).not.toHaveBeenCalled();
      expect(savedSettings()).toHaveLength(0);
      expect(mockStoreState.settings.dnsFiltering).toBe(true);
    });

    it('names the fleet gate, not Custom DNS, when both block the row', async () => {
      mockStoreState.dnsFilteringAvailable = false;
      mockStoreState.settings.customDns = ['1.1.1.1'];
      render(<VpnSettings />);
      expect(screen.getByText(UNAVAILABLE_COPY)).toBeInTheDocument();
      expect(
        screen.queryByText(
          'Custom DNS overrides BirdoShield. Clear your custom DNS servers under Settings › VPN to use the filtering resolver.',
        ),
      ).not.toBeInTheDocument();
    });
  });

  describe('with the fleet gate on or unknown', () => {
    it('true leaves the row enabled and switchable', async () => {
      mockStoreState.dnsFilteringAvailable = true;
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row.tagName).toBe('BUTTON');
      await userEvent.click(row);
      expect(mockStoreState.updateSettings).toHaveBeenCalledWith({ dnsFiltering: true });
    });

    // The default that matters: a failed/absent fetch leaves the store value
    // untouched, and `undefined` must NOT read as "off". Hiding a feature that
    // works because the client could not reach the web app is the failure this
    // whole flag exists to avoid.
    it('an unknown value (failed fetch, older web deploy) leaves the row enabled', async () => {
      mockStoreState.dnsFilteringAvailable = undefined;
      mockStoreState.settings.dnsFiltering = true;
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row.tagName).toBe('BUTTON');
      expect(row).toHaveAttribute('aria-checked', 'true');
      expect(
        screen.getByText("Blocks ads, trackers and malware domains at the VPN's DNS resolver."),
      ).toBeInTheDocument();
      expect(screen.queryByText(UNAVAILABLE_COPY)).not.toBeInTheDocument();
    });
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
