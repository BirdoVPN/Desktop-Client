/**
 * AppShell fetches the BirdoShield fleet gate on EVERY tab (PR #162 review, must-fix 1).
 *
 * THE GAP THIS FILLS: the gate fetch first shipped inside `Dashboard`, which
 * `AppShell` mounts only while `tab === 'home'`. `App.tsx` handles a
 * `birdo://settings` deep link -- including the cold-start one it pulls with
 * `take_pending_deep_link` before the shell ever renders -- by `setTab('settings')`.
 * So the app could reach the authenticated shell with Dashboard never mounted,
 * `get_client_config` never invoked, and `dnsFilteringAvailable` pinned at its
 * `true` default for the whole session: the user opened Settings -> VPN and saw
 * BirdoShield ON and switchable while `DNS_FILTERING_ENABLED` was off. That is
 * the reassurance-from-missing-data this PR exists to remove, and nothing in the
 * 173-test suite failed on it.
 *
 * These tests assert the property that actually matters -- the gate is fetched
 * for every entry point into the authenticated frame -- rather than "Dashboard
 * calls the hook", which is the assertion that let the bug through.
 *
 * WHAT THE MUTATION ACTUALLY DOES, measured (PR #162 review, must-fix 2 -- an
 * earlier revision of this header and of the PR body claimed "fails 5 of the 7
 * cases ... only the two that start on Home survive", and both the number and
 * the mechanism were wrong). Moving `useClientConfig()` off AppShell and back
 * onto `Dashboard` fails ALL SEVEN cases, including the two that open on Home.
 * The reason is the mock 20 lines below: this suite replaces
 * `@/components/Dashboard` with a stub, so a hook placed inside the REAL
 * Dashboard never runs here at all and `get_client_config` is invoked zero
 * times on every tab. Re-measured on this branch: 7 failed / 7.
 *
 * So be precise about what that buys. These cases prove that AppShell itself
 * issues the fetch, and that it does so for every tab, for a cold-start deep
 * link, underneath a pushed sub-screen, and once per shell mount rather than
 * once per tab switch. They do NOT prove anything about the real Dashboard,
 * and the all-seven failure above is a property of this file's stubbing as
 * much as of the placement -- it says "the call is not on the shell", not
 * "the call is unreachable in the app". The argument that the shell is the
 * right home is the structural one in the paragraph above, which these tests
 * pin for the shell's side of it.
 *
 * The tab roots and push screens are stubbed: this file is about the shell's own
 * responsibility, and the real Dashboard drags in the globe, the 2s status poll
 * and a dozen more invokes that would drown the assertion.
 *
 * Run: npx vitest run src/__tests__/AppShellClientConfig.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { invoke } from '@tauri-apps/api/core';
import { AppShell } from '@/components/AppShell';
import { useAppStore, type TabId } from '@/store/app-store';

vi.mock('@tauri-apps/api/core');
// The gate hook subscribes to the `app-shown` tray-restore event; jsdom has no
// Tauri IPC to carry it. The shell's own responsibility is the FETCH, so the
// refetch triggers are pinned in `useClientConfig.test.tsx` instead.
vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn(async () => () => {}),
}));

// Tab roots and push screens are stand-ins. Each renders a testid so the tests
// can also state the structural fact the bug rested on: Dashboard is NOT
// mounted on the Settings tab, so a fetch living there cannot run.
vi.mock('@/components/Dashboard', () => ({
  Dashboard: () => <div data-testid="tab-home" />,
}));
vi.mock('@/screens/Profile', () => ({ Profile: () => <div data-testid="tab-profile" /> }));
vi.mock('@/components/Settings', () => ({ Settings: () => <div data-testid="tab-settings" /> }));
vi.mock('@/screens/VpnSettings', () => ({ VpnSettings: () => <div data-testid="route-vpnSettings" /> }));
vi.mock('@/screens/SplitTunnel', () => ({ SplitTunnel: () => <div /> }));
vi.mock('@/screens/PortForward', () => ({ PortForward: () => <div /> }));
vi.mock('@/screens/Pricing', () => ({ Pricing: () => <div /> }));
vi.mock('@/components/BottomNav', () => ({ BottomNav: () => <nav /> }));
vi.mock('@/components/PixelCanvas', () => ({ PixelCanvas: () => <canvas /> }));

const mockedInvoke = vi.mocked(invoke);

const configCalls = () =>
  mockedInvoke.mock.calls.filter(([cmd]) => cmd === 'get_client_config');

beforeEach(() => {
  mockedInvoke.mockReset();
  mockedInvoke.mockResolvedValue({ dnsFilteringAvailable: false });
  useAppStore.setState({ tab: 'home', navStack: [], dnsFilteringAvailable: true });
});

describe('AppShell -> get_client_config', () => {
  // The three tabs are mutually exclusive in AppShell, so this is the whole
  // entry-point surface of the authenticated frame.
  it.each<TabId>(['home', 'profile', 'settings'])(
    'fetches the fleet gate when the shell opens on the %s tab',
    async (tab) => {
      useAppStore.setState({ tab });
      render(<AppShell />);
      await waitFor(() => expect(configCalls()).toHaveLength(1));
    },
  );

  it('fetches it on a cold-start birdo://settings deep link, with Dashboard never mounted', async () => {
    // What App.tsx does with a URL from `take_pending_deep_link`, before the
    // shell first renders.
    useAppStore.getState().setTab('settings');

    render(<AppShell />);

    expect(screen.queryByTestId('tab-home')).not.toBeInTheDocument();
    expect(screen.getByTestId('tab-settings')).toBeInTheDocument();
    await waitFor(() => expect(configCalls()).toHaveLength(1));
  });

  it('applies the answer, so the gate is really wired and not merely requested', async () => {
    useAppStore.setState({ tab: 'settings' });
    render(<AppShell />);
    await waitFor(() => expect(useAppStore.getState().dnsFilteringAvailable).toBe(false));
  });

  it('fetches once per shell mount, not once per tab switch', async () => {
    render(<AppShell />);
    await waitFor(() => expect(configCalls()).toHaveLength(1));

    // The shell stays mounted across tab changes; only its children swap.
    useAppStore.getState().setTab('settings');
    useAppStore.getState().setTab('profile');
    useAppStore.getState().setTab('home');
    await waitFor(() => expect(screen.getByTestId('tab-home')).toBeInTheDocument());

    expect(configCalls()).toHaveLength(1);
  });

  it('still fetches while a sub-screen is pushed over the tab', async () => {
    useAppStore.setState({ tab: 'settings', navStack: ['vpnSettings'] });
    render(<AppShell />);
    expect(screen.getByTestId('route-vpnSettings')).toBeInTheDocument();
    await waitFor(() => expect(configCalls()).toHaveLength(1));
  });
});
