/**
 * Settings and VPN Settings as mobile lays them out (owner, 2026-10-21):
 * "the settings page needs a lot of work ... ALL the details for each feature
 * / button ... need to get removed, so it's just that, no description of the
 * setting ... the exact same design as the mobile".
 *
 * Pinned here:
 *  - a row is its title and its control: no text beside the title, and no
 *    accessible description, on any row whose control can be used;
 *  - mobile's sections in mobile's order, each a heading (BirdoSectionHeader
 *    is `semantics { heading() }` on Android), under a top bar whose title is
 *    the screen's heading, with mobile's subtitle;
 *  - one row per card, as mobile's SettingsToggle / SettingsLink;
 *  - Kill Switch Exceptions under Settings › VPN, where mobile has Split
 *    Tunneling; VPN Settings keeps mobile's Security / Network / WireGuard.
 *
 * Run: npx vitest run src/__tests__/SettingsMobileLayout.test.tsx
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import { invoke } from '@tauri-apps/api/core';
import { Settings } from '@/components/Settings';
import { VpnSettings } from '@/screens/VpnSettings';
import { defaultSettings, useAppStore } from '@/store/app-store';
import { cancelScheduledReapply, forgetKillSwitchChoices } from '@/session/settings-persist';
import { resetUpdater } from '@/session/updater';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/plugin-opener', () => ({ openUrl: vi.fn().mockResolvedValue(undefined) }));
vi.mock('@tauri-apps/plugin-process', () => ({ relaunch: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));

const mockedInvoke = vi.mocked(invoke);
const realUserAgent = navigator.userAgent;
const setUserAgent = (ua: string) =>
  Object.defineProperty(window.navigator, 'userAgent', { value: ua, configurable: true });
const WINDOWS = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edg/129.0';

beforeEach(() => {
  setUserAgent(WINDOWS);
  resetUpdater();
  cancelScheduledReapply();
  forgetKillSwitchChoices();
  useAppStore.getState().logout();
  useAppStore.setState({
    isAuthenticated: true,
    connectionState: 'disconnected',
    notice: null,
    // Every conditional row showing: always-on (kill switch on), the two
    // notification rows, the DNS fields. Sovereign, so no row is locked by
    // the plan (Port Forwarding is Sovereign's, MR-1517).
    settings: { ...defaultSettings, killSwitchEnabled: true, notifications: true, customDnsEnabled: true },
    account: { ...useAppStore.getState().account, plan: 'SOVEREIGN' },
    customDnsByPlan: {},
    planGates: {},
    dnsFilteringAvailable: true,
  });
  mockedInvoke.mockReset();
  mockedInvoke.mockImplementation(async (cmd: string) => {
    if (cmd === 'check_biometric_available') return { available: true, enabled: false, method: 'windows_hello' };
    if (cmd === 'get_app_version') return '1.4.49';
    return undefined;
  });
});

afterEach(() => {
  cancelScheduledReapply();
  setUserAgent(realUserAgent);
});

/** The visible text of a row, collapsed: what a sighted user reads on it. */
const textOf = (el: HTMLElement) => (el.textContent ?? '').replace(/\s+/g, ' ').trim();

/** The card a row sits in: the nearest ancestor that is more than the row. */
const cardOf = (row: HTMLElement) => row.parentElement!.parentElement!;

describe('Settings tab: mobile layout, no descriptions', () => {
  const SWITCHES = [
    'Kill Switch',
    'Always-on Kill Switch',
    'Quantum Protection',
    'Hide App Contents',
    'Crash Reports',
    'Save Diagnostic Logs',
    'Auto-Connect',
    'Launch at Login',
    'Start Minimized',
    'Notifications',
    'Show IP Address',
    'Show Server Location',
    'Custom DNS Servers',
  ];
  const LINKS = [
    'Delete Logs Now',
    'VPN Settings',
    'Port Forwarding',
    'Kill Switch Exceptions',
    'Privacy Policy',
    'Terms of Service',
    'Manage on web',
    'Licences',
  ];

  it('every switch row is its title and its switch: no description, seen or announced', async () => {
    render(<Settings />);
    // Hide App Contents appears once the biometric probe answers.
    await screen.findByRole('switch', { name: 'Hide App Contents' });
    for (const name of SWITCHES) {
      const row = screen.getByRole('switch', { name });
      expect(textOf(row), name).toBe(name);
      expect(row, name).toHaveAccessibleDescription('');
      expect(row, name).not.toHaveAttribute('aria-describedby');
    }
  });

  it('every link row is its title: no subtitle, no URL under it', async () => {
    render(<Settings />);
    for (const name of LINKS) {
      const row = screen.getByRole('button', { name });
      expect(textOf(row), name).toBe(name);
    }
    expect(document.body.textContent).not.toMatch(/birdo\.app\/privacy|birdo\.app\/terms|dashboard\.birdo\.app/);
  });

  it('no row on the screen carries a sentence: the old descriptions are gone', async () => {
    render(<Settings />);
    await screen.findByRole('switch', { name: 'Hide App Contents' });
    const text = document.body.textContent ?? '';
    for (const gone of [
      /blocks traffic until it reconnects/,
      /pre-shared key/,
      /Covers the screen/,
      /Off by default/,
      /Keeps a log of connection events/,
      /Deletes the diagnostic log/,
      /Connect to VPN on app startup/,
      /when you sign in to your computer/,
      /Open in the system tray/,
      /Show connection notifications/,
      /Local network, port, and MTU/,
      /instead of the VPN defaults/,
      /Expose ports/,
      /Popular: 1\.1\.1\.1/,
      /carrier-grade NAT/,
      /Check for new versions/,
      /Third-party software notices/,
    ]) {
      expect(text, String(gone)).not.toMatch(gone);
    }
  });

  it("mobile's sections, in mobile's order, each a heading, under the screen's heading", () => {
    render(<Settings />);
    expect(screen.getByRole('heading', { level: 1, name: 'Settings' })).toBeInTheDocument();
    expect(screen.getByText('App preferences & account')).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)).toEqual([
      'Appearance',
      'Privacy & Security',
      'Connection',
      'Notifications',
      'VPN',
      'Speed Test',
      'About',
    ]);
  });

  it('one row per card, as mobile', async () => {
    render(<Settings />);
    await screen.findByRole('switch', { name: 'Hide App Contents' });
    for (const row of [
      ...screen.getAllByRole('switch'),
      ...LINKS.map((name) => screen.getByRole('button', { name })),
    ]) {
      const card = cardOf(row);
      expect(within(card).queryAllByRole('switch').length + within(card).queryAllByRole('button').length).toBe(1);
    }
  });

  it('Kill Switch Exceptions sits under Settings › VPN, where mobile has Split Tunneling (Windows)', () => {
    render(<Settings />);
    const follows = (a: Element, b: Element) =>
      Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
    const exceptions = screen.getByRole('button', { name: 'Kill Switch Exceptions' });
    expect(follows(screen.getByRole('button', { name: 'Port Forwarding' }), exceptions)).toBe(true);
    expect(follows(exceptions, screen.getByRole('heading', { name: 'Speed Test' }))).toBe(true);
  });

  it('About opens with the app and its version, as mobile', async () => {
    render(<Settings />);
    expect(await screen.findByText('Version 1.4.49')).toBeInTheDocument();
    expect(screen.getByText('BirdoVPN')).toBeInTheDocument();
  });

  it('a row that cannot be used still says why (the one text a row keeps)', () => {
    useAppStore.setState({ customDnsByPlan: { SOVEREIGN: false } });
    render(<Settings />);
    const row = screen.getByRole('switch', { name: 'Custom DNS Servers' });
    expect(row).toHaveAttribute('aria-disabled', 'true');
    expect(row).toHaveAccessibleDescription('Custom DNS is not available on your plan right now.');
  });

  it('a link the plan does not include is locked and names the plan, still one row per card (MR-1517)', () => {
    useAppStore.setState({ account: { ...useAppStore.getState().account, plan: 'OPERATIVE' } });
    render(<Settings />);
    // The title and the plan that has it: nothing else on the row.
    const row = screen.getByRole('button', { name: /^Port Forwarding\s*Sovereign$/ });
    expect(within(row).getByText('Sovereign')).toBeInTheDocument();
    expect(within(cardOf(row)).getAllByRole('button')).toHaveLength(1);
  });
});

describe('VPN Settings: mobile layout, no descriptions', () => {
  it("mobile's three sections and nothing after them; no Features section", () => {
    render(<VpnSettings />);
    expect(screen.getByRole('heading', { level: 1, name: 'VPN Settings' })).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 2 }).map((h) => h.textContent)).toEqual([
      'Security',
      'Network',
      'WireGuard',
    ]);
    expect(screen.queryByRole('button', { name: 'Kill Switch Exceptions' })).not.toBeInTheDocument();
  });

  it('every switch row is its title and its switch', () => {
    render(<VpnSettings />);
    for (const name of ['Stealth Mode', 'BirdoShield', 'Local Network Sharing']) {
      const row = screen.getByRole('switch', { name });
      expect(textOf(row), name).toBe(name);
      expect(row, name).toHaveAccessibleDescription('');
    }
    const text = document.body.textContent ?? '';
    for (const gone of [
      /encrypted transport/,
      /Blocks ads, trackers/,
      /printers, NAS/,
      /port 51820 only/,
      /Packet size/,
      /Valid range/,
    ]) {
      expect(text, String(gone)).not.toMatch(gone);
    }
  });

  it('the port is a value row and MTU "Automatic" is a checkbox, as mobile', () => {
    render(<VpnSettings />);
    expect(screen.getByText('WireGuard Port')).toBeInTheDocument();
    expect(screen.getByText('Automatic')).toBeInTheDocument();
    expect(screen.getByRole('checkbox', { name: 'Automatic (server default)' })).toHaveAttribute('aria-checked', 'true');
  });
});
