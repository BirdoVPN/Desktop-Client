/**
 * Settings writes: drafts, validation, rollback (W2-007, W2-013, P1-parity-042).
 *
 * W2-007, reproduced by reading the old code: each keystroke in a Custom DNS
 * field saved only the VALID entries, compacted, and mirrored the saved list
 * back into BOTH inputs — the first Backspace in "1.1.1.1" emptied the field,
 * an invalid primary moved the secondary up into it, and a connected user got
 * a fail-closed tunnel rebuild per pause in typing. Port and MTU saved "5" on
 * the way to "51820". W2-013: a failed save kept the optimistic value.
 *
 * These drive the real Settings / VPN Settings screens over the real store.
 *
 * Run: npx vitest run src/__tests__/SettingsPersistence.test.tsx
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { Settings } from '@/components/Settings';
import { VpnSettings } from '@/screens/VpnSettings';
import { defaultSettings, useAppStore } from '@/store/app-store';
import { cancelScheduledReapply } from '@/session/settings-persist';
import { resetUpdater } from '@/session/updater';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/plugin-shell', () => ({ open: vi.fn().mockResolvedValue(undefined) }));
vi.mock('@tauri-apps/plugin-process', () => ({ relaunch: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));

const mockedInvoke = vi.mocked(invoke);
let saveFails = false;

beforeEach(() => {
  saveFails = false;
  resetUpdater();
  cancelScheduledReapply();
  useAppStore.getState().logout();
  useAppStore.setState({
    isAuthenticated: true,
    connectionState: 'disconnected',
    notice: null,
    settings: { ...defaultSettings },
    account: { ...useAppStore.getState().account, plan: 'OPERATIVE' },
    customDnsByPlan: {},
  });
  mockedInvoke.mockReset();
  mockedInvoke.mockImplementation(async (cmd: string) => {
    if (cmd === 'save_settings' && saveFails) throw 'disk full';
    if (cmd === 'check_biometric_available') return { available: false, enabled: false, method: 'none' };
    if (cmd === 'get_app_version') return '1.4.45';
    return undefined;
  });
});

afterEach(() => cancelScheduledReapply());

const saves = () =>
  mockedInvoke.mock.calls
    .filter(([c]) => c === 'save_settings')
    .map(([, a]) => (a as { settings: Record<string, unknown> }).settings);
const reapplies = () => mockedInvoke.mock.calls.filter(([c]) => c === 'reapply_vpn_settings');

describe('Custom DNS: draft fields, saved on leave', () => {
  it('typing never saves; an invalid value is explained on blur and not saved; a valid one is', async () => {
    useAppStore.setState({ settings: { ...defaultSettings, customDnsEnabled: true } });
    render(<Settings />);
    const primary = screen.getByRole('textbox', { name: 'Primary DNS' });

    await userEvent.type(primary, '1.1.1.');
    expect(saves()).toHaveLength(0);
    fireEvent.blur(primary);
    expect(await screen.findByText('Enter a valid IPv4 address (e.g. 1.1.1.1)')).toBeInTheDocument();
    expect(saves()).toHaveLength(0);

    await userEvent.type(primary, '1');
    fireEvent.blur(primary);
    await waitFor(() => expect(saves()).toHaveLength(1));
    expect(saves()[0].custom_dns).toEqual(['1.1.1.1']);
  });

  it('editing the primary never empties it or pulls the secondary into it (the W2-007 trace)', async () => {
    useAppStore.setState({ settings: { ...defaultSettings, customDnsEnabled: true, customDns: ['1.1.1.1', '8.8.8.8'] } });
    render(<Settings />);
    const primary = screen.getByRole('textbox', { name: 'Primary DNS' });
    const secondary = screen.getByRole('textbox', { name: 'Secondary DNS (optional)' });

    await userEvent.type(primary, '{Backspace}');
    expect(primary).toHaveValue('1.1.1.');
    expect(secondary).toHaveValue('8.8.8.8');

    await userEvent.clear(primary);
    expect(primary).toHaveValue('');
    expect(secondary).toHaveValue('8.8.8.8');
    expect(saves()).toHaveLength(0);
  });

  it('while connected, typing rebuilds nothing; leaving the field schedules ONE reapply', async () => {
    useAppStore.setState({ connectionState: 'connected', settings: { ...defaultSettings, customDnsEnabled: true } });
    render(<Settings />);
    const primary = screen.getByRole('textbox', { name: 'Primary DNS' });
    await userEvent.type(primary, '9.9.9.9');
    expect(reapplies()).toHaveLength(0);
    fireEvent.blur(primary);
    await waitFor(() => expect(reapplies()).toHaveLength(1), { timeout: 3000 });
  });

  it('the switch turns Custom DNS off WITHOUT losing the addresses (P1-parity-042)', async () => {
    useAppStore.setState({ settings: { ...defaultSettings, customDnsEnabled: true, customDns: ['1.1.1.1'] } });
    render(<Settings />);
    await userEvent.click(screen.getByRole('switch', { name: 'Custom DNS Servers' }));
    await waitFor(() => expect(saves()).toHaveLength(1));
    expect(saves()[0].custom_dns).toBeNull();
    expect(useAppStore.getState().settings.customDns).toEqual(['1.1.1.1']);
    expect(screen.queryByRole('textbox', { name: 'Primary DNS' })).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole('switch', { name: 'Custom DNS Servers' }));
    expect(screen.getByRole('textbox', { name: 'Primary DNS' })).toHaveValue('1.1.1.1');
    await waitFor(() => expect(saves()).toHaveLength(2));
    expect(saves()[1].custom_dns).toEqual(['1.1.1.1']);
  });
});

describe('Custom DNS is on every plan (owner decision D6, Account API item 40)', () => {
  it.each(['RECON', 'OPERATIVE', 'SOVEREIGN', null])('plan %s: the switch works and nothing upsells it', async (plan) => {
    useAppStore.setState({ account: { ...useAppStore.getState().account, plan } });
    render(<Settings />);
    const toggle = screen.getByRole('switch', { name: 'Custom DNS Servers' });
    expect(toggle).not.toBeDisabled();
    expect(toggle).not.toHaveAttribute('aria-disabled', 'true');
    await userEvent.click(toggle);
    expect(screen.getByRole('textbox', { name: 'Primary DNS' })).toBeInTheDocument();
    await waitFor(() => expect(saves()).toHaveLength(1));
    expect(document.body.textContent).not.toMatch(/sovereign|upgrade|view plans/i);
  });
});

describe('Custom DNS follows the server flag for the plan (client-config features.customDns)', () => {
  it('an explicit false for this plan: the row reads off, cannot be switched on, and the fields go', async () => {
    useAppStore.setState({
      settings: { ...defaultSettings, customDnsEnabled: true, customDns: ['9.9.9.9'] },
      customDnsByPlan: { OPERATIVE: false, RECON: true },
    });
    render(<Settings />);
    const toggle = screen.getByRole('switch', { name: 'Custom DNS Servers' });
    expect(toggle).toHaveAttribute('aria-checked', 'false');
    expect(toggle).toHaveAttribute('aria-disabled', 'true');
    expect(toggle).toHaveAccessibleDescription('Custom DNS is not available on your plan right now.');
    expect(screen.queryByRole('textbox', { name: 'Primary DNS' })).not.toBeInTheDocument();
    await userEvent.click(toggle);
    expect(saves()).toHaveLength(0);
    // Not an upsell: nothing offers a plan for it.
    expect(document.body.textContent).not.toMatch(/upgrade|view plans/i);
  });

  it('true, or a false for another plan, leaves it as it is', () => {
    useAppStore.setState({
      settings: { ...defaultSettings, customDnsEnabled: true, customDns: ['9.9.9.9'] },
      customDnsByPlan: { OPERATIVE: true, SOVEREIGN: false },
    });
    render(<Settings />);
    const toggle = screen.getByRole('switch', { name: 'Custom DNS Servers' });
    expect(toggle).toHaveAttribute('aria-checked', 'true');
    expect(toggle).not.toHaveAttribute('aria-disabled', 'true');
    expect(screen.getByRole('textbox', { name: 'Primary DNS' })).toBeInTheDocument();
  });
});

describe('a failed save is rolled back and reported (W2-013)', () => {
  it('the toggle goes back and the user is told', async () => {
    saveFails = true;
    render(<Settings />);
    const row = screen.getByRole('switch', { name: 'Auto-Connect' });
    expect(row).toHaveAttribute('aria-checked', 'false');
    await userEvent.click(row);
    await waitFor(() => expect(useAppStore.getState().settings.autoConnect).toBe(false));
    expect(screen.getByRole('switch', { name: 'Auto-Connect' })).toHaveAttribute('aria-checked', 'false');
    expect(useAppStore.getState().notice?.text).toMatch(/Couldn't save that setting/);
  });

  it('a successful save keeps the new value and says nothing', async () => {
    render(<Settings />);
    await userEvent.click(screen.getByRole('switch', { name: 'Auto-Connect' }));
    await waitFor(() => expect(saves()).toHaveLength(1));
    expect(useAppStore.getState().settings.autoConnect).toBe(true);
    expect(useAppStore.getState().notice).toBeNull();
  });

  it('a failed live reapply is reported with a Retry', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'reapply_vpn_settings') throw 'tunnel rebuild failed';
      if (cmd === 'check_biometric_available') return { available: false, enabled: false, method: 'none' };
      return undefined;
    });
    useAppStore.setState({ connectionState: 'connected' });
    render(<Settings />);
    await userEvent.click(screen.getByRole('switch', { name: 'Quantum Protection' }));
    await waitFor(() => expect(useAppStore.getState().notice?.actionLabel).toBe('Retry'), { timeout: 3000 });
    expect(useAppStore.getState().notice?.text).toBe("Couldn't apply that change to your live connection.");
  });
});

describe('VPN Settings: port and MTU are drafts too', () => {
  it('a custom port saves on leave, never mid-typing, and an out-of-range one is refused', async () => {
    render(<VpnSettings />);
    await userEvent.click(screen.getByRole('radio', { name: 'Custom' }));
    const port = screen.getByRole('textbox', { name: 'Custom WireGuard port' });
    await userEvent.type(port, '5182');
    expect(saves()).toHaveLength(0);
    await userEvent.type(port, '0');
    fireEvent.blur(port);
    await waitFor(() => expect(saves()).toHaveLength(1));
    expect(saves()[0].wireguard_port).toBe('51820');

    await userEvent.clear(port);
    await userEvent.type(port, '70000');
    fireEvent.blur(port);
    expect(await screen.findByText('Enter a port from 1 to 65535.')).toBeInTheDocument();
    expect(saves()).toHaveLength(1);
  });

  it('the port options are a real radio group with arrow keys (W2-035)', async () => {
    render(<VpnSettings />);
    const group = screen.getByRole('radiogroup', { name: 'WireGuard Port' });
    const auto = screen.getByRole('radio', { name: 'Automatic' });
    expect(auto).toHaveAttribute('aria-checked', 'true');
    expect(auto).toHaveAttribute('tabindex', '0');
    expect(screen.getByRole('radio', { name: '53' })).toHaveAttribute('tabindex', '-1');
    auto.focus();
    await userEvent.keyboard('{ArrowDown}');
    await waitFor(() => expect(saves()).toHaveLength(1));
    expect(saves()[0].wireguard_port).toBe('51820');
    expect(group).toBeInTheDocument();
  });

  it('MTU validates on leave (1280–1500)', async () => {
    useAppStore.setState({ settings: { ...defaultSettings, wireGuardMtu: 1420 } });
    render(<VpnSettings />);
    const mtu = screen.getByRole('textbox', { name: 'WireGuard MTU' });
    await userEvent.clear(mtu);
    await userEvent.type(mtu, '900');
    fireEvent.blur(mtu);
    expect(await screen.findByText('Enter a value from 1280 to 1500.')).toBeInTheDocument();
    expect(saves()).toHaveLength(0);
  });
});
