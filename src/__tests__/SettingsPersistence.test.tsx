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
import { act, render, screen, waitFor, fireEvent, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { Settings } from '@/components/Settings';
import { VpnSettings } from '@/screens/VpnSettings';
import { defaultSettings, useAppStore } from '@/store/app-store';
import {
  askToResetSettings,
  cancelScheduledReapply,
  CONSENT_CRASH_CHOICE_FAILED_COPY,
  forgetKillSwitchChoices,
  KILL_SWITCH_OFF_THIS_CONNECTION_COPY,
  persistSettings,
  resetSettings,
  saveConsentCrashChoice,
  setKillSwitch,
  useResetPrompt,
  REAPPLY_REVERTED_COPY,
  REAPPLY_WAIT_MS,
  scheduleReapply,
  watchKillSwitchAcrossDials,
} from '@/session/settings-persist';
import { settingsToRust } from '@/utils/helpers';
import { resetUpdater } from '@/session/updater';
import { SETTINGS_UNVERIFIED_COPY } from '@/lib/errors';
import { ResetSettingsDialog, RESET_SETTINGS_BODY } from '@/components/ResetSettingsDialog';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

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
  forgetKillSwitchChoices();
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

  it('a resolver on your own network says how it is reached (REVIEW-WIN2-006)', async () => {
    const lanNote = /on your own network can be reached only with Local Network Sharing on/;
    const outsideNote = /on your own network is reached directly, outside the VPN tunnel/;
    useAppStore.setState({ settings: { ...defaultSettings, customDnsEnabled: true, customDns: ['9.9.9.9'] } });
    const { unmount } = render(<Settings />);
    expect(screen.queryByText(lanNote)).not.toBeInTheDocument();

    const secondary = screen.getByRole('textbox', { name: 'Secondary DNS (optional)' });
    await userEvent.type(secondary, '192.168.1.2');
    expect(screen.getByText(lanNote)).toBeInTheDocument();
    unmount();

    useAppStore.setState({
      settings: { ...defaultSettings, customDnsEnabled: true, customDns: ['192.168.1.2'], localNetworkSharing: true },
    });
    render(<Settings />);
    expect(screen.getByText(outsideNote)).toBeInTheDocument();
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

describe('a settings file that cannot be verified (review of #222)', () => {
  const unverified = {
    code: 'settings_unverified',
    message: 'the settings file could not be verified, so it was left as it is',
    retryable: true,
    retry_after_secs: null,
  };

  it('says so instead of "please try again", and offers the reset', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'save_settings') throw unverified;
      return undefined;
    });
    expect(await persistSettings({ autoConnect: true })).toBe(false);
    const notice = useAppStore.getState().notice;
    expect(notice?.text).toBe(SETTINGS_UNVERIFIED_COPY);
    expect(notice?.actionLabel).toBe('Reset settings');
    expect(useAppStore.getState().settings.autoConnect).toBe(defaultSettings.autoConnect);

    // The notice only ASKS (round 3 of the review): nothing is reset until
    // the user confirms, and then the screen shows what is saved.
    render(<ResetSettingsDialog />);
    act(() => notice?.onAction?.());
    expect(await screen.findByText(RESET_SETTINGS_BODY)).toBeInTheDocument();
    expect(mockedInvoke.mock.calls.some(([c]) => c === 'reset_settings')).toBe(false);
    mockedInvoke.mockImplementation(async (cmd: string) => (cmd === 'reset_settings' ? true : undefined));
    await userEvent.click(screen.getByRole('button', { name: 'Reset settings' }));
    await waitFor(() => {
      const order = mockedInvoke.mock.calls.map(([c]) => c);
      expect(order.indexOf('reset_settings')).toBeGreaterThan(-1);
      expect(order.lastIndexOf('get_settings')).toBeGreaterThan(order.indexOf('reset_settings'));
    });
    expect(useAppStore.getState().notice?.text).toBe('Your settings were reset to their defaults.');
  });

  it('the reset is not run when the confirmation is cancelled', async () => {
    render(<ResetSettingsDialog />);
    act(() => askToResetSettings());
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel' }));
    expect(mockedInvoke.mock.calls.some(([c]) => c === 'reset_settings')).toBe(false);
    expect(useResetPrompt.getState().open).toBe(false);
  });

  it('a file that verifies again is not reset, and the user is told', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => (cmd === 'reset_settings' ? false : undefined));
    await resetSettings();
    expect(useAppStore.getState().notice?.text).toBe(
      'Your saved settings can be read again, so nothing was reset.',
    );
  });

  it('any other failed save keeps the plain message, with no reset', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'save_settings') throw { ...unverified, code: 'unknown' };
      return undefined;
    });
    await persistSettings({ autoConnect: true });
    const notice = useAppStore.getState().notice;
    expect(notice?.text).toMatch(/Couldn't save that setting/);
    expect(notice?.actionLabel).toBeUndefined();
  });
});

describe('a kill switch OFF whose save is refused (round 4 of the review of #222, P3-1)', () => {
  // The next dial ends "this connection" (round 5: through the watcher).
  let stopWatching: () => void = () => {};
  beforeEach(() => {
    stopWatching = watchKillSwitchAcrossDials();
  });
  afterEach(() => stopWatching());

  it('the toggle shows what is live, OFF for this connection, and what is saved again at the next dial', async () => {
    useAppStore.setState({
      connectionState: 'reconnecting',
      settings: { ...defaultSettings, killSwitchEnabled: true },
    });
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'save_settings') {
        throw {
          code: 'settings_unverified',
          message: 'the settings file could not be verified, so it was left as it is',
          retryable: true,
          retry_after_secs: null,
        };
      }
      if (cmd === 'get_settings') return settingsToRust({ ...defaultSettings, killSwitchEnabled: true });
      if (cmd === 'check_biometric_available') return { available: false, enabled: false, method: 'none' };
      return undefined;
    });
    render(<Settings />);
    const killSwitch = () => screen.getByRole('switch', { name: /kill switch/i });
    await userEvent.click(killSwitch());
    await userEvent.click(await screen.findByRole('button', { name: /turn off anyway/i }));
    await waitFor(() => {
      expect(useAppStore.getState().notice?.text).toBe(KILL_SWITCH_OFF_THIS_CONNECTION_COPY);
    });
    expect(useAppStore.getState().notice?.actionLabel).toBe('Reset settings');
    expect(mockedInvoke).toHaveBeenCalledWith('set_killswitch_live', { enabled: false });
    // It used to go back to ON here, over a kill switch that was off.
    expect(killSwitch()).toHaveAttribute('aria-checked', 'false');

    // The next dial arms from the file, which still says ON; so does the toggle.
    act(() => useAppStore.setState({ connectionState: 'connecting' }));
    await waitFor(() => expect(killSwitch()).toHaveAttribute('aria-checked', 'true'));
  });
});

describe('the kill switch across dials (round 5 of the review of #222)', () => {
  const UNVERIFIED = {
    code: 'settings_unverified',
    message: 'the settings file could not be verified, so it was left as it is',
    retryable: true,
    retry_after_secs: null,
  };
  /** Rust's intent, as `set_killswitch_live` and the dial's own arm leave it. */
  let intent = false;
  let saveRefused = false;
  let stopWatching: () => void = () => {};
  beforeEach(() => {
    intent = false;
    saveRefused = false;
    stopWatching = watchKillSwitchAcrossDials();
    mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === 'save_settings' && saveRefused) throw UNVERIFIED;
      if (cmd === 'set_killswitch_live') {
        intent = (args as { enabled: boolean }).enabled;
        return true;
      }
      if (cmd === 'get_killswitch_status') return { enabled: intent, active: false, blocking_connections: 0 };
      // What get_settings served for an unverifiable file before this round:
      // the stand-in defaults.
      if (cmd === 'get_settings') return settingsToRust(defaultSettings);
      return undefined;
    });
  });
  afterEach(() => stopWatching());

  it('the next dial puts back the kill switch alone, never an unverifiable file\'s stand-in defaults (N2)', async () => {
    const real = { ...defaultSettings, killSwitchEnabled: true, autoConnect: true, localNetworkSharing: true };
    useAppStore.setState({ connectionState: 'reconnecting', settings: real });
    saveRefused = true;
    await setKillSwitch(false);
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
    act(() => useAppStore.setState({ connectionState: 'connecting' }));
    await waitFor(() => expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true));
    await new Promise((r) => setTimeout(r, 0));
    expect(useAppStore.getState().settings).toEqual(real);
  });

});

describe('the crash-report choice on the consent screen (round 4 of the review of #222)', () => {
  const refuse = (error: unknown) =>
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'set_crash_reports_enabled') throw error;
      return undefined;
    });

  it('a file that cannot be verified is said so, with the reset, and the choice falls back OFF', async () => {
    const quiet = vi.spyOn(console, 'error').mockImplementation(() => {});
    refuse({
      code: 'settings_unverified',
      message: 'the settings file could not be verified, so it was left as it is',
      retryable: true,
      retry_after_secs: null,
    });
    await saveConsentCrashChoice(true);
    expect(useAppStore.getState().settings.crashReportsEnabled).toBe(false);
    const notice = useAppStore.getState().notice;
    expect(notice?.text).toBe(SETTINGS_UNVERIFIED_COPY);
    expect(notice?.actionLabel).toBe('Reset settings');
    quiet.mockRestore();
  });

  it('any other refusal says the choice did not stick', async () => {
    const quiet = vi.spyOn(console, 'error').mockImplementation(() => {});
    refuse('disk full');
    await saveConsentCrashChoice(true);
    expect(useAppStore.getState().settings.crashReportsEnabled).toBe(false);
    expect(useAppStore.getState().notice?.text).toBe(CONSENT_CRASH_CHOICE_FAILED_COPY);
    quiet.mockRestore();
  });

  it('a saved choice says nothing', async () => {
    await saveConsentCrashChoice(true);
    expect(useAppStore.getState().settings.crashReportsEnabled).toBe(true);
    expect(useAppStore.getState().notice).toBeNull();
  });

  it('the consent screen saves through it', () => {
    const app = readFileSync(resolve(__dirname, '../App.tsx'), 'utf8');
    const handler = app.slice(app.indexOf('const handleAcceptConsent'));
    expect(handler.slice(0, handler.indexOf('};'))).toContain(
      'saveConsentCrashChoice(crashReportsEnabled)',
    );
    expect(app).not.toContain("invoke('set_crash_reports_enabled'");
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

  // WIN-FIX-3: Rust could not apply the change, saved the previous settings
  // back and reconnected on them. The screen shows what is really in force
  // and says what happened — not a stranded error.
  it('a change the live connection could not take is put back, and the user is told', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'reapply_vpn_settings') return 'reverted';
      if (cmd === 'get_settings') return settingsToRust(defaultSettings);
      if (cmd === 'check_biometric_available') return { available: false, enabled: false, method: 'none' };
      return undefined;
    });
    useAppStore.setState({ connectionState: 'connected' });
    render(<Settings />);
    const pq = screen.getByRole('switch', { name: 'Quantum Protection' });
    expect(pq).toHaveAttribute('aria-checked', 'true');
    await userEvent.click(pq);
    await waitFor(() => expect(useAppStore.getState().notice?.text).toBe(REAPPLY_REVERTED_COPY), {
      timeout: 3000,
    });
    expect(REAPPLY_REVERTED_COPY).toBe("Couldn't apply that change — your previous setting was restored.");
    expect(useAppStore.getState().notice?.actionLabel).toBeUndefined();
    expect(useAppStore.getState().settings.quantumProtection).toBe(true);
    expect(screen.getByRole('switch', { name: 'Quantum Protection' })).toHaveAttribute('aria-checked', 'true');
  });

  // WIN3-002: the user pressed Disconnect while the change was being put
  // back. Rust saved the previous settings and did not reconnect; the screen
  // shows what is saved, and the Disconnect the user asked for is not
  // reported as a failure.
  it('a revert the user disconnected under says nothing and shows the saved settings', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      // Rust had saved the previous settings back before the Disconnect.
      if (cmd === 'reapply_vpn_settings') throw { code: 'cancelled', message: 'Cancelled.', settings_restored: true };
      if (cmd === 'get_settings') return settingsToRust(defaultSettings);
      if (cmd === 'check_biometric_available') return { available: false, enabled: false, method: 'none' };
      return undefined;
    });
    useAppStore.setState({ connectionState: 'connected' });
    render(<Settings />);
    await userEvent.click(screen.getByRole('switch', { name: 'Quantum Protection' }));
    await waitFor(() => expect(reapplies()).toHaveLength(1), { timeout: 3000 });
    await waitFor(() => expect(useAppStore.getState().reapplying).toBe(false));
    expect(useAppStore.getState().notice).toBeNull();
    expect(useAppStore.getState().settings.quantumProtection).toBe(true);
  });

  // WIN3-009: Rust is putting Quantum Protection back (the change failed) when
  // the user flips Auto-Connect. That full-object save must not write the
  // failed Quantum value back over the restored one: it waits for the
  // reapply and goes on top of what was saved.
  it('a save during a reapply that reverts goes on top of the restored settings', async () => {
    let finishReapply: (outcome: string) => void = () => {};
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'reapply_vpn_settings') return new Promise((resolve) => (finishReapply = resolve));
      if (cmd === 'get_settings') return settingsToRust(defaultSettings);
      if (cmd === 'check_biometric_available') return { available: false, enabled: false, method: 'none' };
      return undefined;
    });
    useAppStore.setState({ connectionState: 'connected' });
    render(<Settings />);
    await userEvent.click(screen.getByRole('switch', { name: 'Quantum Protection' }));
    await waitFor(() => expect(reapplies()).toHaveLength(1), { timeout: 3000 });
    expect(saves()).toHaveLength(1);
    expect(saves()[0].quantum_protection).toBe(false);

    await userEvent.click(screen.getByRole('switch', { name: 'Auto-Connect' }));
    expect(saves()).toHaveLength(1);
    expect(useAppStore.getState().settings.autoConnect).toBe(true);

    await act(async () => finishReapply('reverted'));
    await waitFor(() => expect(saves()).toHaveLength(2));
    expect(saves()[1].quantum_protection).toBe(true);
    expect(saves()[1].auto_connect).toBe(true);
    expect(useAppStore.getState().settings.quantumProtection).toBe(true);
    expect(useAppStore.getState().settings.autoConnect).toBe(true);
  });

  // REVIEW-WIN4-004: a failure with nothing saved back (a refused restore: the
  // settings file could not be verified) leaves the screen as it is. Re-reading
  // would hydrate the defaults Rust refused to save, and the next save would
  // write them over the user's file.
  it('a failed reapply that restored nothing does not re-read the settings', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'reapply_vpn_settings') throw { code: 'server_unreachable', message: 'Unreachable.' };
      if (cmd === 'get_settings') return settingsToRust(defaultSettings);
      if (cmd === 'check_biometric_available') return { available: false, enabled: false, method: 'none' };
      return undefined;
    });
    useAppStore.setState({ connectionState: 'connected' });
    render(<Settings />);
    const reads = () => mockedInvoke.mock.calls.filter(([c]) => c === 'get_settings').length;
    const readsBefore = reads();
    await userEvent.click(screen.getByRole('switch', { name: 'Quantum Protection' }));
    await waitFor(() => expect(reapplies()).toHaveLength(1), { timeout: 3000 });
    await waitFor(() => expect(useAppStore.getState().reapplying).toBe(false));
    expect(reads()).toBe(readsBefore);
    expect(useAppStore.getState().settings.quantumProtection).toBe(false);
    expect(useAppStore.getState().notice?.text).toBe("Couldn't apply that change to your live connection.");
  });

  // REVIEW-WIN4-003: a reapply that never answers holds a save only so long;
  // then the save re-reads the file and goes on top of it.
  it('a save waits for a wedged reapply only so long', async () => {
    vi.useFakeTimers();
    try {
      mockedInvoke.mockImplementation(async (cmd: string) => {
        if (cmd === 'reapply_vpn_settings') return new Promise(() => {});
        if (cmd === 'get_settings') return settingsToRust(defaultSettings);
        return undefined;
      });
      useAppStore.setState({ connectionState: 'connected' });
      scheduleReapply();
      await vi.advanceTimersByTimeAsync(1000);
      expect(reapplies()).toHaveLength(1);

      const saved = persistSettings({ killSwitchEnabled: false });
      await vi.advanceTimersByTimeAsync(REAPPLY_WAIT_MS - 1000);
      expect(saves()).toHaveLength(0);
      await vi.advanceTimersByTimeAsync(2000);
      await expect(saved).resolves.toBe(true);
      expect(saves()).toHaveLength(1);
      expect(saves()[0].killswitch_enabled).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('an applied change says nothing', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'reapply_vpn_settings') return 'applied';
      if (cmd === 'check_biometric_available') return { available: false, enabled: false, method: 'none' };
      return undefined;
    });
    useAppStore.setState({ connectionState: 'connected' });
    render(<Settings />);
    await userEvent.click(screen.getByRole('switch', { name: 'Quantum Protection' }));
    await waitFor(() => expect(reapplies()).toHaveLength(1), { timeout: 3000 });
    await waitFor(() => expect(useAppStore.getState().reapplying).toBe(false));
    expect(useAppStore.getState().notice).toBeNull();
    expect(useAppStore.getState().settings.quantumProtection).toBe(false);
  });
});

describe('VPN Settings: the port, and MTU as a draft', () => {
  // WIN-FIX-3: the relays accept WireGuard on 51820 only; the "53" preset and
  // the custom port failed the handshake on every one of them.
  it('offers Automatic and 51820 only', () => {
    render(<VpnSettings />);
    const group = screen.getByRole('radiogroup', { name: 'WireGuard Port' });
    expect(within(group).getAllByRole('radio').map((r) => r.textContent)).toEqual(['Automatic', '51820']);
    expect(screen.queryByRole('radio', { name: '53' })).toBeNull();
    expect(screen.queryByRole('radio', { name: 'Custom' })).toBeNull();
    expect(screen.queryByRole('textbox', { name: 'Custom WireGuard port' })).toBeNull();
    expect(screen.queryByText(/port 53/)).toBeNull();
  });

  it('the port options are a real radio group with arrow keys (W2-035)', async () => {
    render(<VpnSettings />);
    const group = screen.getByRole('radiogroup', { name: 'WireGuard Port' });
    const auto = screen.getByRole('radio', { name: 'Automatic' });
    expect(auto).toHaveAttribute('aria-checked', 'true');
    expect(auto).toHaveAttribute('tabindex', '0');
    expect(screen.getByRole('radio', { name: '51820' })).toHaveAttribute('tabindex', '-1');
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

  // WIN-FIX-3: a change Rust put back reaches the field, not only the store.
  it('the MTU field follows a value put back under it', async () => {
    useAppStore.setState({ settings: { ...defaultSettings, wireGuardMtu: 1280 } });
    render(<VpnSettings />);
    expect(screen.getByRole('textbox', { name: 'WireGuard MTU' })).toHaveValue('1280');
    act(() => useAppStore.getState().updateSettings({ wireGuardMtu: 1420 }));
    expect(screen.getByRole('textbox', { name: 'WireGuard MTU' })).toHaveValue('1420');
  });
});
