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
  KILL_SWITCH_ON_FAILED_COPY,
  KILL_SWITCH_OFF_THIS_CONNECTION_COPY,
  persistSettings,
  reloadSettings,
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

  it('the first save that lands after an unverifiable start-up marks the settings as loaded (round 6, P3-4)', async () => {
    useAppStore.setState({ settingsHydrated: false });
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'save_settings') throw unverified;
      return undefined;
    });
    await persistSettings({ autoConnect: true }, { quiet: true });
    expect(useAppStore.getState().settingsHydrated).toBe(false);
    // The file can be verified again: this save lands, and the store is
    // what the file holds.
    mockedInvoke.mockImplementation(async () => undefined);
    expect(await persistSettings({ autoConnect: true })).toBe(true);
    expect(useAppStore.getState().settingsHydrated).toBe(true);
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
  /** The intent's sequence: every live push moves it. */
  let seq = 0;
  let saveRefused = false;
  let stopWatching: () => void = () => {};
  beforeEach(() => {
    intent = false;
    seq = 0;
    saveRefused = false;
    stopWatching = watchKillSwitchAcrossDials();
    mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === 'save_settings' && saveRefused) throw UNVERIFIED;
      if (cmd === 'set_killswitch_live') {
        intent = (args as { enabled: boolean }).enabled;
        seq += 1;
        return true;
      }
      if (cmd === 'get_killswitch_status') return { enabled: intent, active: false, blocking_connections: 0 };
      if (cmd === 'reset_settings') return true;
      // What get_settings served for an unverifiable file before this round:
      // the stand-in defaults.
      if (cmd === 'get_settings') return settingsToRust(defaultSettings);
      return undefined;
    });
  });
  afterEach(() => stopWatching());
  const statusChecks = () => mockedInvoke.mock.calls.filter(([c]) => c === 'get_killswitch_status');

  it('a refused OFF that lands during a dial still holds once that dial has armed ON (N1)', async () => {
    useAppStore.setState({ connectionState: 'connecting', settings: { ...defaultSettings, killSwitchEnabled: true } });
    saveRefused = true;
    await setKillSwitch(false);
    expect(intent).toBe(false);
    expect(useAppStore.getState().notice?.text).toBe(KILL_SWITCH_OFF_THIS_CONNECTION_COPY);
    // The dial ends: its own arm read the file (or the defaults standing in
    // for it) and armed ON.
    intent = true;
    act(() => useAppStore.setState({ connectionState: 'connected' }));
    await waitFor(() => expect(intent).toBe(false));
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
  });

  // Round 6 (P3-1): Rust publishes Connected BEFORE the dial's arm, so the
  // check above usually runs first and finds the OFF in force. The dial's arm
  // then takes the sequence read when the dial began and stands aside, since
  // the OFF moved it (killswitch `an_off_during_the_dial_makes_its_arm_stand_aside`,
  // session `the_dials_arm_takes_the_intent_sequence_from_the_dials_start`).
  it('a refused OFF during a dial holds when the dial\'s arm lands after `connected` (round 6, P3-1)', async () => {
    useAppStore.setState({ connectionState: 'connecting', settings: { ...defaultSettings, killSwitchEnabled: true } });
    const dialBegan = seq; // Rust: connect_session_for reads intent_seq()
    saveRefused = true;
    await setKillSwitch(false);
    act(() => useAppStore.setState({ connectionState: 'connected' }));
    await waitFor(() => expect(statusChecks()).toHaveLength(1));
    // The dial's arm lands now: arm_since(dialBegan) stores ON only if
    // nothing wrote the intent since the dial began.
    if (seq === dialBegan) intent = true;
    await new Promise((r) => setTimeout(r, 0));
    expect(intent).toBe(false);
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
  });

  // Round 7 (N2): a dial that Rust starts itself (the tray's Quick Connect)
  // can take an older OFF from the UI before the UI has seen it begin. The
  // dial's arm stands aside for it, then the UI ends "this connection" and
  // shows ON again: the end of that dial must put the intent back.
  it('a stale OFF that lands inside a dial Rust started is undone when that dial ends (round 7, N2)', async () => {
    useAppStore.setState({ connectionState: 'connected', settings: { ...defaultSettings, killSwitchEnabled: true } });
    const dialBegan = seq; // the tray's dial begins in Rust; the UI has not seen it yet
    saveRefused = true;
    await setKillSwitch(false); // its push lands inside that dial
    expect(intent).toBe(false);
    act(() => useAppStore.setState({ connectionState: 'switching' }));
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true);
    if (seq === dialBegan) intent = true; // the dial's arm: it stands aside
    act(() => useAppStore.setState({ connectionState: 'connected' }));
    await waitFor(() => expect(intent).toBe(true));
  });

  it('an ON the dial-end check could not push says so (round 7, N2)', async () => {
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === 'set_killswitch_live' && (args as { enabled: boolean }).enabled) throw 'arm failed';
      return base(cmd, args as never);
    });
    useAppStore.setState({ connectionState: 'connecting', settings: { ...defaultSettings, killSwitchEnabled: false } });
    await setKillSwitch(true);
    act(() => useAppStore.setState({ connectionState: 'connected' }));
    await waitFor(() => expect(useAppStore.getState().notice?.text).toBe(KILL_SWITCH_ON_FAILED_COPY));
    expect(intent).toBe(false);
  });

  it('an ON saved during connecting is pushed once the dial is up without it, and never on a failed dial', async () => {
    useAppStore.setState({ connectionState: 'connecting', settings: { ...defaultSettings, killSwitchEnabled: false } });
    await setKillSwitch(true);
    // Not pushed while connecting; the dial read the file before the save.
    expect(mockedInvoke.mock.calls.some(([c]) => c === 'set_killswitch_live')).toBe(false);
    act(() => useAppStore.setState({ connectionState: 'connected' }));
    await waitFor(() => expect(intent).toBe(true));

    // A dial that fails gets no ON of its own.
    intent = false;
    act(() => useAppStore.setState({ connectionState: 'switching' }));
    act(() => useAppStore.setState({ connectionState: 'error' }));
    await waitFor(() => expect(statusChecks()).toHaveLength(2));
    await new Promise((r) => setTimeout(r, 0));
    expect(intent).toBe(false);
  });

  // Round 6 (P2-2) kept the toggle OFF when a later save had written the OFF
  // to the file. Round 7 (N4): no unrelated save writes it any more — the
  // notice promised the saved ON back at the next connection — so the file
  // keeps ON, the toggle shows the live OFF, and the next dial brings ON back.
  it('a refused OFF is not written to the file by a later save of another setting (round 7, N4)', async () => {
    useAppStore.setState({ connectionState: 'reconnecting', settings: { ...defaultSettings, killSwitchEnabled: true } });
    saveRefused = true;
    await setKillSwitch(false);
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
    // The file can be verified again; another setting's save lands.
    saveRefused = false;
    expect(await persistSettings({ autoConnect: true })).toBe(true);
    expect(saves()[saves().length - 1]?.killswitch_enabled).toBe(true);
    expect(saves()[saves().length - 1]?.auto_connect).toBe(true);
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
    // The next dial arms from that file, ON, and the toggle says so.
    act(() => useAppStore.setState({ connectionState: 'connecting' }));
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true);
  });

  it('a reset drops the standing choice, so the next dial is not pushed back to it (round 6, P3-2)', async () => {
    useAppStore.setState({ connectionState: 'connected', settings: { ...defaultSettings, killSwitchEnabled: true } });
    await setKillSwitch(false);
    expect(intent).toBe(false);
    await resetSettings();
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true);
    // The session is rebuilt on the defaults, and that dial arms ON.
    act(() => useAppStore.setState({ connectionState: 'switching' }));
    intent = true;
    act(() => useAppStore.setState({ connectionState: 'connected' }));
    await new Promise((r) => setTimeout(r, 0));
    expect(intent).toBe(true);
  });

  // Round 8 (E2): the reapply after a reset runs only while connected, and
  // the auto-reconnect never arms, so a reset while reconnecting or in error
  // left a this-connection OFF in force under a toggle reading ON.
  it('a reset while reconnecting gives the session the defaults\' kill switch at once (round 8, E2)', async () => {
    useAppStore.setState({ connectionState: 'reconnecting', settings: { ...defaultSettings, killSwitchEnabled: true } });
    saveRefused = true;
    await setKillSwitch(false);
    expect(intent).toBe(false);
    await resetSettings();
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true);
    expect(intent).toBe(true);
  });

  it('a reset whose kill switch cannot be pushed says so (round 8, E2)', async () => {
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === 'set_killswitch_live' && (args as { enabled: boolean }).enabled) throw 'arm failed';
      return base(cmd, args as never);
    });
    useAppStore.setState({ connectionState: 'error', settings: { ...defaultSettings, killSwitchEnabled: true } });
    saveRefused = true;
    await setKillSwitch(false);
    await resetSettings();
    expect(useAppStore.getState().notice?.text).toBe(KILL_SWITCH_ON_FAILED_COPY);
    expect(intent).toBe(false);
  });

  // Round 8 (E1), reproduced: OFF for this connection (the file could not
  // be verified), the key comes back, Reset finds nothing to reset and the
  // screen re-reads the file. The toggle read ON while the intent was OFF.
  it('a re-read over a this-connection OFF keeps it on screen: Reset that finds nothing to reset (round 8, E1)', async () => {
    useAppStore.setState({ connectionState: 'connected', settings: { ...defaultSettings, killSwitchEnabled: true } });
    saveRefused = true;
    await setKillSwitch(false);
    expect(intent).toBe(false);
    // The key is back: nothing to reset, and the file (ON) is re-read.
    saveRefused = false;
    mockedInvoke.mockImplementation(
      ((base) => async (cmd: string, args?: unknown) =>
        cmd === 'reset_settings' ? false : base(cmd, args as never))(mockedInvoke.getMockImplementation()!),
    );
    await resetSettings();
    expect(useAppStore.getState().notice?.text).toBe(
      'Your saved settings can be read again, so nothing was reset.',
    );
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
    expect(intent).toBe(false);
    // The file's ON is what comes back at the next dial, and what a save of
    // anything else writes meanwhile.
    expect(await persistSettings({ autoConnect: true })).toBe(true);
    expect(saves()[saves().length - 1]?.killswitch_enabled).toBe(true);
    act(() => useAppStore.setState({ connectionState: 'switching' }));
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true);
  });

  it('every re-read keeps a this-connection OFF on screen, and only the file\'s value changes (round 8, E1)', async () => {
    useAppStore.setState({ connectionState: 'reconnecting', settings: { ...defaultSettings, killSwitchEnabled: true } });
    saveRefused = true;
    await setKillSwitch(false);
    saveRefused = false;
    // The file now says OFF (saved elsewhere); the re-read takes that as the
    // value to give way to, and the toggle still shows the live OFF.
    mockedInvoke.mockImplementation(
      ((base) => async (cmd: string, args?: unknown) =>
        cmd === 'get_settings'
          ? settingsToRust({ ...defaultSettings, killSwitchEnabled: false, autoConnect: true })
          : base(cmd, args as never))(mockedInvoke.getMockImplementation()!),
    );
    await reloadSettings();
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
    expect(useAppStore.getState().settings.autoConnect).toBe(true);
    act(() => useAppStore.setState({ connectionState: 'connecting' }));
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);

    // And no path re-reads around it.
    const source = readFileSync(resolve(__dirname, '../session/settings-persist.ts'), 'utf8');
    expect(source.match(/(await|void) loadSettings\(/g)).toEqual(['await loadSettings(']);
    const controller = readFileSync(resolve(__dirname, '../session/controller.tsx'), 'utf8');
    expect(controller).not.toMatch(/(await|void) loadSettings\(/);
  });

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

  // Round 6 (P3-3): round 5 copied Rust's intent into settings that had not
  // come from Rust. That read can precede the dial's arm, and a later save
  // then wrote it over the file. With no choice made, nothing is touched.
  it('with no choice made, the dial end leaves the settings alone, hydrated or not (round 6, P3-3)', async () => {
    for (const settingsHydrated of [false, true]) {
      useAppStore.setState({
        connectionState: 'connecting',
        settingsHydrated,
        settings: { ...defaultSettings, killSwitchEnabled: false },
      });
      intent = true;
      act(() => useAppStore.setState({ connectionState: 'connected' }));
      await new Promise((r) => setTimeout(r, 0));
      expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
    }
    expect(statusChecks()).toHaveLength(0);
  });

  const pushesOn = () =>
    mockedInvoke.mock.calls.filter(
      ([c, a]) => c === 'set_killswitch_live' && (a as { enabled: boolean }).enabled,
    );

  // Follow-up 1 to the review of #222: the reset pushed ON whatever Rust's
  // intent was. The push re-arms, and while reconnecting in Windows lockdown
  // no tunnel LUID is published: activate_blocking refuses and arm falls
  // back to the reactive kill switch for the rest of the session
  // (killswitch.rs, arm_with_preference) — a kill switch that was already on
  // lost its lockdown.
  describe('a reset leaves a kill switch that is already on alone (follow-up 1)', () => {
    /** The session's lockdown: an ON pushed while reconnecting drops it. */
    let lockdown = true;
    beforeEach(() => {
      lockdown = true;
      const base = mockedInvoke.getMockImplementation()!;
      mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
        if (
          cmd === 'set_killswitch_live' &&
          (args as { enabled: boolean }).enabled &&
          useAppStore.getState().connectionState === 'reconnecting'
        ) {
          lockdown = false;
        }
        return base(cmd, args as never);
      });
    });

    it('reconnecting in lockdown with the kill switch on: nothing is pushed, and lockdown stays', async () => {
      intent = true; // the session's dial armed it
      useAppStore.setState({ connectionState: 'reconnecting', settings: { ...defaultSettings, killSwitchEnabled: true } });
      await resetSettings();
      expect(useAppStore.getState().notice?.text).toBe('Your settings were reset to their defaults.');
      expect(pushesOn()).toHaveLength(0);
      expect(lockdown).toBe(true);
      expect(intent).toBe(true);
    });

    it('nor is an ON the user chose earlier pushed again', async () => {
      useAppStore.setState({ connectionState: 'connected', settings: { ...defaultSettings, killSwitchEnabled: false } });
      await setKillSwitch(true);
      expect(intent).toBe(true);
      act(() => useAppStore.setState({ connectionState: 'reconnecting' }));
      const before = pushesOn().length;
      await resetSettings();
      expect(pushesOn()).toHaveLength(before);
      expect(lockdown).toBe(true);
    });

    it('an intent that cannot be read is pushed, as before: OFF under a toggle reading ON is worse', async () => {
      const base = mockedInvoke.getMockImplementation()!;
      mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
        if (cmd === 'get_killswitch_status') throw 'status unavailable';
        return base(cmd, args as never);
      });
      useAppStore.setState({ connectionState: 'reconnecting', settings: { ...defaultSettings, killSwitchEnabled: true } });
      saveRefused = true;
      await setKillSwitch(false);
      expect(intent).toBe(false);
      await resetSettings();
      expect(intent).toBe(true);
    });
  });

  // Follow-up 2: an OFF clicked while reset_settings is in flight. Its save
  // was refused (the file could not be verified yet) and the refusal
  // answered after the reset: the reset forgot the OFF and pushed ON, and
  // the OFF then put the toggle back to OFF — the toggle OFF, the intent ON.
  it('an OFF made while reset_settings runs keeps the kill switch: not forgotten, no ON pushed over it (follow-up 2)', async () => {
    let answerReset: (reset: boolean) => void = () => {};
    let refuseSave: () => void = () => {};
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === 'reset_settings') return new Promise((r) => (answerReset = r));
      if (cmd === 'save_settings') return new Promise((_, reject) => (refuseSave = () => reject(UNVERIFIED)));
      return base(cmd, args as never);
    });
    intent = true;
    useAppStore.setState({ connectionState: 'reconnecting', settings: { ...defaultSettings, killSwitchEnabled: true } });
    const reset = resetSettings();
    const off = setKillSwitch(false);
    await waitFor(() => expect(intent).toBe(false)); // an OFF goes out before its save
    answerReset(true);
    await reset;
    refuseSave();
    await off;
    expect(useAppStore.getState().notice?.text).toBe(KILL_SWITCH_OFF_THIS_CONNECTION_COPY);
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
    expect(intent).toBe(false);
    expect(pushesOn()).toHaveLength(0);
    // It holds for this connection only: the next dial brings back the file's ON.
    act(() => useAppStore.setState({ connectionState: 'connecting' }));
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true);
  });

  it('an OFF made while reset_settings runs, whose save lands after the re-read, stays on the toggle (follow-up 2)', async () => {
    let answerReset: (reset: boolean) => void = () => {};
    let landSave: () => void = () => {};
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === 'reset_settings') return new Promise((r) => (answerReset = r));
      if (cmd === 'save_settings') return new Promise<void>((r) => (landSave = r));
      return base(cmd, args as never);
    });
    intent = true;
    useAppStore.setState({ connectionState: 'reconnecting', settings: { ...defaultSettings, killSwitchEnabled: true } });
    const reset = resetSettings();
    const off = setKillSwitch(false);
    await waitFor(() => expect(intent).toBe(false));
    answerReset(true);
    await reset;
    landSave();
    await off;
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
    expect(intent).toBe(false);
  });

  // Review of #255, L1: the reset left the kill switch to an ON still being
  // made, whose save was then refused. The toggle went back to OFF and the
  // intent stayed OFF while the file held the defaults' ON: honest on screen,
  // but the reset's kill switch was lost. It now finishes once the ON ends.
  it('a reset left to an ON that is then refused finishes: the defaults\' kill switch, on screen and live (L1)', async () => {
    let refuseSave: () => void = () => {};
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === 'save_settings') return new Promise((_, reject) => (refuseSave = () => reject(UNVERIFIED)));
      return base(cmd, args as never);
    });
    useAppStore.setState({ connectionState: 'connected', settings: { ...defaultSettings, killSwitchEnabled: false } });
    const on = setKillSwitch(true);
    await resetSettings(); // the defaults are saved; the toggle is left to the ON
    expect(intent).toBe(false);
    refuseSave();
    await on;
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true);
    expect(intent).toBe(true);
    expect(pushesOn()).toHaveLength(1);
  });

  it('a reset left to a choice that takes stays left to it: nothing re-read, no ON pushed (L1)', async () => {
    let landSave: () => void = () => {};
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === 'save_settings') return new Promise<void>((r) => (landSave = r));
      return base(cmd, args as never);
    });
    intent = true;
    useAppStore.setState({ connectionState: 'reconnecting', settings: { ...defaultSettings, killSwitchEnabled: true } });
    // Made before the reset, saved after it.
    const off = setKillSwitch(false);
    await waitFor(() => expect(intent).toBe(false));
    await resetSettings();
    landSave();
    await off;
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
    expect(intent).toBe(false);
    expect(pushesOn()).toHaveLength(0);
    expect(mockedInvoke.mock.calls.filter(([c]) => c === 'get_settings')).toHaveLength(1);
  });

  // Review of #261.
  it('two choices in flight at the reset, both refused: it finishes once, after the last (REVIEW-E)', async () => {
    const refusals: Array<() => void> = [];
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === 'save_settings') return new Promise((_, reject) => refusals.push(() => reject(UNVERIFIED)));
      return base(cmd, args as never);
    });
    useAppStore.setState({ connectionState: 'connected', settings: { ...defaultSettings, killSwitchEnabled: false } });
    const a = setKillSwitch(true);
    const b = setKillSwitch(true);
    await waitFor(() => expect(refusals).toHaveLength(2));
    await resetSettings();
    refusals[0]();
    await a;
    expect(pushesOn()).toHaveLength(0);
    refusals[1]();
    await b;
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true);
    expect(intent).toBe(true);
    expect(pushesOn()).toHaveLength(1);
  });

  it('a this-connection OFF made during the reset stands when an older ON in flight is refused (REVIEW-F)', async () => {
    let answerReset: (r: boolean) => void = () => {};
    const refusals: Array<() => void> = [];
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === 'reset_settings') return new Promise((r) => (answerReset = r));
      if (cmd === 'save_settings') return new Promise((_, reject) => refusals.push(() => reject(UNVERIFIED)));
      return base(cmd, args as never);
    });
    useAppStore.setState({ connectionState: 'connected', settings: { ...defaultSettings, killSwitchEnabled: false } });
    const on = setKillSwitch(true);
    await waitFor(() => expect(refusals).toHaveLength(1));
    const reset = resetSettings();
    const off = setKillSwitch(false);
    await waitFor(() => expect(refusals).toHaveLength(2));
    refusals[1]();
    await off;
    answerReset(true);
    await reset;
    refusals[0]();
    await on;
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
    expect(intent).toBe(false);
    expect(pushesOn()).toHaveLength(0);
  });

  it('a reset that finishes for a refused ON says so last, over the refusal (REVIEW-N)', async () => {
    let refuseSave: () => void = () => {};
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === 'save_settings') return new Promise((_, reject) => (refuseSave = () => reject(UNVERIFIED)));
      return base(cmd, args as never);
    });
    useAppStore.setState({ connectionState: 'connected', settings: { ...defaultSettings, killSwitchEnabled: false } });
    const on = setKillSwitch(true);
    await resetSettings();
    refuseSave();
    await on;
    // Not the refusal's "could not be verified ... Reset settings".
    expect(useAppStore.getState().notice?.text).toBe('Your settings were reset to their defaults.');
    expect(useAppStore.getState().notice?.actionLabel).toBeUndefined();
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true);
    expect(intent).toBe(true);
  });

  // REVIEW-P/Q: ON is not pushed during a dial; the dial's own arm brings it.
  // But that arm stands aside when the intent moved after the dial began (an
  // OFF pushed during it: arm_since), and the reset has just forgotten the
  // choice the dial-end check would compare, so the dial came up OFF under a
  // toggle reading ON.
  it('a reset during a switch that an OFF already moved: the dial comes up ON (REVIEW-P)', async () => {
    useAppStore.setState({ connectionState: 'switching', settings: { ...defaultSettings, killSwitchEnabled: true } });
    const dialBegan = seq;
    saveRefused = true;
    await setKillSwitch(false); // pushed: the dial's arm will stand aside
    expect(intent).toBe(false);
    saveRefused = false;
    await resetSettings();
    expect(pushesOn()).toHaveLength(0); // not during the dial
    if (seq === dialBegan) intent = true; // the dial's arm_since
    act(() => useAppStore.setState({ connectionState: 'connected' }));
    await waitFor(() => expect(intent).toBe(true));
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true);
    expect(pushesOn()).toHaveLength(1);
  });

  it('a waiting reset finished during a switch that an OFF already moved: the dial comes up ON (REVIEW-Q)', async () => {
    useAppStore.setState({ connectionState: 'switching', settings: { ...defaultSettings, killSwitchEnabled: true } });
    const dialBegan = seq;
    saveRefused = true;
    await setKillSwitch(false); // this-connection OFF, pushed: the dial's arm will stand aside
    expect(intent).toBe(false);
    saveRefused = false;
    let refuseSave: () => void = () => {};
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === 'save_settings') return new Promise((_, reject) => (refuseSave = () => reject(UNVERIFIED)));
      return base(cmd, args as never);
    });
    const on = setKillSwitch(true); // persisted-only while switching; its save is refused
    await resetSettings();
    refuseSave();
    await on;
    expect(pushesOn()).toHaveLength(0); // not during the dial
    if (seq === dialBegan) intent = true; // the dial's arm_since
    act(() => useAppStore.setState({ connectionState: 'connected' }));
    await waitFor(() => expect(intent).toBe(true));
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true);
    expect(pushesOn()).toHaveLength(1);
  });

  it('a sign-out while a reset waits ends it: a refused choice in the next session re-runs nothing', async () => {
    const refusals: Array<() => void> = [];
    const base = mockedInvoke.getMockImplementation()!;
    mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
      if (cmd === 'save_settings') return new Promise((_, reject) => refusals.push(() => reject(UNVERIFIED)));
      return base(cmd, args as never);
    });
    useAppStore.setState({ connectionState: 'connected', settings: { ...defaultSettings, killSwitchEnabled: false } });
    const old = setKillSwitch(true);
    await resetSettings(); // left to the ON
    // Sign-out (the session controller's teardown), then the next session.
    forgetKillSwitchChoices();
    useAppStore.getState().logout();
    useAppStore.setState({
      isAuthenticated: true,
      connectionState: 'connected',
      settings: { ...defaultSettings, killSwitchEnabled: false },
    });
    const reads = mockedInvoke.mock.calls.filter(([c]) => c === 'get_settings').length;
    const next = setKillSwitch(true);
    await waitFor(() => expect(refusals).toHaveLength(2));
    refusals[0]();
    await old;
    refusals[1]();
    await next;
    expect(mockedInvoke.mock.calls.filter(([c]) => c === 'get_settings')).toHaveLength(reads);
    expect(pushesOn()).toHaveLength(0);
    expect(intent).toBe(false);
    expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
  });

  // Follow-up 4: a re-read in flight while the toggle moved hydrated the file
  // as it was before the save, so the toggle read ON beside an OFF that had
  // been pushed and saved — and the next save of anything wrote that ON.
  describe('a re-read keeps a kill switch toggle that moved under it (follow-up 4)', () => {
    let answerRead: (rs: unknown) => void = () => {};
    beforeEach(() => {
      const base = mockedInvoke.getMockImplementation()!;
      mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
        if (cmd === 'get_settings') return new Promise((r) => (answerRead = r));
        return base(cmd, args as never);
      });
    });

    it('a choice made while get_settings is in flight; every other field is hydrated', async () => {
      useAppStore.setState({ connectionState: 'connected', settings: { ...defaultSettings, killSwitchEnabled: true } });
      const read = reloadSettings();
      await setKillSwitch(false);
      expect(intent).toBe(false);
      expect(saves()[saves().length - 1]?.killswitch_enabled).toBe(false);
      // The read answers with the file as it was before that save.
      answerRead(settingsToRust({ ...defaultSettings, killSwitchEnabled: true, autoConnect: true }));
      await read;
      expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
      expect(useAppStore.getState().settings.autoConnect).toBe(true);
      expect(await persistSettings({ autoConnect: false })).toBe(true);
      expect(saves()[saves().length - 1]?.killswitch_enabled).toBe(false);
    });

    it('a choice still being made when the read lands', async () => {
      let landSave: () => void = () => {};
      const base = mockedInvoke.getMockImplementation()!;
      mockedInvoke.mockImplementation(async (cmd: string, args?: unknown) => {
        if (cmd === 'save_settings') return new Promise<void>((r) => (landSave = r));
        return base(cmd, args as never);
      });
      useAppStore.setState({ connectionState: 'connected', settings: { ...defaultSettings, killSwitchEnabled: true } });
      const off = setKillSwitch(false);
      await waitFor(() => expect(intent).toBe(false));
      const read = reloadSettings();
      answerRead(settingsToRust({ ...defaultSettings, killSwitchEnabled: true }));
      await read;
      expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
      landSave();
      await off;
      expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
      expect(intent).toBe(false);
    });

    it('a choice that did not take leaves the toggle to what is read', async () => {
      useAppStore.setState({ connectionState: 'connected', settings: { ...defaultSettings, killSwitchEnabled: false } });
      const read = reloadSettings();
      saveRefused = true;
      await setKillSwitch(true); // refused: the toggle goes back to OFF
      expect(useAppStore.getState().settings.killSwitchEnabled).toBe(false);
      // The file says ON: a stale OFF kept here would be written over it.
      answerRead(settingsToRust({ ...defaultSettings, killSwitchEnabled: true }));
      await read;
      expect(useAppStore.getState().settings.killSwitchEnabled).toBe(true);
    });
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
