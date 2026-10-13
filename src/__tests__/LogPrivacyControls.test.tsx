/**
 * Settings › Privacy & Security › Save Diagnostic Logs and Delete Logs Now
 * (MR-808).
 *
 * Release builds keep `birdo.log` and crash files on the device: a dated
 * record of when it connected, reconnected and failed. These are the user's
 * controls over it. The switch is a setting like any other (saved through
 * `save_settings`, rolled back on failure), which Rust applies live; the
 * delete asks first, sends no path, and reports counts.
 *
 * These drive the real Settings screen over the real store.
 *
 * Run: npx vitest run src/__tests__/LogPrivacyControls.test.tsx
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import {
  DELETE_LOGS_CONFIRM_BODY,
  DELETE_LOGS_COPY,
  DELETE_LOGS_FAILED_COPY,
  DELETE_LOGS_STILL_ON_NOTE,
  FILE_LOGGING_COPY,
  Settings,
  deleteLogsNotice,
} from '@/components/Settings';
import { defaultSettings, useAppStore } from '@/store/app-store';
import { cancelScheduledReapply, forgetKillSwitchChoices } from '@/session/settings-persist';
import { resetUpdater } from '@/session/updater';
import { parseDeleteLogsResult } from '@/lib/ipc';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/plugin-shell', () => ({ open: vi.fn().mockResolvedValue(undefined) }));
vi.mock('@tauri-apps/plugin-process', () => ({ relaunch: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));

const mockedInvoke = vi.mocked(invoke);
let saveFails = false;
let deleteAnswer: () => Promise<unknown> = async () => ({ deleted: 2, failed: 0 });

beforeEach(() => {
  saveFails = false;
  deleteAnswer = async () => ({ deleted: 2, failed: 0 });
  resetUpdater();
  cancelScheduledReapply();
  forgetKillSwitchChoices();
  useAppStore.getState().logout();
  useAppStore.setState({
    isAuthenticated: true,
    connectionState: 'disconnected',
    notice: null,
    settings: { ...defaultSettings },
    settingsHydrated: true,
  });
  mockedInvoke.mockReset();
  mockedInvoke.mockImplementation(async (cmd: string) => {
    if (cmd === 'save_settings' && saveFails) throw 'disk full';
    if (cmd === 'delete_logs') return deleteAnswer();
    if (cmd === 'check_biometric_available') return { available: false, enabled: false, method: 'none' };
    if (cmd === 'get_app_version') return '1.4.47';
    return undefined;
  });
});

afterEach(() => cancelScheduledReapply());

const saves = () =>
  mockedInvoke.mock.calls
    .filter(([c]) => c === 'save_settings')
    .map(([, a]) => (a as { settings: Record<string, unknown> }).settings);
const deletes = () => mockedInvoke.mock.calls.filter(([c]) => c === 'delete_logs');
const logSwitch = () => screen.getByRole('switch', { name: 'Save Diagnostic Logs' });
const deleteRow = () => screen.getByRole('button', { name: /Delete Logs Now/ });

describe('Save Diagnostic Logs', () => {
  it('is on by default, under Privacy & Security, and says what it keeps and what off does', () => {
    render(<Settings />);
    expect(logSwitch()).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByText(FILE_LOGGING_COPY)).toBeInTheDocument();
    expect(FILE_LOGGING_COPY).toMatch(/on this device/);
    expect(FILE_LOGGING_COPY).toMatch(/last 7 days/);
    expect(FILE_LOGGING_COPY).toMatch(/never sends it/);
    expect(FILE_LOGGING_COPY).toMatch(/does not delete existing logs/);
    // Rust applies it live in both directions: no restart note.
    expect(FILE_LOGGING_COPY).not.toMatch(/restart/i);
    // In Privacy & Security, after Crash Reports and before Connection.
    const follows = (a: Element, b: Element) =>
      Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
    const crash = screen.getByRole('switch', { name: 'Crash Reports' });
    const connection = screen.getByText('Connection');
    expect(follows(screen.getByText('Privacy & Security'), crash)).toBe(true);
    expect(follows(crash, logSwitch())).toBe(true);
    expect(follows(logSwitch(), deleteRow())).toBe(true);
    expect(follows(deleteRow(), connection)).toBe(true);
  });

  it('turning it off is a whole-object save carrying file_logging_enabled: false, with no tunnel reapply', async () => {
    render(<Settings />);
    await userEvent.click(logSwitch());
    await waitFor(() => expect(saves()).toHaveLength(1));
    expect(saves()[0]).toMatchObject({
      file_logging_enabled: false,
      // The rest of the settings travel unchanged.
      killswitch_enabled: true,
      quantum_protection: true,
      crash_reports_enabled: false,
    });
    expect(useAppStore.getState().settings.fileLoggingEnabled).toBe(false);
    expect(logSwitch()).toHaveAttribute('aria-checked', 'false');
    expect(mockedInvoke).not.toHaveBeenCalledWith('reapply_vpn_settings');
    expect(useAppStore.getState().notice).toBeNull();
  });

  it('a save of anything else keeps an "off" (the key is always written)', async () => {
    useAppStore.setState({ settings: { ...defaultSettings, fileLoggingEnabled: false } });
    render(<Settings />);
    await userEvent.click(screen.getByRole('switch', { name: 'Auto-Connect' }));
    await waitFor(() => expect(saves()).toHaveLength(1));
    expect(saves()[0].file_logging_enabled).toBe(false);
  });

  it('a failed save puts the switch back and says so', async () => {
    saveFails = true;
    render(<Settings />);
    await userEvent.click(logSwitch());
    await waitFor(() => expect(useAppStore.getState().notice?.text).toMatch(/Couldn't save that setting/));
    expect(useAppStore.getState().settings.fileLoggingEnabled).toBe(true);
    expect(logSwitch()).toHaveAttribute('aria-checked', 'true');
  });
});

describe('Delete Logs Now', () => {
  it('says what it deletes, and asks before deleting anything', async () => {
    render(<Settings />);
    expect(screen.getByText(DELETE_LOGS_COPY)).toBeInTheDocument();
    await userEvent.click(deleteRow());
    expect(await screen.findByText('Delete logs?')).toBeInTheDocument();
    expect(deletes()).toHaveLength(0);
  });

  it('Cancel deletes nothing', async () => {
    render(<Settings />);
    await userEvent.click(deleteRow());
    await userEvent.click(await screen.findByRole('button', { name: 'Cancel' }));
    await waitFor(() => expect(screen.queryByText('Delete logs?')).not.toBeInTheDocument());
    expect(deletes()).toHaveLength(0);
    expect(useAppStore.getState().notice).toBeNull();
  });

  it('confirming deletes once, sends no path, and reports the count', async () => {
    render(<Settings />);
    await userEvent.click(deleteRow());
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(useAppStore.getState().notice?.text).toBe('Deleted 2 log files.'));
    expect(deletes()).toEqual([['delete_logs']]);
    expect(useAppStore.getState().notice?.tone).toBe('info');
    await waitFor(() => expect(screen.queryByText('Delete logs?')).not.toBeInTheDocument());
    // Deleting is not a setting: nothing is saved.
    expect(saves()).toHaveLength(0);
  });

  it('while the log is on, the confirmation says new entries start a new log; off, it does not', async () => {
    const { unmount } = render(<Settings />);
    await userEvent.click(deleteRow());
    expect(await screen.findByText(DELETE_LOGS_CONFIRM_BODY + DELETE_LOGS_STILL_ON_NOTE)).toBeInTheDocument();
    unmount();

    useAppStore.setState({ settings: { ...defaultSettings, fileLoggingEnabled: false } });
    render(<Settings />);
    await userEvent.click(deleteRow());
    expect(await screen.findByText(DELETE_LOGS_CONFIRM_BODY)).toBeInTheDocument();
  });

  it('files another program holds are reported, never claimed as deleted', async () => {
    deleteAnswer = async () => ({ deleted: 1, failed: 2 });
    render(<Settings />);
    await userEvent.click(deleteRow());
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(useAppStore.getState().notice?.tone).toBe('danger'));
    expect(useAppStore.getState().notice?.text).toBe(
      "Deleted 1 log file, but 2 log files couldn't be deleted. Close any program that has them open and try again.",
    );
  });

  it.each([
    ['the command fails', async () => Promise.reject(new Error('boom'))],
    ['the answer is not counts', async () => ({ deleted: 'all' })],
  ])('%s: it says the logs were not deleted', async (_label, answer) => {
    deleteAnswer = answer;
    render(<Settings />);
    await userEvent.click(deleteRow());
    await userEvent.click(await screen.findByRole('button', { name: 'Delete' }));
    await waitFor(() => expect(useAppStore.getState().notice?.text).toBe(DELETE_LOGS_FAILED_COPY));
    expect(useAppStore.getState().notice?.tone).toBe('danger');
  });
});

describe('the delete_logs answer', () => {
  it('parses counts and nothing else', () => {
    expect(parseDeleteLogsResult({ deleted: 3, failed: 0 })).toEqual({ deleted: 3, failed: 0 });
    for (const bad of [null, 'ok', 3, { deleted: 1 }, { deleted: -1, failed: 0 }, { deleted: '1', failed: 0 }]) {
      expect(parseDeleteLogsResult(bad)).toBeNull();
    }
  });

  it('words each outcome', () => {
    expect(deleteLogsNotice({ deleted: 0, failed: 0 })).toEqual({
      text: 'There were no logs to delete.',
      tone: 'info',
    });
    expect(deleteLogsNotice({ deleted: 1, failed: 0 }).text).toBe('Deleted 1 log file.');
    expect(deleteLogsNotice({ deleted: 0, failed: 1 })).toEqual({
      text: "1 log file couldn't be deleted. Close any program that has them open and try again.",
      tone: 'danger',
    });
  });
});
