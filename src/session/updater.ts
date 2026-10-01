/**
 * Software-update state, owned by the app rather than by the Settings card
 * (W2-024). The card used to hold it in component state, so leaving Settings
 * mid-download and coming back re-ran the check and offered Download again
 * while `install_update` was still running — two installs of one update.
 *
 * The check and the download run in Rust over the CERT-PINNED client
 * (commands/updater.rs); the JS updater plugin's un-pinned path is not
 * reachable from the webview and must not become so.
 *
 * WINDOWS EXITS AT INSTALL. Per the Tauri v2 updater docs, "on Windows the
 * application is automatically exited when the install step is executed due to
 * a limitation of Windows installers" — so `install_update` does not return
 * there and the "Restart" step can never be reached. The UI says "Install and
 * restart" on Windows and warns first when a tunnel is up. Rust performs the
 * exit teardown (disconnect, release the kill switch) before it installs
 * (contract §3.5).
 */
import { create } from 'zustand';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { isWindowsPlatform } from '@/utils/helpers';

/** Mirrors `commands::updater::UpdateInfo` (serde camelCase). */
export interface UpdateInfo {
  version: string;
  currentVersion: string;
  notes?: string | null;
}

export type UpdatePhase =
  | 'idle'
  | 'checking'
  | 'available'
  | 'up-to-date'
  | 'installing'
  | 'ready'
  | 'error';

interface UpdaterState {
  phase: UpdatePhase;
  info: UpdateInfo | null;
  progress: number;
  error: string | null;
  /**
   * The install failed after Rust ended the VPN session for it, and the
   * session can be put back with one click (REVIEW-WIN-002). Under always-on
   * Rust reconnects by itself and this stays false.
   */
  reconnectOffered: boolean;
  appVersion: string | null;
}

export const useUpdater = create<UpdaterState>(() => ({
  phase: 'idle',
  info: null,
  progress: 0,
  error: null,
  reconnectOffered: false,
  appVersion: null,
}));

export const UPDATE_DOWNLOAD_FAILED_COPY = 'The update could not be downloaded or verified. Please try again.';
export const UPDATE_INSTALL_FAILED_COPY =
  'The update was downloaded but could not be installed. Please try again.';
const UPDATE_INSTALL_FAILED_RECONNECTING_COPY =
  'The update was downloaded but could not be installed. BirdoVPN is reconnecting.';

/**
 * `install_update`'s error (commands/updater.rs `UpdateFailure`): which stage
 * failed, and what Rust did about the session the install ended.
 */
function failureCopy(e: unknown): { error: string; reconnectOffered: boolean } {
  const f = typeof e === 'object' && e !== null ? (e as Record<string, unknown>) : {};
  if (f.code !== 'install_failed') {
    // A pin failure lands here too: the pinned client refuses the handshake
    // rather than downloading over an unverified chain.
    return { error: UPDATE_DOWNLOAD_FAILED_COPY, reconnectOffered: false };
  }
  return f.reconnect === 'automatic'
    ? { error: UPDATE_INSTALL_FAILED_RECONNECTING_COPY, reconnectOffered: false }
    : { error: UPDATE_INSTALL_FAILED_COPY, reconnectOffered: f.reconnect === 'offered' };
}

const CHECK_TIMEOUT_MS = 10_000;
let checkedThisRun = false;

/** For tests. */
export function resetUpdater(): void {
  checkedThisRun = false;
  useUpdater.setState({
    phase: 'idle',
    info: null,
    progress: 0,
    error: null,
    reconnectOffered: false,
    appVersion: null,
  });
}

/** On Windows the installer exits the app, so there is no separate restart step. */
export const installExitsApp = (): boolean => isWindowsPlatform();

export async function loadAppVersion(): Promise<void> {
  if (useUpdater.getState().appVersion) return;
  try {
    useUpdater.setState({ appVersion: await invoke<string>('get_app_version') });
  } catch {
    useUpdater.setState({ appVersion: 'unknown' });
  }
}

/**
 * Check for an update. Once per app run unless `force` (the manual button and
 * the daily timer), and never while an install is running.
 */
export async function checkForUpdates(force = false): Promise<UpdateInfo | null> {
  const s = useUpdater.getState();
  if (s.phase === 'installing' || s.phase === 'checking') return s.info;
  if (!force && checkedThisRun) return s.info;
  checkedThisRun = true;
  useUpdater.setState({ phase: 'checking', error: null, reconnectOffered: false });
  try {
    const info = await Promise.race([
      invoke<UpdateInfo | null>('check_for_updates'),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('timeout')), CHECK_TIMEOUT_MS),
      ),
    ]);
    useUpdater.setState({ phase: info ? 'available' : 'up-to-date', info: info ?? null });
    return info ?? null;
  } catch {
    // Offline or the endpoint is down. Neutral: it says nothing about whether
    // this is the latest version.
    useUpdater.setState({ phase: 'error', error: 'Update check unavailable right now.' });
    return null;
  }
}

export async function installUpdate(): Promise<void> {
  if (useUpdater.getState().phase === 'installing') return;
  useUpdater.setState({ phase: 'installing', progress: 0, error: null, reconnectOffered: false });
  const unlisten = listen<{ downloaded: number; contentLength?: number | null }>(
    'updater-download-progress',
    (event) => {
      const { downloaded, contentLength } = event.payload;
      if (contentLength && contentLength > 0) {
        useUpdater.setState({ progress: Math.min(100, Math.round((downloaded / contentLength) * 100)) });
      }
    },
  );
  try {
    const installed = await invoke<boolean>('install_update');
    useUpdater.setState(
      installed ? { phase: 'ready', progress: 100 } : { phase: 'up-to-date', progress: 0 },
    );
  } catch (e) {
    useUpdater.setState({ phase: 'error', ...failureCopy(e) });
  } finally {
    unlisten.then((off) => off()).catch(() => {});
  }
}
