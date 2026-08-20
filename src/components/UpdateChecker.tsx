import { useState, useCallback, useRef, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { relaunch } from '@tauri-apps/plugin-process';
import { Download, Check, Loader2, RefreshCw } from 'lucide-react';

type UpdateStatus = 
  | 'idle' 
  | 'checking' 
  | 'available' 
  | 'downloading' 
  | 'ready' 
  | 'up-to-date' 
  | 'error';

/** Mirrors `commands::updater::UpdateInfo` (serde camelCase). */
interface UpdateInfo {
  version: string;
  currentVersion: string;
  notes?: string | null;
}

/** Payload of the `updater-download-progress` event. */
interface DownloadProgress {
  downloaded: number;
  contentLength?: number | null;
}

export function UpdateChecker() {
  const [status, setStatus] = useState<UpdateStatus>('idle');
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
  const [downloadProgress, setDownloadProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const idleTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // The check/download run in Rust over the CERT-PINNED client
  // (commands/updater.rs). The frontend deliberately no longer talks to
  // @tauri-apps/plugin-updater directly: that JS path uses the plugin's own
  // un-pinned reqwest client, and `updater:default` has been removed from the
  // capability set so it is not reachable from here at all.
  //
  // Guard against a hung/unreachable update server leaving the UI stuck in
  // 'checking' forever. Reject after 10s so the catch handler can surface an
  // error state the user can retry from.
  const checkWithTimeout = useCallback(() => {
    return Promise.race([
      invoke<UpdateInfo | null>('check_for_updates'),
      new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error('Update check timed out.')), 10000)
      ),
    ]);
  }, []);

  useEffect(() => {
    return () => {
      if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
    };
  }, []);

  const checkForUpdates = useCallback(async () => {
    setStatus('checking');
    setError(null);

    try {
      const update = await checkWithTimeout();

      if (update) {
        setUpdateInfo(update);
        setStatus('available');
      } else {
        setStatus('up-to-date');
        if (idleTimerRef.current) clearTimeout(idleTimerRef.current);
        idleTimerRef.current = setTimeout(() => setStatus('idle'), 3000);
      }
    } catch (_err) {
      // Endpoint unreachable (offline, server hiccup). Keep the tone neutral
      // and avoid implying the user is (or isn't) on the latest version.
      setError('Update check unavailable right now.');
      setStatus('error');
    }
  }, [checkWithTimeout]);

  const downloadAndInstall = useCallback(async () => {
    if (status !== 'available') return;

    setStatus('downloading');
    setDownloadProgress(0);

    // Progress arrives as a Rust-side event while `install_update` runs.
    const unlisten = listen<DownloadProgress>('updater-download-progress', (event) => {
      const { downloaded, contentLength } = event.payload;
      if (contentLength && contentLength > 0) {
        setDownloadProgress(Math.min(100, Math.round((downloaded / contentLength) * 100)));
      }
    });

    try {
      const installed = await invoke<boolean>('install_update');
      if (!installed) {
        setStatus('up-to-date');
        return;
      }
      setDownloadProgress(100);
      setStatus('ready');
    } catch (_err) {
      // A pin failure surfaces here too: the pinned client refuses the
      // handshake rather than downloading over an unverified chain.
      setError('Download failed. Please try again.');
      setStatus('error');
    } finally {
      unlisten.then((fn) => fn()).catch(() => {});
    }
  }, [status]);

  const restartApp = useCallback(async () => {
    try {
      await relaunch();
    } catch (_err) {
      setError('Failed to restart. Please close and reopen the app.');
      setStatus('error');
    }
  }, []);

  // Auto-check when the panel opens: the per-platform update endpoint is live
  // (api.birdo.app/updates/…, verified with v1.4.11), so surfacing the state
  // immediately beats a manual-only "Check" button. App.tsx additionally runs
  // a daily background check with a native notification.
  useEffect(() => {
    checkForUpdates();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div className="space-y-3">
      {/* Update status card */}
      <div className="glass rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${
              status === 'available' || status === 'ready'
                ? 'bg-emerald-500/20'
                : 'bg-white/10'
            }`}>
              {status === 'checking' || status === 'downloading' ? (
                <Loader2 size={20} className="animate-spin text-white" />
              ) : status === 'available' ? (
                <Download size={20} className="text-emerald-400" />
              ) : status === 'ready' ? (
                <Check size={20} className="text-emerald-400" />
              ) : status === 'error' ? (
                <RefreshCw size={20} className="text-white/40" />
              ) : status === 'up-to-date' ? (
                <Check size={20} className="text-emerald-400" />
              ) : (
                <RefreshCw size={20} className="text-white" />
              )}
            </div>
            <div>
              <p className="font-medium text-white">
                {status === 'checking' && 'Checking for updates...'}
                {status === 'available' && `Update available: v${updateInfo?.version}`}
                {status === 'downloading' && `Downloading... ${downloadProgress}%`}
                {status === 'ready' && 'Update ready to install'}
                {status === 'up-to-date' && 'You\'re up to date!'}
                {status === 'error' && 'Software Updates'}
                {status === 'idle' && 'Software Updates'}
              </p>
              <p className="text-xs text-white/60">
                {status === 'available' && `Current: v${updateInfo?.currentVersion}`}
                {status === 'downloading' && 'Please wait...'}
                {status === 'ready' && 'Restart to apply update'}
                {status === 'error' && error}
                {(status === 'idle' || status === 'up-to-date') && 'Check for new versions'}
              </p>
            </div>
          </div>

          {/* Action button */}
          {status === 'idle' && (
            <button
              onClick={checkForUpdates}
              className="rounded-lg bg-white/10 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-white/20"
            >
              Check
            </button>
          )}
          {status === 'available' && (
            <button
              onClick={downloadAndInstall}
              className="rounded-lg bg-emerald-500 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-emerald-600"
            >
              Download
            </button>
          )}
          {status === 'ready' && (
            <button
              onClick={restartApp}
              className="rounded-lg bg-emerald-500 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-emerald-600"
            >
              Restart
            </button>
          )}
          {status === 'error' && (
            <button
              onClick={checkForUpdates}
              className="rounded-lg bg-white/10 px-3 py-1.5 text-sm font-medium text-white transition hover:bg-white/20"
            >
              Retry
            </button>
          )}
        </div>

        {/* Download progress bar */}
        {status === 'downloading' && (
          <div className="mt-3">
            <div className="h-1.5 overflow-hidden rounded-full bg-white/10">
              <div 
                className="h-full bg-emerald-500 transition-all duration-300"
                style={{ width: `${downloadProgress}%` }}
              />
            </div>
          </div>
        )}

        {/* Release notes */}
            {status === 'available' && updateInfo?.notes && (
          <div className="mt-3 rounded-lg bg-white/5 p-3">
            <p className="mb-1 text-xs font-medium text-white/60">What's new:</p>
            <p className="text-xs text-white/60 line-clamp-3">
              {updateInfo.notes}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
