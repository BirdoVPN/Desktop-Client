import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { relaunch, exit } from '@tauri-apps/plugin-process';
import { open as openExternal } from '@tauri-apps/plugin-shell';
import { AlertTriangle, Download, Loader2, RefreshCw } from 'lucide-react';

/** Mirrors `api::upgrade_gate::RequiredUpdate` (serde camelCase). */
export interface RequiredUpdate {
  requiredVersion?: string | null;
  downloadUrl?: string | null;
  message?: string | null;
}

interface DownloadProgress {
  downloaded: number;
  contentLength?: number | null;
}

type Phase = 'idle' | 'installing' | 'ready' | 'error';

/**
 * Hard block shown when the backend refuses this build with a 426 Upgrade
 * Required (`api::upgrade_gate`).
 *
 * This is a FIRST-CLASS state, not an error toast: the version floor is a wall,
 * so nothing behind it is usable and there is no point letting the user keep
 * poking Connect. Everything here is user-initiated — there is deliberately no
 * timer, no retry loop and no automatic re-check. A fleet of clients retrying
 * forever against an upgrade wall is a self-inflicted DoS on the very control
 * plane the user needs in order to recover.
 *
 * "Update now" runs the CERT-PINNED updater (commands/updater.rs); a pin
 * failure surfaces as an error here rather than installing something
 * unverified.
 */
export function UpdateRequired({ info }: { info: RequiredUpdate }) {
  const [phase, setPhase] = useState<Phase>('idle');
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const version = info.requiredVersion?.trim() || null;
  const downloadUrl = info.downloadUrl?.trim() || null;

  useEffect(() => {
    if (phase !== 'installing') return;
    const unlisten = listen<DownloadProgress>('updater-download-progress', (event) => {
      const { downloaded, contentLength } = event.payload;
      if (contentLength && contentLength > 0) {
        setProgress(Math.min(100, Math.round((downloaded / contentLength) * 100)));
      }
    });
    return () => {
      unlisten.then((fn) => fn()).catch(() => {});
    };
  }, [phase]);

  const runUpdate = useCallback(async () => {
    setPhase('installing');
    setProgress(0);
    setError(null);
    try {
      const installed = await invoke<boolean>('install_update');
      if (!installed) {
        // The updater endpoint has nothing newer than what is already running,
        // yet the backend says this build is too old. Retrying would not change
        // that, so say so plainly and offer the manual download instead.
        setError(
          'No update is being offered for this platform yet. Please download the latest version manually.'
        );
        setPhase('error');
        return;
      }
      setProgress(100);
      setPhase('ready');
    } catch {
      setError('The update could not be downloaded or verified. Please try again.');
      setPhase('error');
    }
  }, []);

  const restart = useCallback(async () => {
    try {
      await relaunch();
    } catch {
      setError('Failed to restart. Please close and reopen BirdoVPN.');
      setPhase('error');
    }
  }, []);

  const openDownloadPage = useCallback(() => {
    if (!downloadUrl) return;
    openExternal(downloadUrl).catch(() => {
      setError('Could not open your browser. Visit birdo.app to download the latest version.');
    });
  }, [downloadUrl]);

  return (
    <div className="flex h-full flex-col items-center justify-center gap-6 px-8 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-amber-500/15">
        <AlertTriangle size={24} className="text-amber-400" />
      </div>

      <div className="flex flex-col gap-2">
        <h1 className="text-lg font-semibold text-white">Update required</h1>
        <p className="max-w-xs text-sm text-white/60">
          {info.message?.trim()
            ? info.message
            : version
              ? `BirdoVPN ${version} or later is required to connect. This build is no longer supported.`
              : 'This version of BirdoVPN is no longer supported and can no longer connect.'}
        </p>
        {version && (
          <p className="text-xs text-white/40">Required version: v{version}</p>
        )}
      </div>

      {phase === 'installing' && (
        <div className="w-full max-w-xs">
          <div className="h-1.5 overflow-hidden rounded-full bg-white/10">
            <div
              className="h-full bg-emerald-500 transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>
          <p className="mt-2 text-xs text-white/50">Downloading… {progress}%</p>
        </div>
      )}

      {error && <p className="max-w-xs text-xs text-amber-300/80">{error}</p>}

      <div className="flex flex-col items-center gap-3">
        {phase === 'ready' ? (
          <button
            type="button"
            onClick={restart}
            className="flex items-center gap-2 rounded-lg bg-emerald-500 px-6 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-600"
          >
            <RefreshCw size={16} />
            Restart to finish
          </button>
        ) : (
          <button
            type="button"
            onClick={runUpdate}
            disabled={phase === 'installing'}
            className="flex items-center gap-2 rounded-lg bg-white px-6 py-2.5 text-sm font-semibold text-black transition hover:bg-white/90 disabled:opacity-50"
          >
            {phase === 'installing' ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <Download size={16} />
            )}
            {phase === 'error' ? 'Try again' : 'Update now'}
          </button>
        )}

        {downloadUrl && (
          <button
            type="button"
            onClick={openDownloadPage}
            className="text-xs text-white/50 underline-offset-2 transition hover:text-white/80 hover:underline"
          >
            Download manually
          </button>
        )}

        <button
          type="button"
          onClick={() => exit(0).catch(() => window.close())}
          className="text-xs text-white/40 transition hover:text-white/70"
        >
          Quit
        </button>
      </div>
    </div>
  );
}
