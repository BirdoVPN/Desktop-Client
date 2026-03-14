import { useState, useCallback } from 'react';
import { check } from '@tauri-apps/plugin-updater';
import { relaunch } from '@tauri-apps/plugin-process';
import { Download, Check, AlertCircle, Loader2, RefreshCw } from 'lucide-react';

type UpdateStatus = 
  | 'idle' 
  | 'checking' 
  | 'available' 
  | 'downloading' 
  | 'ready' 
  | 'up-to-date' 
  | 'error';

interface UpdateInfo {
  version: string;
  currentVersion: string;
  releaseNotes?: string;
}

export function UpdateChecker() {
  const [status, setStatus] = useState<UpdateStatus>('idle');
  const [updateInfo, setUpdateInfo] = useState<UpdateInfo | null>(null);
  const [downloadProgress, setDownloadProgress] = useState(0);
  const [error, setError] = useState<string | null>(null);

  const checkForUpdates = useCallback(async () => {
    setStatus('checking');
    setError(null);

    try {
      const update = await check();
      
      if (update) {
        setUpdateInfo({
          version: update.version,
          currentVersion: update.currentVersion,
          releaseNotes: update.body || undefined,
        });
        setStatus('available');
      } else {
        setStatus('up-to-date');
        // Reset to idle after 3 seconds
        setTimeout(() => setStatus('idle'), 3000);
      }
    } catch (err) {
      setError('Update server is not available right now. Try again later.');
      setStatus('error');
    }
  }, []);

  const downloadAndInstall = useCallback(async () => {
    if (status !== 'available') return;

    setStatus('downloading');
    setDownloadProgress(0);

    try {
      const update = await check();
      if (!update) {
        setStatus('up-to-date');
        return;
      }

      // Download the update with progress tracking
      let downloaded = 0;
      let contentLength = 0;

      await update.downloadAndInstall((event) => {
        switch (event.event) {
          case 'Started':
            contentLength = event.data.contentLength || 0;
            break;
          case 'Progress':
            downloaded += event.data.chunkLength;
            if (contentLength > 0) {
              setDownloadProgress(Math.round((downloaded / contentLength) * 100));
            }
            break;
          case 'Finished':
            setDownloadProgress(100);
            break;
        }
      });

      setStatus('ready');
    } catch (err) {
      setError('Download failed. Please try again.');
      setStatus('error');
    }
  }, [status]);

  const restartApp = useCallback(async () => {
    try {
      await relaunch();
    } catch (err) {
      setError('Failed to restart. Please close and reopen the app.');
      setStatus('error');
    }
  }, []);

  // Don't auto-check on mount — update server may not be available yet.
  // Users can manually check via the "Check" button.

  return (
    <div className="space-y-3">
      {/* Update status card */}
      <div className="glass rounded-lg p-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className={`flex h-10 w-10 items-center justify-center rounded-lg ${
              status === 'available' || status === 'ready' 
                ? 'bg-emerald-500/20' 
                : status === 'error'
                ? 'bg-red-500/20'
                : 'bg-white/10'
            }`}>
              {status === 'checking' || status === 'downloading' ? (
                <Loader2 size={20} className="animate-spin text-white" />
              ) : status === 'available' ? (
                <Download size={20} className="text-emerald-400" />
              ) : status === 'ready' ? (
                <Check size={20} className="text-emerald-400" />
              ) : status === 'error' ? (
                <AlertCircle size={20} className="text-red-400" />
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
                {status === 'error' && 'Update check failed'}
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
        {status === 'available' && updateInfo?.releaseNotes && (
          <div className="mt-3 rounded-lg bg-white/5 p-3">
            <p className="mb-1 text-xs font-medium text-white/60">What's new:</p>
            <p className="text-xs text-white/60 line-clamp-3">
              {updateInfo.releaseNotes}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
