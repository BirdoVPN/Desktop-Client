import { useCallback } from 'react';
import { relaunch, exit } from '@tauri-apps/plugin-process';
import { open as openExternal } from '@tauri-apps/plugin-shell';
import { TriangleAlert, Download, LoaderCircle, RefreshCw, ShieldOff } from 'lucide-react';
import { useShallow } from 'zustand/react/shallow';
import { UPDATE_REQUIRED_COPY } from '@/lib/errors';
import { statusPill } from '@/lib/vpn-display';
import { status, white } from '@/lib/birdo-theme';
import { disconnectVpn } from '@/session/vpn-actions';
import { installExitsApp, installUpdate, UPDATE_WAITING_COPY, useUpdater } from '@/session/updater';
import { useAppStore } from '@/store/app-store';
import { selectDisplayState, selectTunnelActive } from '@/store/selectors';

/** Mirrors `api::upgrade_gate::RequiredUpdate` (serde camelCase). */
export interface RequiredUpdate {
  requiredVersion?: string | null;
  downloadUrl?: string | null;
  message?: string | null;
}

/**
 * Hard block shown when the backend refuses this build with a 426 Upgrade
 * Required (`api::upgrade_gate`).
 *
 * A FIRST-CLASS state, not an error toast: nothing behind it can work. Every
 * action is user-initiated — no timer, no retry loop, no automatic re-check:
 * a fleet retrying forever against an upgrade wall is a self-inflicted DoS on
 * the control plane the user needs to recover.
 *
 * A tunnel that was up when the 426 arrived is STILL up (W2-025): the wall says
 * so and offers Disconnect, instead of claiming the app "can no longer
 * connect" over a live session the user had no in-app way to end. The session
 * controller keeps running underneath, so the tray works too.
 *
 * "Update now" runs the CERT-PINNED updater (commands/updater.rs); a pin
 * failure surfaces as an error here rather than installing something
 * unverified. The install state lives in `session/updater.ts`.
 */
export function UpdateRequired({ info }: { info: RequiredUpdate }) {
  const { phase, progress, error } = useUpdater();
  const { tunnelActive, stateText, disconnecting } = useAppStore(
    useShallow((s) => {
      const d = selectDisplayState(s);
      return {
        tunnelActive: selectTunnelActive(s),
        stateText: s.killSwitchBlocking && d !== 'connected' ? 'Kill Switch — all traffic blocked' : statusPill(d).text,
        disconnecting: d === 'disconnecting',
      };
    }),
  );
  const exitsApp = installExitsApp();

  const version = info.requiredVersion?.trim() || null;
  const downloadUrl = info.downloadUrl?.trim() || null;
  const installing = phase === 'installing';
  const waiting = phase === 'waiting';

  const openDownloadPage = useCallback(() => {
    if (!downloadUrl) return;
    openExternal(downloadUrl).catch(() => {
      useAppStore.getState().showNotice({
        text: "Couldn't open your browser. Visit birdo.app to download the latest version.",
        tone: 'danger',
      });
    });
  }, [downloadUrl]);

  return (
    <div className="flex h-full flex-col items-center justify-center gap-6 overflow-y-auto px-8 py-6 text-center">
      <div className="flex h-12 w-12 items-center justify-center rounded-lg" style={{ backgroundColor: status.yellowBg }}>
        <TriangleAlert size={24} color={status.yellowLight} aria-hidden />
      </div>

      <div className="flex flex-col gap-2">
        <h1 className="text-lg font-semibold text-white">Update required</h1>
        <p className="max-w-xs text-sm" style={{ color: white.w60 }}>
          {info.message?.trim()
            ? info.message
            : version
              ? `BirdoVPN ${version} or later is required. ${UPDATE_REQUIRED_COPY}`
              : UPDATE_REQUIRED_COPY}
        </p>
        {version && (
          <p className="text-xs" style={{ color: white.w60 }}>
            Required version: v{version}
          </p>
        )}
      </div>

      {tunnelActive && (
        <div
          className="flex w-full max-w-xs flex-col items-center gap-2 rounded-birdo-md px-4 py-3"
          style={{ backgroundColor: white.w05 }}
        >
          <p className="text-sm font-medium text-white">You&apos;re still connected</p>
          <p className="text-xs" style={{ color: white.w60 }}>
            {stateText}
            {exitsApp ? '. Installing the update ends this session.' : '.'}
          </p>
          <button
            type="button"
            onClick={() => void disconnectVpn()}
            disabled={disconnecting}
            className="mt-1 flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-semibold disabled:opacity-60"
            style={{ backgroundColor: status.redBg, color: status.red, border: `1px solid ${status.redBorder}` }}
          >
            <ShieldOff size={16} aria-hidden />
            {disconnecting ? 'Disconnecting…' : 'Disconnect'}
          </button>
        </div>
      )}

      {installing && (
        <div className="w-full max-w-xs">
          <div
            className="h-1.5 overflow-hidden rounded-full bg-white/10"
            role="progressbar"
            aria-label="Update download"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={progress}
          >
            <div className="h-full bg-emerald-500 transition-all duration-300" style={{ width: `${progress}%` }} />
          </div>
          <p className="mt-2 text-xs" style={{ color: white.w60 }}>
            {exitsApp ? `Installing… ${progress}% — BirdoVPN will restart` : `Downloading… ${progress}%`}
          </p>
        </div>
      )}

      {waiting && (
        <p role="status" className="max-w-xs text-xs" style={{ color: status.yellowLight }}>
          {UPDATE_WAITING_COPY}
        </p>
      )}
      {phase === 'error' && error && (
        <p role="alert" className="max-w-xs text-xs" style={{ color: status.yellowLight }}>
          {error}
        </p>
      )}
      {phase === 'up-to-date' && (
        <p role="alert" className="max-w-xs text-xs" style={{ color: status.yellowLight }}>
          No update is being offered for this platform yet. Please download the latest version manually.
        </p>
      )}

      <div className="flex flex-col items-center gap-3">
        {phase === 'ready' && !exitsApp ? (
          <button
            type="button"
            onClick={() => relaunch().catch(() => {})}
            className="flex items-center gap-2 rounded-lg bg-emerald-600 px-6 py-2.5 text-sm font-semibold text-white transition hover:bg-emerald-700"
          >
            <RefreshCw size={16} aria-hidden />
            Restart to finish
          </button>
        ) : (
          <button
            type="button"
            onClick={() => void installUpdate()}
            disabled={installing}
            className="flex items-center gap-2 rounded-lg bg-white px-6 py-2.5 text-sm font-semibold text-black transition hover:bg-white/90 disabled:opacity-50"
          >
            {installing ? (
              <LoaderCircle size={16} className="animate-spin motion-reduce:animate-none" aria-hidden />
            ) : (
              <Download size={16} aria-hidden />
            )}
            {phase === 'error' ? 'Try again' : exitsApp ? 'Install and restart' : 'Update now'}
          </button>
        )}

        {downloadUrl && (
          <button
            type="button"
            onClick={openDownloadPage}
            className="text-xs underline-offset-2 transition hover:text-white/80 hover:underline"
            style={{ color: white.w60 }}
          >
            Download manually
          </button>
        )}

        <button
          type="button"
          onClick={() => exit(0).catch(() => window.close())}
          className="text-xs transition hover:text-white/80"
          style={{ color: white.w60 }}
        >
          Quit
        </button>
      </div>
    </div>
  );
}
