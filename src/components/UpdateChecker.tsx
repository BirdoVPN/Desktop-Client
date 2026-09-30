/**
 * Settings › About › Software Updates. A view over `session/updater.ts`, which
 * owns the state (so an install survives leaving Settings, W2-024).
 *
 * On Windows the installer exits the app, so the button says "Install and
 * restart" and there is no separate Restart step; while a tunnel is up it asks
 * first, because installing ends the VPN session.
 */
import { useEffect, useState } from 'react';
import { relaunch } from '@tauri-apps/plugin-process';
import { Download, Check, Loader2, RefreshCw } from 'lucide-react';
import { BirdoButton, BirdoCard, BirdoDialog } from '@/components/birdo';
import { brand, status, surface, white } from '@/lib/birdo-theme';
import { useAppStore } from '@/store/app-store';
import { selectTunnelActive } from '@/store/selectors';
import { checkForUpdates, installExitsApp, installUpdate, useUpdater } from '@/session/updater';

export function UpdateChecker() {
  const { phase, info, progress, error } = useUpdater();
  const [confirmInstall, setConfirmInstall] = useState(false);
  const [restartError, setRestartError] = useState<string | null>(null);
  const exitsApp = installExitsApp();

  // Once per app run (the daily check in App covers the rest); a revisit of
  // this tab no longer re-checks or re-offers a download that is running.
  useEffect(() => {
    void checkForUpdates();
  }, []);

  const startInstall = () => {
    if (selectTunnelActive(useAppStore.getState())) {
      setConfirmInstall(true);
      return;
    }
    void installUpdate();
  };

  const title =
    phase === 'checking' ? 'Checking for updates…'
    : phase === 'available' ? `Update available: v${info?.version ?? ''}`
    : phase === 'installing' ? (exitsApp ? `Installing… ${progress}%` : `Downloading… ${progress}%`)
    : phase === 'ready' ? 'Update ready to install'
    : phase === 'up-to-date' ? "You're up to date"
    : 'Software Updates';
  const subtitle =
    phase === 'available' ? `Current: v${info?.currentVersion ?? ''}`
    : phase === 'installing' ? (exitsApp ? 'BirdoVPN will close and restart to finish.' : 'Please wait…')
    : phase === 'ready' ? 'Restart to apply the update'
    : phase === 'error' ? error ?? ''
    : restartError ?? 'Check for new versions';

  return (
    <BirdoCard>
      <div className="flex items-center gap-3.5">
        <div
          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full"
          style={{ backgroundColor: phase === 'available' || phase === 'ready' ? brand.accentBg : white.w05 }}
        >
          {phase === 'checking' || phase === 'installing' ? (
            <Loader2 size={18} className="animate-spin motion-reduce:animate-none" color={white.w80} aria-hidden />
          ) : phase === 'available' ? (
            <Download size={18} color={brand.accentLight} aria-hidden />
          ) : phase === 'ready' || phase === 'up-to-date' ? (
            <Check size={18} color={brand.accentLight} aria-hidden />
          ) : (
            <RefreshCw size={18} color={white.w60} aria-hidden />
          )}
        </div>
        <div className="min-w-0 flex-1" aria-live="polite">
          <div className="text-[15px] font-medium text-white">{title}</div>
          <div className="mt-0.5 text-xs" style={{ color: phase === 'error' ? status.red : white.w60 }}>
            {subtitle}
          </div>
        </div>
        {(phase === 'idle' || phase === 'up-to-date' || phase === 'error') && (
          <UpdateAction label={phase === 'error' ? 'Retry' : 'Check'} onClick={() => void checkForUpdates(true)} />
        )}
        {phase === 'available' && (
          <UpdateAction label={exitsApp ? 'Install and restart' : 'Download'} onClick={startInstall} />
        )}
        {phase === 'ready' && !exitsApp && (
          <UpdateAction
            label="Restart"
            onClick={() => {
              relaunch().catch(() => setRestartError('Failed to restart. Please close and reopen BirdoVPN.'));
            }}
          />
        )}
      </div>

      {phase === 'installing' && (
        <div
          className="mt-3 h-1.5 overflow-hidden rounded-full"
          style={{ backgroundColor: surface.s2 }}
          role="progressbar"
          aria-label="Update download"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={progress}
        >
          <div className="h-full transition-all duration-300" style={{ width: `${progress}%`, backgroundColor: brand.accent }} />
        </div>
      )}

      {phase === 'available' && info?.notes && (
        <div className="mt-3 rounded-birdo-sm p-3" style={{ backgroundColor: white.w05 }}>
          <p className="mb-1 text-xs font-medium" style={{ color: white.w60 }}>
            What's new:
          </p>
          <p className="line-clamp-3 text-xs" style={{ color: white.w60 }}>
            {info.notes}
          </p>
        </div>
      )}

      <BirdoDialog
        open={confirmInstall}
        onClose={() => setConfirmInstall(false)}
        title="Install update now?"
        icon={Download}
        iconColor={brand.accentLight}
      >
        <p className="text-[13px]" style={{ color: white.w60 }}>
          Installing will disconnect the VPN and restart BirdoVPN.
        </p>
        <div className="flex gap-2.5">
          <BirdoButton text="Cancel" variant="secondary" fullWidth onClick={() => setConfirmInstall(false)} />
          <BirdoButton
            text={exitsApp ? 'Install and restart' : 'Install'}
            variant="primary"
            fullWidth
            onClick={() => {
              setConfirmInstall(false);
              void installUpdate();
            }}
          />
        </div>
      </BirdoDialog>
    </BirdoCard>
  );
}

function UpdateAction({ label, onClick }: { label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="shrink-0 rounded-birdo-sm px-3 py-2 text-[13px] font-semibold transition-all hover:brightness-125"
      style={{ backgroundColor: brand.accentBg, color: brand.accentSoft }}
    >
      {label}
    </button>
  );
}
