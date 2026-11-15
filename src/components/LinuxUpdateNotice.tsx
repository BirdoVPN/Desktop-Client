import { useEffect, useState } from 'react';
import { Download, X } from 'lucide-react';
import {
  checkLinuxRelease,
  dismissLinuxVersion,
  dismissedLinuxVersion,
  openLinuxReleasePage,
} from '@/session/linux-release';
import { isLinuxPlatform } from '@/utils/helpers';

const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * "BirdoVPN x is available" on Linux (A-M50), where the in-app updater has no
 * feed. Checks shortly after start, then every 24 h; renders nothing on other
 * platforms, when the check fails, or for a version the user dismissed.
 */
export function LinuxUpdateNotice() {
  const [version, setVersion] = useState<string | null>(null);

  useEffect(() => {
    if (!isLinuxPlatform()) return;
    let cancelled = false;
    const run = async () => {
      const found = await checkLinuxRelease();
      if (cancelled || !found) return;
      setVersion(found !== dismissedLinuxVersion() ? found : null);
    };
    const initial = setTimeout(() => void run(), 20_000); // let startup settle first
    const daily = setInterval(() => void run(), DAY_MS);
    return () => {
      cancelled = true;
      clearTimeout(initial);
      clearInterval(daily);
    };
  }, []);

  if (!version) return null;
  return (
    <div role="status" aria-live="polite" className="shrink-0">
      <div className="flex items-center justify-center gap-3 bg-white/10 px-3 py-1.5 text-xs text-white">
        <span className="font-semibold">BirdoVPN {version} is available</span>
        <button
          type="button"
          onClick={openLinuxReleasePage}
          className="inline-flex items-center gap-1 rounded-md bg-white px-2 py-0.5 font-semibold text-black transition hover:bg-white/90"
        >
          <Download size={12} aria-hidden />
          Download
        </button>
        <button
          type="button"
          aria-label="Dismiss"
          onClick={() => {
            dismissLinuxVersion(version);
            setVersion(null);
          }}
          className="rounded-md p-0.5 text-white/70 transition hover:text-white"
        >
          <X size={14} aria-hidden />
        </button>
      </div>
    </div>
  );
}
