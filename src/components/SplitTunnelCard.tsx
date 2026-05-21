import { useCallback, useState, type KeyboardEvent } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Lock, Plus, Scissors, X } from 'lucide-react';
import { useAppStore, type AppSettings } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';
import { settingsToRust } from '@/utils/helpers';
import { brand, hairline, surface, white } from '@/lib/birdo-theme';

interface SplitTunnelCardProps {
  busy: boolean;
}

const planLevel = (plan: string | null | undefined): number => {
  switch (plan?.toUpperCase()) {
    case 'SOVEREIGN':
      return 2;
    case 'OPERATIVE':
      return 1;
    default:
      return 0;
  }
};

export function SplitTunnelCard({ busy }: SplitTunnelCardProps) {
  const [appInput, setAppInput] = useState('');
  const { settings, updateSettings, account } = useAppStore(
    useShallow((s) => ({
      settings: s.settings,
      updateSettings: s.updateSettings,
      account: s.account,
    })),
  );

  const isOperative = planLevel(account?.plan) >= 1;
  const enabled = settings.splitTunnelingEnabled && isOperative;
  const apps = settings.splitTunnelApps;

  const persist = useCallback(
    async (patch: Partial<AppSettings>) => {
      const next = { ...settings, ...patch };
      updateSettings(patch);
      try {
        await invoke('save_settings', { settings: settingsToRust(next) });
      } catch {
        /* Rust backend logs the failure. */
      }
    },
    [settings, updateSettings],
  );

  const toggle = useCallback(() => {
    if (busy || !isOperative) return;
    persist({ splitTunnelingEnabled: !settings.splitTunnelingEnabled });
  }, [busy, isOperative, persist, settings.splitTunnelingEnabled]);

  const addApp = useCallback(() => {
    if (busy || !enabled) return;
    const appName = appInput.trim();
    if (!appName || apps.includes(appName)) return;

    const splitTunnelApps = [...apps, appName];
    persist({ splitTunnelApps });
    setAppInput('');
  }, [appInput, apps, busy, enabled, persist]);

  const removeApp = useCallback(
    (appName: string) => {
      if (busy || !enabled) return;
      persist({ splitTunnelApps: apps.filter((app) => app !== appName) });
    },
    [apps, busy, enabled, persist],
  );

  const handleInputKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    addApp();
  };

  return (
    <div
      className="w-full rounded-2xl px-3.5 py-3 text-left transition"
      style={{
        backgroundColor: surface.s2,
        border: `1px solid ${enabled ? brand.purple : hairline.soft}`,
      }}
    >
      <div className="flex items-center gap-3">
        <div
          className="flex h-10 w-10 items-center justify-center rounded-full"
          style={{
            backgroundColor: enabled ? 'rgba(168,85,247,0.15)' : 'rgba(255,255,255,0.05)',
          }}
        >
          {isOperative ? (
            <Scissors size={18} color={enabled ? brand.purple : white.w60} />
          ) : (
            <Lock size={16} color={white.w40} />
          )}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <p className="text-sm font-medium" style={{ color: white.w100 }}>
              Split Tunneling
            </p>
            {!isOperative && (
              <span
                className="rounded-full px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide"
                style={{ backgroundColor: 'rgba(168,85,247,0.18)', color: brand.purple }}
              >
                Operative
              </span>
            )}
          </div>
          <p className="truncate text-xs" style={{ color: white.w60 }}>
            {isOperative ? 'Choose which apps bypass VPN' : 'Requires Operative plan or higher'}
          </p>
        </div>

        <button
          type="button"
          role="switch"
          aria-checked={enabled}
          aria-label="Split Tunneling"
          onClick={toggle}
          disabled={busy || !isOperative}
          className="relative h-6 w-11 shrink-0 rounded-full transition disabled:opacity-40"
          style={{ backgroundColor: enabled ? brand.purple : 'rgba(255,255,255,0.18)' }}
        >
          <div
            className="absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all"
            style={{ left: enabled ? '22px' : '2px' }}
          />
        </button>
      </div>

      {enabled && (
        <div className="mt-3 space-y-2">
          <div className="flex gap-2">
            <input
              type="text"
              value={appInput}
              onChange={(event) => setAppInput(event.target.value)}
              onKeyDown={handleInputKeyDown}
              placeholder="e.g. chrome.exe"
              disabled={busy}
              className="min-w-0 flex-1 rounded-xl px-3 py-2 text-sm outline-none disabled:opacity-50"
              style={{
                backgroundColor: white.w05,
                border: `1px solid ${hairline.soft}`,
                color: white.w100,
              }}
            />
            <button
              type="button"
              onClick={addApp}
              disabled={busy}
              aria-label="Add split tunnel app"
              className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl transition disabled:opacity-40"
              style={{ backgroundColor: brand.purple, color: white.w100 }}
            >
              <Plus size={16} />
            </button>
          </div>

          {apps.length > 0 ? (
            <div className="flex flex-wrap gap-1.5">
              {apps.map((appName) => (
                <span
                  key={appName}
                  className="inline-flex max-w-full items-center gap-1 rounded-full px-2 py-1 text-xs"
                  style={{ backgroundColor: white.w05, color: white.w80, border: `1px solid ${hairline.soft}` }}
                >
                  <span className="max-w-[180px] truncate">{appName}</span>
                  <button
                    type="button"
                    onClick={() => removeApp(appName)}
                    disabled={busy}
                    aria-label={`Remove ${appName}`}
                    className="rounded-full p-0.5 transition hover:bg-white/10 disabled:opacity-40"
                  >
                    <X size={12} />
                  </button>
                </span>
              ))}
            </div>
          ) : (
            <p className="text-[11px]" style={{ color: white.w40 }}>
              Apps added here bypass VPN on the next connection.
            </p>
          )}
        </div>
      )}
    </div>
  );
}