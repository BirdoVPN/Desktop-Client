/**
 * SplitTunnel — pushed sub-screen mirroring mobile's `SplitTunnelScreen.kt`.
 *
 * Layout (mobile parity, adapted for desktop):
 *  - BirdoTopBar (title "Split Tunneling", back → popRoute)
 *  - Master enable toggle (gated to Operative+, like SplitTunnelCard)
 *  - Purple info banner (Info icon + "… N apps excluded.")
 *  - "Add by path/name" BirdoTextField + Add button — desktop CANNOT enumerate
 *    installed Windows apps, so apps are added manually instead of picked from a
 *    system list.
 *  - Search BirdoTextField to filter the added entries.
 *  - Each excluded app renders as a mobile-style list row: icon + label + a
 *    BYPASS pill + a remove action (the desktop analogue of mobile's AppItem).
 *
 * Persists split_tunnel_apps + split_tunneling_enabled by sending the FULL
 * settings object through `settingsToRust` to `invoke('save_settings', …)`,
 * exactly like `SplitTunnelCard.tsx`.
 */
import { useCallback, useMemo, useState, type KeyboardEvent } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useShallow } from 'zustand/react/shallow';
import { Info, Lock, Plus, Scissors, Search, X } from 'lucide-react';
import { useAppStore, type AppSettings } from '@/store/app-store';
import {
  BirdoTopBar,
  BirdoButton,
  BirdoTextField,
  BirdoSwitch,
  BirdoEmptyState,
  AppIconMark,
} from '@/components/birdo';
import { settingsToRust } from '@/utils/helpers';
import { brand, white, hairline } from '@/lib/birdo-theme';

// Operative (1) or Sovereign (2) unlock split tunneling — matches SplitTunnelCard.
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

export function SplitTunnel() {
  const { settings, updateSettings, account, popRoute } = useAppStore(
    useShallow((s) => ({
      settings: s.settings,
      updateSettings: s.updateSettings,
      account: s.account,
      popRoute: s.popRoute,
    })),
  );

  const [appInput, setAppInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  const isOperative = planLevel(account?.plan) >= 1;
  const enabled = settings.splitTunnelingEnabled && isOperative;
  const apps = settings.splitTunnelApps;
  const excludedCount = apps.length;

  // ── Persist: always send the FULL settings object (mirrors SplitTunnelCard) ──
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

  const toggleEnabled = useCallback(() => {
    if (!isOperative) return;
    persist({ splitTunnelingEnabled: !settings.splitTunnelingEnabled });
  }, [isOperative, persist, settings.splitTunnelingEnabled]);

  const addApp = useCallback(() => {
    if (!enabled) return;
    const appName = appInput.trim();
    if (!appName || apps.includes(appName)) return;
    persist({ splitTunnelApps: [...apps, appName] });
    setAppInput('');
  }, [appInput, apps, enabled, persist]);

  const removeApp = useCallback(
    (appName: string) => {
      if (!enabled) return;
      persist({ splitTunnelApps: apps.filter((app) => app !== appName) });
    },
    [apps, enabled, persist],
  );

  const handleInputKeyDown = (event: KeyboardEvent<HTMLInputElement>) => {
    if (event.key !== 'Enter') return;
    event.preventDefault();
    addApp();
  };

  // ── Filter the added entries (mobile filters the installed-app list) ──
  const filteredApps = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return apps;
    return apps.filter((app) => app.toLowerCase().includes(q));
  }, [apps, searchQuery]);

  return (
    <div className="flex h-full flex-col" style={{ backgroundColor: 'var(--birdo-s0)' }}>
      {/* ── Header ── */}
      <BirdoTopBar title="Split Tunneling" onBack={popRoute} />

      <div className="flex-1 overflow-y-auto px-4 py-3">
        {/* ── Master enable toggle (gated to Operative+) ── */}
        <div
          className="flex items-center gap-3 rounded-birdo-md px-3.5 py-3"
          style={{
            backgroundColor: white.w05,
            border: `1px solid ${enabled ? brand.purple : hairline.soft}`,
          }}
        >
          <div
            className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full"
            style={{ backgroundColor: enabled ? brand.purpleBg : white.w05 }}
          >
            {isOperative ? (
              <Scissors size={18} color={enabled ? brand.purple : white.w60} aria-hidden />
            ) : (
              <Lock size={16} color={white.w40} aria-hidden />
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
                  style={{ backgroundColor: brand.purpleBg, color: brand.purple }}
                >
                  Operative
                </span>
              )}
            </div>
            <p className="truncate text-xs" style={{ color: white.w60 }}>
              {isOperative ? 'Choose which apps bypass VPN' : 'Requires Operative plan or higher'}
            </p>
          </div>
          <BirdoSwitch
            checked={enabled}
            onChange={toggleEnabled}
            disabled={!isOperative}
            ariaLabel="Split Tunneling"
          />
        </div>

        {/* ── Purple info banner ── */}
        <div
          className="mt-3 flex items-start gap-2.5 rounded-birdo-md px-3 py-3"
          style={{ backgroundColor: brand.purpleBg }}
        >
          <Info size={18} color={brand.purple} aria-hidden className="mt-px shrink-0" />
          <p className="text-xs leading-relaxed" style={{ color: 'rgba(168,85,247,0.85)' }}>
            Selected apps will bypass VPN and use your regular internet connection. {excludedCount}{' '}
            {excludedCount === 1 ? 'app' : 'apps'} excluded.
          </p>
        </div>

        {enabled && (
          <>
            {/* ── Add by path/name (desktop can't enumerate installed apps) ── */}
            <div className="mt-3">
              <label className="mb-1.5 block pl-1 text-xs font-medium" style={{ color: white.w60 }}>
                Add by path or name
              </label>
              <div className="flex gap-2">
                <div
                  className="flex min-w-0 flex-1 items-center gap-2 px-3"
                  style={{
                    minHeight: 48,
                    borderRadius: 12,
                    backgroundColor: white.w04,
                    border: `1px solid ${hairline.soft}`,
                  }}
                >
                  <Plus size={18} color={white.w40} aria-hidden className="shrink-0" />
                  <input
                    type="text"
                    value={appInput}
                    onChange={(e) => setAppInput(e.target.value)}
                    onKeyDown={handleInputKeyDown}
                    placeholder="e.g. chrome.exe"
                    aria-label="App path or name"
                    className="min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-w20"
                    style={{ color: white.w100 }}
                  />
                </div>
                <BirdoButton
                  text="Add"
                  onClick={addApp}
                  variant="brand"
                  size="medium"
                  ariaLabel="Add split tunnel app"
                />
              </div>
            </div>

            {/* ── Search the added entries ── */}
            {apps.length > 0 && (
              <BirdoTextField
                value={searchQuery}
                onChange={setSearchQuery}
                placeholder="Search apps…"
                ariaLabel="Search apps"
                leadingIcon={Search}
                className="mt-2"
                trailing={
                  searchQuery ? (
                    <button
                      type="button"
                      onClick={() => setSearchQuery('')}
                      aria-label="Clear search"
                      className="flex h-6 w-6 items-center justify-center rounded-full transition-colors hover:bg-white/5"
                    >
                      <X size={16} color={white.w40} aria-hidden />
                    </button>
                  ) : undefined
                }
              />
            )}

            {/* ── Excluded-app rows (mobile AppItem analogue) ── */}
            <div className="mt-3 space-y-1.5">
              {filteredApps.map((appName) => (
                <div
                  key={appName}
                  className="flex items-center gap-3 rounded-birdo-md px-3.5 py-2.5"
                  style={{
                    backgroundColor: 'rgba(168,85,247,0.08)',
                    border: `1px solid ${hairline.soft}`,
                  }}
                >
                  <AppIconMark size={36} />
                  <div className="min-w-0 flex-1">
                    <div
                      className="truncate text-[15px] font-medium"
                      style={{ color: white.w80 }}
                    >
                      {appName}
                    </div>
                  </div>
                  <span
                    className="shrink-0 rounded-md px-1.5 py-0.5 text-[9px] font-bold tracking-wide"
                    style={{ backgroundColor: 'rgba(168,85,247,0.20)', color: brand.purple }}
                  >
                    BYPASS
                  </span>
                  <button
                    type="button"
                    onClick={() => removeApp(appName)}
                    aria-label={`Remove ${appName}`}
                    className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full transition-colors hover:bg-white/10"
                  >
                    <X size={16} color={white.w40} aria-hidden />
                  </button>
                </div>
              ))}

              {/* ── Empty state ── */}
              {filteredApps.length === 0 && (
                <BirdoEmptyState
                  icon={Scissors}
                  title={searchQuery.trim() ? 'No apps match' : 'No apps excluded'}
                  description={
                    searchQuery.trim()
                      ? `Nothing matches "${searchQuery.trim()}".`
                      : 'Add an app above to route it around the VPN on the next connection.'
                  }
                  className="pt-6"
                />
              )}
            </div>
          </>
        )}
      </div>
    </div>
  );
}
