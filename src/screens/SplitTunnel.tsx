/**
 * SplitTunnel — pushed sub-screen mirroring mobile's `SplitTunnelScreen.kt`.
 *
 * Layout (mobile parity, adapted for desktop):
 *  - BirdoTopBar (title "Split Tunneling", back → popRoute)
 *  - Master enable toggle (gated to Operative+, like SplitTunnelCard)
 *  - Purple info banner (Info icon + "… N apps excluded.")
 *  - "Add by path/name" BirdoTextField + Add button, plus an "Installed apps"
 *    picker (enumerated from the Windows registry by `list_installed_apps`) and
 *    a native "Browse…" .exe file dialog.
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
import { open } from '@tauri-apps/plugin-dialog';
import { useShallow } from 'zustand/react/shallow';
import { AppWindow, FolderOpen, Info, Lock, Plus, Scissors, Search, X } from 'lucide-react';
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
import { brand, white, hairline, status } from '@/lib/birdo-theme';

/** An installed app returned by the Rust `list_installed_apps` command. */
interface InstalledApp {
  name: string;
  path: string;
}

/** Display the basename of a stored entry (which may be a full path). */
const baseName = (s: string): string => s.split(/[\\/]/).pop() || s;

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

  // Installed-app picker (enumerated from the Windows registry by Rust).
  const [pickerOpen, setPickerOpen] = useState(false);
  const [installed, setInstalled] = useState<InstalledApp[] | null>(null);
  const [pickerError, setPickerError] = useState(false);
  const [pickerSearch, setPickerSearch] = useState('');
  const [pickerLoading, setPickerLoading] = useState(false);

  // Surfaced when save_settings rejects so the user knows the change didn't stick.
  const [persistError, setPersistError] = useState(false);

  const isOperative = planLevel(account?.plan) >= 1;
  const enabled = settings.splitTunnelingEnabled && isOperative;
  const apps = settings.splitTunnelApps;
  const excludedCount = apps.length;

  // ── Persist: always send the FULL settings object (mirrors SplitTunnelCard) ──
  const persist = useCallback(
    async (patch: Partial<AppSettings>) => {
      const next = { ...settings, ...patch };
      // Snapshot the keys we're optimistically changing so we can roll back if
      // the save rejects, keeping the UI in sync with what's actually stored.
      const rollback = Object.fromEntries(
        (Object.keys(patch) as (keyof AppSettings)[]).map((k) => [k, settings[k]]),
      ) as Partial<AppSettings>;
      setPersistError(false);
      updateSettings(patch);
      try {
        await invoke('save_settings', { settings: settingsToRust(next) });
      } catch {
        // Revert the optimistic update and tell the user it didn't persist.
        updateSettings(rollback);
        setPersistError(true);
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

  // ── Native file picker — select an .exe instead of typing the path ──
  // The picked path's basename is added via the SAME full-object persist() the
  // text-field Add uses, so storage stays consistent (save_settings).
  const browseForApp = useCallback(async () => {
    if (!enabled) return;
    let selected: string | string[] | null;
    try {
      selected = await open({
        multiple: false,
        filters: [{ name: 'Applications', extensions: ['exe'] }],
      });
    } catch {
      // Dialog cancelled or unavailable — nothing to add.
      return;
    }
    if (typeof selected !== 'string') return;
    // Derive the basename from the returned path (handles \ and /).
    const appName = selected.split(/[\\/]/).pop()?.trim();
    if (!appName || apps.includes(appName)) return;
    persist({ splitTunnelApps: [...apps, appName] });
  }, [apps, enabled, persist]);

  const removeApp = useCallback(
    (appName: string) => {
      if (!enabled) return;
      persist({ splitTunnelApps: apps.filter((app) => app !== appName) });
    },
    [apps, enabled, persist],
  );

  // ── Installed-app picker: enumerate once, then add by full path ──
  const loadInstalled = useCallback(async () => {
    setPickerError(false);
    setInstalled(null);
    setPickerLoading(true);
    try {
      const list = await invoke<InstalledApp[]>('list_installed_apps');
      setInstalled(list);
    } catch {
      // Distinguish a genuine failure from an empty result so the picker can
      // surface an error + retry instead of a misleading "No apps found".
      setPickerError(true);
      setInstalled([]);
    } finally {
      setPickerLoading(false);
    }
  }, []);

  const openInstalledPicker = useCallback(async () => {
    if (!enabled) return;
    setPickerSearch('');
    setPickerOpen(true);
    // Guard against rapid re-clicks stacking concurrent list_installed_apps
    // calls before the first resolves (installed stays null until it returns).
    if (installed === null && !pickerLoading) {
      await loadInstalled();
    }
  }, [enabled, installed, loadInstalled, pickerLoading]);

  const addInstalled = useCallback(
    (path: string) => {
      if (!enabled || apps.includes(path)) return;
      persist({ splitTunnelApps: [...apps, path] });
    },
    [apps, enabled, persist],
  );

  const pickerResults = useMemo(() => {
    if (!installed) return [];
    const q = pickerSearch.trim().toLowerCase();
    const base = q
      ? installed.filter(
          (a) => a.name.toLowerCase().includes(q) || a.path.toLowerCase().includes(q),
        )
      : installed;
    return base;
  }, [installed, pickerSearch]);

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
    <div className="flex h-full flex-col">
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

        {/* ── Persist-failure banner ── */}
        {persistError && (
          <div
            className="mt-3 flex items-start gap-2.5 rounded-birdo-md px-3 py-3"
            style={{ backgroundColor: status.redBg, border: `1px solid rgba(248,113,113,0.30)` }}
            role="alert"
          >
            <Info size={18} color={status.red} aria-hidden className="mt-px shrink-0" />
            <p className="text-xs leading-relaxed" style={{ color: status.red }}>
              Couldn’t save your split-tunnel changes. The last change was reverted — please try again.
            </p>
          </div>
        )}

        {enabled && (
          <>
            {/* ── Add by path/name, installed-app picker, or file browse ── */}
            <div className="mt-3">
              <label className="mb-1.5 block pl-1 text-xs font-medium" style={{ color: white.w60 }}>
                Add by path or name
              </label>
              <div className="flex gap-2">
                <div
                  className="flex min-w-0 flex-1 items-center gap-2 px-3 transition-shadow focus-within:shadow-[0_0_0_2px_#a855f780]"
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
                    className="birdo-field-input min-w-0 flex-1 bg-transparent text-sm outline-none placeholder:text-w40"
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
              <div className="mt-2 grid grid-cols-2 gap-2">
                <BirdoButton
                  text="Installed apps"
                  icon={AppWindow}
                  onClick={() => {
                    void openInstalledPicker();
                  }}
                  variant="secondary"
                  size="medium"
                  fullWidth
                  ariaLabel="Choose from installed apps"
                />
                <BirdoButton
                  text="Browse…"
                  icon={FolderOpen}
                  onClick={() => {
                    void browseForApp();
                  }}
                  variant="secondary"
                  size="medium"
                  fullWidth
                  ariaLabel="Browse for an application"
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
                  <div className="min-w-0 flex-1" title={appName}>
                    <div
                      className="truncate text-[15px] font-medium"
                      style={{ color: white.w80 }}
                    >
                      {baseName(appName)}
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

      {/* ── Installed-apps picker overlay ── */}
      {/* top-8 clears the 32px custom TitleBar (z-100) so the header isn't
          rendered under the window chrome. */}
      {pickerOpen && (
        <div
          className="fixed inset-0 top-8 z-50 flex flex-col"
          style={{ backgroundColor: 'rgba(11,11,16,0.985)' }}
        >
          <div className="flex items-center gap-2 px-4 pb-2 pt-4">
            <AppWindow size={18} color={brand.purple} aria-hidden />
            <span className="flex-1 text-[15px] font-semibold" style={{ color: white.w100 }}>
              Installed apps
            </span>
            <button
              type="button"
              onClick={() => setPickerOpen(false)}
              aria-label="Close installed apps"
              className="flex h-7 w-7 items-center justify-center rounded-full transition-colors hover:bg-white/10"
            >
              <X size={18} color={white.w60} aria-hidden />
            </button>
          </div>
          <div className="px-4 pb-2">
            <BirdoTextField
              value={pickerSearch}
              onChange={setPickerSearch}
              placeholder="Search installed apps…"
              ariaLabel="Search installed apps"
              leadingIcon={Search}
            />
          </div>
          <div className="flex-1 overflow-y-auto px-4 pb-4">
            {installed === null ? (
              <p className="pt-6 text-center text-sm" style={{ color: white.w40 }}>
                Scanning installed apps…
              </p>
            ) : pickerError ? (
              <BirdoEmptyState
                icon={AppWindow}
                title="Couldn’t scan apps"
                description="Something went wrong reading installed apps. Use Browse… to pick an .exe directly, or try again."
                action={
                  <BirdoButton
                    text="Try again"
                    onClick={() => {
                      void loadInstalled();
                    }}
                    variant="secondary"
                    size="medium"
                    ariaLabel="Retry scanning installed apps"
                  />
                }
                className="pt-6"
              />
            ) : pickerResults.length === 0 ? (
              <BirdoEmptyState
                icon={AppWindow}
                title={pickerSearch.trim() ? 'No matches' : 'No apps found'}
                description={
                  pickerSearch.trim()
                    ? `Nothing matches "${pickerSearch.trim()}".`
                    : 'Use Browse… to pick an .exe directly.'
                }
                className="pt-6"
              />
            ) : (
              <div className="space-y-1.5">
                {pickerResults.map((app) => {
                  const added = apps.includes(app.path);
                  return (
                    <button
                      key={app.path}
                      type="button"
                      disabled={added}
                      onClick={() => {
                        addInstalled(app.path);
                        setPickerOpen(false);
                      }}
                      title={app.path}
                      className="flex w-full items-center gap-3 rounded-birdo-md px-3.5 py-2.5 text-left transition-colors hover:bg-white/[0.06] disabled:opacity-50"
                      style={{ backgroundColor: white.w04, border: `1px solid ${hairline.soft}` }}
                    >
                      <AppIconMark size={32} />
                      <div className="min-w-0 flex-1">
                        <div className="truncate text-[14px] font-medium" style={{ color: white.w80 }}>
                          {app.name}
                        </div>
                        <div className="truncate text-[11px]" style={{ color: white.w40 }}>
                          {baseName(app.path)}
                        </div>
                      </div>
                      {added ? (
                        <span
                          className="shrink-0 text-[10px] font-semibold"
                          style={{ color: brand.purple }}
                        >
                          ADDED
                        </span>
                      ) : (
                        <Plus size={16} color={white.w40} aria-hidden className="shrink-0" />
                      )}
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
