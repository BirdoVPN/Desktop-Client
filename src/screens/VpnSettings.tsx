/**
 * VpnSettings — pushed sub-screen, pixel-faithful to mobile's
 * `VpnSettingsScreen.kt`.
 *
 * Sections: SECURITY (Stealth Mode), NETWORK (Local Network Sharing),
 * WIREGUARD (Port radio group + MTU), an info note, then FEATURES
 * (Kill Switch Exceptions nav row, Windows-only).
 *
 * Every toggle reads/writes the Zustand store settings and persists via the
 * SAME full-object `invoke('save_settings', { settings: settingsToRust(...) })`
 * path used by Settings.tsx / MultiHopCard.tsx. Changes apply on next connect.
 *
 * Kill Switch, Quantum Protection, Custom DNS and Port Forwarding have moved UP
 * to the main Settings page (Security / VPN) — they are not duplicated here.
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useShallow } from 'zustand/react/shallow';
import {
  EyeOff,
  Network,
  Router,
  SlidersHorizontal,
  Info,
  Split,
} from 'lucide-react';
import {
  BirdoTopBar,
  BirdoCard,
  BirdoSectionHeader,
  BirdoToggleRow,
  BirdoNavRow,
  BirdoTextField,
} from '@/components/birdo';
import { useAppStore } from '@/store/app-store';
import { settingsToRust, isValidPort, isWindowsPlatform } from '@/utils/helpers';
import { white, status, brand } from '@/lib/birdo-theme';

export function VpnSettings() {
  const { settings, updateSettings, popRoute, pushRoute, account, connectionState } = useAppStore(
    useShallow((s) => ({
      settings: s.settings,
      updateSettings: s.updateSettings,
      popRoute: s.popRoute,
      pushRoute: s.pushRoute,
      account: s.account,
      connectionState: s.connectionState,
    })),
  );
  const connected = connectionState === 'connected';

  // Stealth mode is OPERATIVE+. Gated by PLAN only (an anonymous RECON user is
  // treated identically to an email/SSO RECON user). Enforced server-side too
  // (birdo-web): a non-entitled connect with stealth is refused.
  const planRank = (plan: string | null | undefined): number =>
    plan === 'SOVEREIGN' ? 2 : plan === 'OPERATIVE' ? 1 : 0;
  const isOperativeOrAbove = planRank(account?.plan) >= 1;

  const [customPortInput, setCustomPortInput] = useState(
    !['auto', '51820', '53'].includes(settings.wireGuardPort) ? settings.wireGuardPort : '',
  );
  // Whether the "Custom" port radio is selected. Tracked as UI state (not derived
  // purely from the persisted port) so choosing Custom can REVEAL the input field
  // before a valid port exists — otherwise clicking Custom with an empty input
  // persisted "auto", which snapped the selection straight back to Automatic and
  // the input never appeared (Custom was impossible to select).
  const [customPortMode, setCustomPortMode] = useState(
    !['auto', '51820', '53'].includes(settings.wireGuardPort),
  );
  const [customMtuInput, setCustomMtuInput] = useState(
    settings.wireGuardMtu > 0 ? String(settings.wireGuardMtu) : '',
  );
  const saveDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reapplyDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const [reapplying, setReapplying] = useState(false);

  useEffect(() => {
    return () => {
      if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
      if (reapplyDebounceRef.current) clearTimeout(reapplyDebounceRef.current);
    };
  }, []);

  // Live-apply tunnel-affecting changes to an ACTIVE session (mobile parity):
  // a debounced fail-closed tunnel rebuild. The kill switch is pushed live as a
  // flag (no rebuild). Both no-op when disconnected — the persisted setting then
  // applies at the next connect. Reads live connection state to avoid a stale
  // closure. See the Rust `reapply_vpn_settings` / `set_killswitch_live`.
  const scheduleReapply = useCallback(() => {
    if (useAppStore.getState().connectionState !== 'connected') return;
    if (reapplyDebounceRef.current) clearTimeout(reapplyDebounceRef.current);
    reapplyDebounceRef.current = setTimeout(async () => {
      setReapplying(true);
      try {
        await invoke('reapply_vpn_settings');
      } catch {
        /* Rust backend logs the error */
      } finally {
        setReapplying(false);
      }
    }, 900);
  }, []);

  // Keep the custom port/MTU inputs in sync if settings change elsewhere.
  useEffect(() => {
    if (!['auto', '51820', '53'].includes(settings.wireGuardPort)) {
      setCustomPortInput(settings.wireGuardPort);
    }
    if (settings.wireGuardMtu > 0) {
      setCustomMtuInput(String(settings.wireGuardMtu));
    }
  }, [settings.wireGuardPort, settings.wireGuardMtu]);

  // Persist the FULL settings object via the shared settingsToRust path.
  const saveSettingsToBackend = useCallback(async (next: typeof settings) => {
    try {
      await invoke('save_settings', { settings: settingsToRust(next) });
    } catch {
      /* Rust backend logs the error */
    }
  }, []);

  // Patch the store + persist the full object, then live-apply to an active
  // session. Every setting left on this screen is tunnel-affecting, so each one
  // schedules a debounced fail-closed rebuild (reapply_vpn_settings). No-op when
  // disconnected — the persisted setting applies at the next connect.
  const persist = useCallback(
    async (patch: Partial<typeof settings>) => {
      const next = { ...useAppStore.getState().settings, ...patch };
      updateSettings(patch);
      await saveSettingsToBackend(next);
      scheduleReapply();
    },
    [updateSettings, saveSettingsToBackend, scheduleReapply],
  );

  // ── WireGuard port selection ──────────────────────────────────────────────
  const portOptions = ['auto', '51820', '53', 'custom'] as const;
  const persistedIsCustom = !['auto', '51820', '53'].includes(settings.wireGuardPort);
  const selectedPort =
    customPortMode || persistedIsCustom ? 'custom' : settings.wireGuardPort;

  const onSelectPort = (option: (typeof portOptions)[number]) => {
    if (option === 'custom') {
      // Enter custom mode and reveal the input. Only persist if a valid port is
      // already typed; otherwise wait for the input's onChange (persisting "auto"
      // here would revert the selection and hide the field).
      setCustomPortMode(true);
      if (isValidPort(customPortInput)) {
        persist({ wireGuardPort: customPortInput });
      }
    } else {
      setCustomPortMode(false);
      persist({ wireGuardPort: option });
    }
  };

  const portLabel = (option: (typeof portOptions)[number]) => {
    switch (option) {
      case 'auto':
        return 'Automatic';
      case 'custom':
        return 'Custom';
      default:
        return option;
    }
  };

  // ── MTU ───────────────────────────────────────────────────────────────────
  const mtuAuto = settings.wireGuardMtu === 0;

  return (
    // Transparent so the App-level PixelCanvas backdrop shows through (matches
    // the Settings / Profile tab roots).
    <div className="flex h-full flex-col">
      <BirdoTopBar title="VPN Settings" onBack={popRoute} />

      <div className="flex-1 overflow-y-auto px-4 pb-8 pt-2">
        {/* ── SECURITY ──────────────────────────────────────────────── */}
        <BirdoSectionHeader title="Security" />

        <BirdoCard padding="0">
          <BirdoToggleRow
            title="Stealth Mode · Premium"
            leadingIcon={EyeOff}
            leadingTint={status.blue}
            // `&& isOperativeOrAbove` so a persisted-on state can't resurface
            // after a downgrade; disabled for RECON (also enforced server-side).
            checked={settings.stealthMode && isOperativeOrAbove}
            onCheckedChange={(v) => persist({ stealthMode: v })}
            enabled={isOperativeOrAbove}
          />
          {!isOperativeOrAbove && (
            <button
              type="button"
              onClick={() => pushRoute('pricing')}
              className="px-3.5 pb-3 pt-0 text-xs font-semibold transition-opacity hover:opacity-80"
              style={{ color: brand.accent }}
            >
              View plans →
            </button>
          )}
        </BirdoCard>

        {/* ── NETWORK ───────────────────────────────────────────────── */}
        <BirdoSectionHeader title="Network" className="mt-4" />

        <BirdoCard padding="0">
          <BirdoToggleRow
            title="Local Network Sharing"
            leadingIcon={Network}
            leadingTint={status.blue}
            checked={settings.localNetworkSharing}
            onCheckedChange={(v) => persist({ localNetworkSharing: v })}
          />
        </BirdoCard>

        {/* ── WIREGUARD ─────────────────────────────────────────────── */}
        <BirdoSectionHeader title="WireGuard" className="mt-4" />

        {/* Port radio group */}
        <BirdoCard>
          <div className="flex items-center gap-3.5">
            <Router size={20} color={status.green} aria-hidden />
            <span className="text-[15px] font-medium text-white">WireGuard Port</span>
          </div>
          <div className="mt-3 space-y-1">
            {portOptions.map((option) => {
              const checked = selectedPort === option;
              return (
                <button
                  key={option}
                  type="button"
                  role="radio"
                  aria-checked={checked}
                  onClick={() => onSelectPort(option)}
                  className={`flex w-full items-center gap-3 rounded-birdo-sm px-3 py-2 text-left transition-colors ${
                    checked ? 'bg-white/10' : 'hover:bg-white/5'
                  }`}
                >
                  <span
                    className="flex h-4 w-4 shrink-0 items-center justify-center rounded-full border-2"
                    style={{ borderColor: checked ? white.w100 : white.w40 }}
                  >
                    {checked && (
                      <span className="h-2 w-2 rounded-full" style={{ backgroundColor: white.w100 }} />
                    )}
                  </span>
                  <span className="text-sm" style={{ color: white.w80 }}>
                    {portLabel(option)}
                  </span>
                </button>
              );
            })}

            {selectedPort === 'custom' && (
              <div className="pt-1">
                <BirdoTextField
                  placeholder="1-65535"
                  value={customPortInput}
                  onChange={(raw) => {
                    const filtered = raw.replace(/\D/g, '').slice(0, 5);
                    setCustomPortInput(filtered);
                    if (isValidPort(filtered)) {
                      updateSettings({ wireGuardPort: filtered });
                      if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
                      saveDebounceRef.current = setTimeout(() => {
                        saveSettingsToBackend({
                          ...useAppStore.getState().settings,
                          wireGuardPort: filtered,
                        });
                        scheduleReapply();
                      }, 500);
                    }
                  }}
                />
              </div>
            )}
          </div>
          <p className="mt-2 text-xs" style={{ color: white.w40 }}>
            Use port 53 to bypass restrictive firewalls. Default is 51820.
          </p>
        </BirdoCard>

        {/* MTU */}
        <div className="h-2" />
        <BirdoCard>
          <div className="flex items-center gap-3.5">
            <SlidersHorizontal size={20} color={status.yellow} aria-hidden />
            <div>
              <div className="text-[15px] font-medium text-white">MTU</div>
              <div className="text-xs" style={{ color: white.w40 }}>
                Maximum transmission unit
              </div>
            </div>
          </div>
          <div className="mt-3 space-y-1">
            <button
              type="button"
              role="checkbox"
              aria-checked={mtuAuto}
              onClick={() => {
                if (mtuAuto) {
                  setCustomMtuInput('1420');
                  persist({ wireGuardMtu: 1420 });
                } else {
                  setCustomMtuInput('');
                  persist({ wireGuardMtu: 0 });
                }
              }}
              className="flex w-full items-center gap-3 rounded-birdo-sm px-3 py-2 text-left"
            >
              <span
                className="flex h-4 w-4 shrink-0 items-center justify-center rounded border-2"
                style={{
                  borderColor: mtuAuto ? white.w100 : white.w40,
                  backgroundColor: mtuAuto ? white.w100 : 'transparent',
                }}
              >
                {mtuAuto && (
                  <svg viewBox="0 0 12 12" className="h-3 w-3" style={{ color: '#000000' }}>
                    <path
                      d="M10 3L4.5 8.5L2 6"
                      stroke="currentColor"
                      strokeWidth="2"
                      fill="none"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                    />
                  </svg>
                )}
              </span>
              <span className="text-sm" style={{ color: white.w80 }}>
                Automatic (use server default)
              </span>
            </button>

            {!mtuAuto && (
              <div className="pt-1">
                <BirdoTextField
                  placeholder="1280-1500"
                  value={customMtuInput}
                  onChange={(raw) => {
                    const filtered = raw.replace(/\D/g, '').slice(0, 4);
                    setCustomMtuInput(filtered);
                    const n = Number(filtered);
                    if (n >= 1280 && n <= 1500) {
                      updateSettings({ wireGuardMtu: n });
                      if (saveDebounceRef.current) clearTimeout(saveDebounceRef.current);
                      saveDebounceRef.current = setTimeout(() => {
                        saveSettingsToBackend({
                          ...useAppStore.getState().settings,
                          wireGuardMtu: n,
                        });
                        scheduleReapply();
                      }, 500);
                    }
                  }}
                />
                <p className="mt-1.5 text-xs" style={{ color: white.w40 }}>
                  Valid range: 1280 - 1500. Recommended: 1420.
                </p>
              </div>
            )}
          </div>
        </BirdoCard>

        {/* ── Info note ─────────────────────────────────────────────── */}
        <div
          className="mt-3 flex items-center gap-2.5 rounded-birdo-sm px-3 py-2.5"
          style={{ backgroundColor: white.w10 }}
        >
          <Info size={16} color={white.w40} aria-hidden className="shrink-0" />
          <p className="text-xs" style={{ color: white.w60 }}>
            {reapplying
              ? 'Applying changes to your live connection…'
              : connected
                ? 'Changes apply to your current connection automatically (brief reconnect).'
                : 'Changes take effect on the next connection.'}
          </p>
        </div>

        {/* ── FEATURES ──────────────────────────────────────────────── */}
        {/* WFP enforcement is Windows-only. Offering it on Linux/macOS let
            users configure exceptions that silently did nothing. Presented
            as "Kill Switch Exceptions", not "Split Tunneling": WFP permit
            filters exempt an app from the kill-switch block — they cannot
            route it outside the VPN (that needs a signed redirect callout
            driver), so the old name claimed behaviour that didn't exist.
            Port Forwarding used to sit beside it; it lives on the main
            Settings page (VPN) now, which leaves this section Windows-only —
            hence the gate around the header too, so other platforms don't get
            a heading over an empty card. */}
        {isWindowsPlatform() && (
          <>
            <BirdoSectionHeader title="Features" className="mt-4" />

            <BirdoCard padding="0">
              <BirdoNavRow
                title="Kill Switch Exceptions"
                leadingIcon={Split}
                leadingTint={white.w60}
                onClick={() => pushRoute('splitTunnel')}
              />
            </BirdoCard>
          </>
        )}
      </div>
    </div>
  );
}
