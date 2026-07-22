/**
 * VpnSettings — pushed sub-screen, pixel-faithful to mobile's
 * `VpnSettingsScreen.kt`.
 *
 * Sections (mobile order): SECURITY (Kill Switch, Stealth Mode, Quantum
 * Protection), NETWORK (Local Network Sharing), DNS (Custom DNS expandable),
 * WIREGUARD (Port radio group + MTU), an info note, then FEATURES
 * (Port Forwarding nav row).
 *
 * Every toggle reads/writes the Zustand store settings and persists via the
 * SAME full-object `invoke('save_settings', { settings: settingsToRust(...) })`
 * path used by Settings.tsx / MultiHopCard.tsx. Changes apply on next connect.
 *
 * Kill Switch defaults ON but is user-toggleable: the Rust connect path only
 * arms the firewall block when the persisted setting is on (killswitch::arm),
 * so turning it off genuinely lets traffic through if the tunnel drops.
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useShallow } from 'zustand/react/shallow';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  EyeOff,
  Lock,
  Network,
  Globe,
  Router,
  SlidersHorizontal,
  Info,
  ArrowLeftRight,
  Split,
  ChevronRight,
} from 'lucide-react';
import {
  BirdoTopBar,
  BirdoCard,
  BirdoSectionHeader,
  BirdoToggleRow,
  BirdoNavRow,
  BirdoTextField,
  BirdoButton,
} from '@/components/birdo';
import { useAppStore } from '@/store/app-store';
import { settingsToRust, isValidPort, isValidDnsAddress, isWindowsPlatform } from '@/utils/helpers';
import { white, status, brand, surface, gradient, motion as motionTokens } from '@/lib/birdo-theme';

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

  const [dnsExpanded, setDnsExpanded] = useState(false);
  const [dnsErrors, setDnsErrors] = useState<{ primary: string | null; secondary: string | null }>({
    primary: null,
    secondary: null,
  });
  const [dnsPrimaryInput, setDnsPrimaryInput] = useState((settings.customDns ?? [])[0] ?? '');
  const [dnsSecondaryInput, setDnsSecondaryInput] = useState((settings.customDns ?? [])[1] ?? '');
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
  // Disabling the kill switch removes leak protection — gate it behind an
  // explicit confirmation (mobile parity). Enabling stays immediate.
  const [showKsConfirm, setShowKsConfirm] = useState(false);

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

  // NOTE: we deliberately do NOT reconcile the toggle against
  // `get_killswitch_status` here. That command reports the RUNTIME armed flag
  // (true only while a session is actively armed), which is distinct from the
  // user's persisted preference. Now that the kill switch is user-toggleable,
  // the persisted setting is the source of truth for this row; syncing it to the
  // armed flag would silently flip a user's ON preference to OFF whenever they
  // are disconnected (not armed).

  // Keep DNS-derived custom port/MTU inputs in sync if settings change elsewhere.
  useEffect(() => {
    if (!['auto', '51820', '53'].includes(settings.wireGuardPort)) {
      setCustomPortInput(settings.wireGuardPort);
    }
    if (settings.wireGuardMtu > 0) {
      setCustomMtuInput(String(settings.wireGuardMtu));
    }
  }, [settings.wireGuardPort, settings.wireGuardMtu]);

  // Mirror persisted custom DNS into the local inputs if it changes elsewhere
  // (e.g. another window). Only persisted (already-valid) values flow back in,
  // so this never clobbers an in-progress invalid edit with a stale value.
  const persistedDnsPrimary = (settings.customDns ?? [])[0] ?? '';
  const persistedDnsSecondary = (settings.customDns ?? [])[1] ?? '';
  useEffect(() => {
    setDnsPrimaryInput(persistedDnsPrimary);
    setDnsSecondaryInput(persistedDnsSecondary);
  }, [persistedDnsPrimary, persistedDnsSecondary]);

  // Persist the FULL settings object via the shared settingsToRust path.
  const saveSettingsToBackend = useCallback(async (next: typeof settings) => {
    try {
      await invoke('save_settings', { settings: settingsToRust(next) });
    } catch {
      /* Rust backend logs the error */
    }
  }, []);

  // Patch the store + persist the full object, then live-apply to an active
  // session. The kill switch is a live flag push (set_killswitch_live); every
  // other setting on this screen is tunnel-affecting, so it triggers a debounced
  // fail-closed rebuild (reapply_vpn_settings). No-op when disconnected.
  const persist = useCallback(
    async (patch: Partial<typeof settings>) => {
      const next = { ...useAppStore.getState().settings, ...patch };
      updateSettings(patch);
      // AWAIT the persist before any live-apply: set_killswitch_live -> arm()
      // re-reads killswitch_enabled from disk, so arming ON must not race the
      // write (else it reads the stale value and silently doesn't arm).
      await saveSettingsToBackend(next);

      if (useAppStore.getState().connectionState === 'connected') {
        if ('killSwitchEnabled' in patch) {
          invoke('set_killswitch_live', { enabled: !!patch.killSwitchEnabled }).catch(() => {});
        } else {
          scheduleReapply();
        }
      }
    },
    [updateSettings, saveSettingsToBackend, scheduleReapply],
  );

  // ── DNS helpers (custom DNS expandable: primary / secondary) ──────────────
  const dnsList = settings.customDns ?? [];
  const customDnsEnabled = dnsList.length > 0;

  // Re-validate the local inputs and persist only valid entries. An empty field
  // is allowed (it clears that entry / falls back to the VPN server's DNS).
  // Invalid entries are surfaced inline and are NEVER persisted, so a malformed
  // or special-use address can't silently reach the tunnel config and cause a
  // DNS failure or leak.
  const setDns = useCallback(
    (primary: string, secondary: string) => {
      const p = primary.trim();
      const s = secondary.trim();

      const pCheck = p.length > 0 ? isValidDnsAddress(p) : { valid: true as const };
      const sCheck = s.length > 0 ? isValidDnsAddress(s) : { valid: true as const };

      setDnsErrors({
        primary: pCheck.valid ? null : pCheck.error ?? 'Invalid DNS address',
        secondary: sCheck.valid ? null : sCheck.error ?? 'Invalid DNS address',
      });

      // Persist only entries that are present AND valid, preserving order.
      const next = [
        p.length > 0 && pCheck.valid ? p : '',
        s.length > 0 && sCheck.valid ? s : '',
      ].filter((v) => v.length > 0);
      persist({ customDns: next.length > 0 ? next : null });
    },
    [persist],
  );

  const onChangeDnsPrimary = useCallback(
    (raw: string) => {
      setDnsPrimaryInput(raw);
      setDns(raw, dnsSecondaryInput);
    },
    [setDns, dnsSecondaryInput],
  );

  const onChangeDnsSecondary = useCallback(
    (raw: string) => {
      setDnsSecondaryInput(raw);
      setDns(dnsPrimaryInput, raw);
    },
    [setDns, dnsPrimaryInput],
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

        <BirdoCard padding="0" className="overflow-visible">
          {/* Kill switch defaults ON (the safe choice) but is user-toggleable.
              The Rust connect path only arms the firewall block when this is on
              (killswitch::arm reads the persisted setting), so turning it off
              genuinely lets traffic through if the tunnel drops. */}
          <BirdoToggleRow
            title="Kill Switch"
            leadingIcon={Shield}
            leadingTint={status.green}
            checked={settings.killSwitchEnabled}
            onCheckedChange={(v) => {
              // Enabling is immediate; disabling removes leak protection, so
              // require an explicit confirmation first (mobile parity).
              if (v) persist({ killSwitchEnabled: true });
              else setShowKsConfirm(true);
            }}
          />
        </BirdoCard>

        <div className="h-2" />
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

        <div className="h-2" />
        <BirdoCard padding="0">
          <BirdoToggleRow
            title="Quantum Protection"
            leadingIcon={Lock}
            leadingTint={brand.accent}
            checked={settings.quantumProtection}
            onCheckedChange={(v) => persist({ quantumProtection: v })}
          />
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

        {/* ── DNS ───────────────────────────────────────────────────── */}
        <BirdoSectionHeader title="DNS" className="mt-4" />

        <BirdoCard padding="0">
          <button
            type="button"
            onClick={() => setDnsExpanded((v) => !v)}
            aria-expanded={dnsExpanded}
            className="flex w-full items-center gap-3.5 rounded-birdo-md px-3.5 py-3 text-left transition-colors hover:bg-white/5"
          >
            <div
              className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full"
              style={{ backgroundColor: white.w05 }}
            >
              <Globe size={18} color={brand.accent} aria-hidden />
            </div>
            <div className="min-w-0 flex-1">
              <div className="truncate text-[15px] font-medium text-white">Custom DNS Servers</div>
              <div className="mt-0.5 truncate text-xs" style={{ color: white.w60 }}>
                {customDnsEnabled
                  ? `${dnsList.length} server${dnsList.length > 1 ? 's' : ''} configured`
                  : 'Using VPN default DNS'}
              </div>
            </div>
            <ChevronRight
              size={20}
              color={white.w40}
              aria-hidden
              className="shrink-0 transition-transform"
              style={{ transform: dnsExpanded ? 'rotate(90deg)' : 'none' }}
            />
          </button>

          <AnimatePresence initial={false}>
            {dnsExpanded && (
              <motion.div
                className="overflow-hidden"
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: motionTokens.fast, ease: motionTokens.ease }}
              >
                <div className="space-y-3 px-3.5 pb-3.5 pt-1">
                  <div>
                    <BirdoTextField
                      label="Primary DNS"
                      placeholder="e.g. 1.1.1.1"
                      value={dnsPrimaryInput}
                      onChange={onChangeDnsPrimary}
                      error={!!dnsErrors.primary}
                    />
                    {dnsErrors.primary && (
                      <p className="mt-1 pl-1 text-xs" style={{ color: status.red }}>
                        {dnsErrors.primary}
                      </p>
                    )}
                  </div>
                  <div>
                    <BirdoTextField
                      label="Secondary DNS (optional)"
                      placeholder="e.g. 1.0.0.1"
                      value={dnsSecondaryInput}
                      onChange={onChangeDnsSecondary}
                      error={!!dnsErrors.secondary}
                    />
                    {dnsErrors.secondary && (
                      <p className="mt-1 pl-1 text-xs" style={{ color: status.red }}>
                        {dnsErrors.secondary}
                      </p>
                    )}
                  </div>
                  <p className="text-xs" style={{ color: white.w40 }}>
                    Popular: 1.1.1.1 (Cloudflare), 8.8.8.8 (Google), 9.9.9.9 (Quad9).
                  </p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
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
        <BirdoSectionHeader title="Features" className="mt-4" />

        <BirdoCard padding="0">
          {/* Split tunneling is enforced via WFP — Windows only. Offering it
              on Linux/macOS let users configure exclusions that silently did
              nothing (apps they believed bypassed the VPN were tunnelled). */}
          {isWindowsPlatform() && (
            <BirdoNavRow
              title="Split Tunneling"
              leadingIcon={Split}
              leadingTint={white.w60}
              onClick={() => pushRoute('splitTunnel')}
            />
          )}
          <BirdoNavRow
            title="Port Forwarding"
            leadingIcon={ArrowLeftRight}
            leadingTint={status.blue}
            onClick={() => pushRoute('portForward')}
          />
        </BirdoCard>
      </div>

      <AnimatePresence>
        {showKsConfirm && (
          <motion.div
            className="absolute inset-0 z-50 flex items-center justify-center p-5"
            style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: motionTokens.fast, ease: motionTokens.ease }}
            onClick={() => setShowKsConfirm(false)}
          >
            <motion.div
              role="dialog"
              aria-modal="true"
              aria-label="Disable kill switch"
              className="w-full max-w-[340px] overflow-hidden rounded-birdo-lg"
              style={{
                background: `linear-gradient(${surface.s3}, ${surface.s3}) padding-box, ${gradient.glassStroke} border-box`,
                border: '1px solid transparent',
              }}
              initial={{ scale: 0.94, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.94, opacity: 0 }}
              transition={{ duration: motionTokens.standard, ease: motionTokens.ease }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="flex flex-col gap-4 p-5">
                <div className="flex items-center gap-2">
                  <Shield size={20} color={status.red} aria-hidden />
                  <h2 className="text-[16px] font-bold" style={{ color: '#FFFFFF' }}>
                    Disable kill switch?
                  </h2>
                </div>
                <p className="text-[13px]" style={{ color: white.w60 }}>
                  Without the kill switch, your internet keeps flowing in the clear
                  if the VPN drops — apps can leak your real IP. Leave it on unless
                  you have a specific reason to turn it off.
                </p>
                <div className="flex gap-2.5">
                  <BirdoButton
                    text="Keep it on"
                    variant="secondary"
                    fullWidth
                    onClick={() => setShowKsConfirm(false)}
                  />
                  <BirdoButton
                    text="Turn off"
                    variant="danger"
                    fullWidth
                    onClick={() => {
                      setShowKsConfirm(false);
                      persist({ killSwitchEnabled: false });
                    }}
                  />
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
