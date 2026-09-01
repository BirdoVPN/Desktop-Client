/**
 * Settings — mobile-parity top-level TAB ROOT.
 *
 * Mirrors mobile's `SettingsScreen.kt`: a short scrollable list of
 * `BirdoSectionHeader` + `BirdoCard` groups built from `BirdoToggleRow` /
 * `BirdoNavRow`, with the heavy/configurable surfaces PUSHED to their own
 * sub-screens (VPN Settings, Kill Switch Exceptions, Port Forwarding, Subscription).
 *
 * As a TAB ROOT it renders its OWN title header (no pushed BirdoTopBar / back
 * button) — matching `ProfileScreen.kt` / Profile.tsx.
 *
 * Sections: APPEARANCE (window position), CONNECTION (auto-connect), DISPLAY
 * (notifications + show-IP / show-server-location sub-toggles), SECURITY
 * (biometric unlock — hidden when unavailable — quantum protection, kill
 * switch), STARTUP (launch at login, start minimized), VPN (VPN Settings push
 * row, custom DNS, port forwarding), ABOUT (version + updates + support links).
 *
 * Every settings write goes through the SAME full-object path used elsewhere:
 *   invoke('save_settings', { settings: settingsToRust(next) })
 * Partial saves are never sent. `get_settings` hydrates the store on mount.
 *
 * Specials:
 *   - Biometric Unlock uses `check_biometric_available` -> { available, enabled,
 *     method }; toggling calls `set_biometric_enabled` { enabled } and, when
 *     enabling, confirms with `authenticate_biometric` { reason }.
 *
 * Kill Switch, Quantum Protection, Custom DNS and Port Forwarding used to live
 * one level down in the VPN Settings sub-screen. They are top-level here now —
 * the two toggles under Security, the two VPN surfaces under VPN — and are NOT
 * rendered on the sub-screen any more. Kill Switch Exceptions, Split-Tunnel and
 * Multi-Hop stay where they are (VPN Settings / the dashboard / their own
 * screens).
 *
 * Custom DNS and the kill switch carry the sub-screen's live-apply semantics
 * with them; see `persistTunnel` below.
 */
import { useState, useEffect, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open as openExternal } from '@tauri-apps/plugin-shell';
import { useShallow } from 'zustand/react/shallow';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Wifi,
  Bell,
  Fingerprint,
  Shield,
  Lock,
  Zap,
  Monitor,
  SlidersHorizontal,
  Globe,
  ArrowLeftRight,
  ChevronRight,
  ExternalLink,
  ShieldCheck,
  FileText,
  Palette,
  Gauge,
  ArrowUpLeft,
  ArrowUpRight,
  ArrowDownLeft,
  ArrowDownRight,
  Move,
} from 'lucide-react';
import { useAppStore } from '@/store/app-store';
import {
  settingsToRust,
  settingsFromRust,
  isValidDnsAddress,
  type RustSettings,
} from '@/utils/helpers';
import {
  BirdoCard,
  BirdoSectionHeader,
  BirdoToggleRow,
  BirdoNavRow,
  BirdoTextField,
  BirdoButton,
} from '@/components/birdo';
import { UpdateChecker } from './UpdateChecker';
import {
  brand,
  status as statusTokens,
  white,
  surface,
  gradient,
  motion as motionTokens,
} from '@/lib/birdo-theme';
import type { WindowCorner } from '@/store/app-store';

const DASHBOARD_URL = 'https://dashboard.birdo.app';
const PRIVACY_URL = 'https://birdo.app/privacy';
const TERMS_URL = 'https://birdo.app/terms';

/** Shape returned by the Rust `check_biometric_available` command. */
interface BiometricStatus {
  available: boolean;
  enabled: boolean;
  method: string; // "windows_hello" | "touch_id" | "none"
}

/** Shape returned by the Rust `run_speed_test_command`. */
interface SpeedTestResult {
  downloadMbps: number;
  uploadMbps: number;
  latencyMs: number;
}

const CORNER_OPTIONS: { value: WindowCorner; label: string; icon: typeof ArrowUpLeft }[] = [
  { value: 'top-left', label: 'Top L', icon: ArrowUpLeft },
  { value: 'top-right', label: 'Top R', icon: ArrowUpRight },
  { value: 'bottom-left', label: 'Bot L', icon: ArrowDownLeft },
  { value: 'bottom-right', label: 'Bot R', icon: ArrowDownRight },
];

export function Settings() {
  const {
    settings,
    updateSettings,
    hydrateSettings,
    windowCorner,
    setWindowCorner,
    pushRoute,
  } = useAppStore(
    useShallow((s) => ({
      settings: s.settings,
      updateSettings: s.updateSettings,
      hydrateSettings: s.hydrateSettings,
      windowCorner: s.windowCorner,
      setWindowCorner: s.setWindowCorner,
      pushRoute: s.pushRoute,
    })),
  );

  const [appVersion, setAppVersion] = useState('');
  const [biometric, setBiometric] = useState<BiometricStatus | null>(null);
  const [biometricError, setBiometricError] = useState<string | null>(null);

  // ── Custom DNS (moved up from VPN Settings, behaviour unchanged) ───────────
  const [dnsExpanded, setDnsExpanded] = useState(false);
  const [dnsErrors, setDnsErrors] = useState<{ primary: string | null; secondary: string | null }>({
    primary: null,
    secondary: null,
  });
  const [dnsPrimaryInput, setDnsPrimaryInput] = useState((settings.customDns ?? [])[0] ?? '');
  const [dnsSecondaryInput, setDnsSecondaryInput] = useState((settings.customDns ?? [])[1] ?? '');

  // Disabling the kill switch removes leak protection — gate it behind an
  // explicit confirmation (mobile parity). Enabling stays immediate.
  const [showKsConfirm, setShowKsConfirm] = useState(false);

  // ── Speed test (on-device, through the tunnel via Rust) ───────────────────
  // The Rust test measures throughput THROUGH the VPN tunnel, so it only works
  // while connected. Short-circuit when disconnected and surface a friendly
  // message on any failure instead of silently swallowing the error.
  const [speedTestRunning, setSpeedTestRunning] = useState(false);
  const [speedTestResult, setSpeedTestResult] = useState<SpeedTestResult | null>(null);
  const [speedTestError, setSpeedTestError] = useState<string | null>(null);
  const runSpeedTest = useCallback(async () => {
    // Throughput is measured through the tunnel — require an active connection.
    if (useAppStore.getState().connectionState !== 'connected') {
      setSpeedTestResult(null);
      setSpeedTestError('Connect to a VPN server first to run a speed test.');
      return;
    }
    setSpeedTestRunning(true);
    setSpeedTestResult(null);
    setSpeedTestError(null);
    try {
      const result = await invoke<SpeedTestResult>('run_speed_test_command');
      setSpeedTestResult(result);
      setSpeedTestError(null);
    } catch (err) {
      const lower = String(err).toLowerCase();
      const notConnected =
        lower.includes('not connected') ||
        lower.includes('no tunnel') ||
        lower.includes('tunnel') ||
        lower.includes('timeout') ||
        lower.includes('timed out');
      setSpeedTestError(
        notConnected
          ? 'Connect to a VPN server first to run a speed test.'
          : 'Speed test failed. Try again.',
      );
    } finally {
      setSpeedTestRunning(false);
    }
  }, []);

  // ── Hydrate settings from Rust on mount ────────────────────────────────────
  useEffect(() => {
    invoke<RustSettings>('get_settings')
      .then((rs) => hydrateSettings(settingsFromRust(rs)))
      .catch(() => {
        /* Rust backend logs the error; keep persisted preference */
      });
  }, [hydrateSettings]);

  // ── App version ─────────────────────────────────────────────────────────
  useEffect(() => {
    invoke<string>('get_app_version')
      .then(setAppVersion)
      .catch(() => setAppVersion('unknown'));
  }, []);

  // ── Biometric availability ────────────────────────────────────────────────
  useEffect(() => {
    invoke<BiometricStatus>('check_biometric_available')
      .then(setBiometric)
      .catch(() => setBiometric({ available: false, enabled: false, method: 'none' }));
  }, []);

  // ── Persist the FULL settings object via the shared settingsToRust path ─────
  const saveSettingsToBackend = useCallback(async (next: typeof settings) => {
    try {
      await invoke('save_settings', { settings: settingsToRust(next) });
    } catch {
      /* Rust backend logs the error */
    }
  }, []);

  // Patch the store + persist the full object.
  const persist = useCallback(
    (patch: Partial<typeof settings>) => {
      const next = { ...useAppStore.getState().settings, ...patch };
      updateSettings(patch);
      saveSettingsToBackend(next);
    },
    [updateSettings, saveSettingsToBackend],
  );

  // ── Live-apply for the tunnel-affecting settings that moved up here ────────
  // Custom DNS, Quantum Protection and the Kill Switch came from the VPN
  // Settings sub-screen and keep its apply semantics: the kill switch is pushed
  // to an ACTIVE session as a live flag (no rebuild), everything else schedules
  // a debounced fail-closed tunnel rebuild. Both no-op when disconnected — the
  // persisted setting then applies at the next connect. The plain `persist`
  // above stays for the settings that never touch the tunnel (auto-connect,
  // notifications, startup); routing those through here would rebuild the
  // tunnel every time someone toggled a notification.
  const reapplyDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => {
    return () => {
      if (reapplyDebounceRef.current) clearTimeout(reapplyDebounceRef.current);
    };
  }, []);

  const scheduleReapply = useCallback(() => {
    if (useAppStore.getState().connectionState !== 'connected') return;
    if (reapplyDebounceRef.current) clearTimeout(reapplyDebounceRef.current);
    reapplyDebounceRef.current = setTimeout(() => {
      invoke('reapply_vpn_settings').catch(() => {
        /* Rust backend logs the error */
      });
    }, 900);
  }, []);

  const persistTunnel = useCallback(
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

  // NOTE: we deliberately do NOT reconcile the Kill Switch toggle against
  // `get_killswitch_status`. That command reports the RUNTIME armed flag (true
  // only while a session is actively armed), which is distinct from the user's
  // persisted preference. The kill switch is user-toggleable, so the persisted
  // setting is the source of truth for that row; syncing it to the armed flag
  // would silently flip a user's ON preference to OFF whenever they are
  // disconnected (not armed).

  // ── Custom DNS helpers (primary / secondary) ───────────────────────────────
  // Mirror persisted custom DNS into the local inputs if it changes elsewhere
  // (e.g. another window). Only persisted (already-valid) values flow back in,
  // so this never clobbers an in-progress invalid edit with a stale value.
  const persistedDnsPrimary = (settings.customDns ?? [])[0] ?? '';
  const persistedDnsSecondary = (settings.customDns ?? [])[1] ?? '';
  useEffect(() => {
    setDnsPrimaryInput(persistedDnsPrimary);
    setDnsSecondaryInput(persistedDnsSecondary);
  }, [persistedDnsPrimary, persistedDnsSecondary]);

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
      const sec = secondary.trim();

      const pCheck = p.length > 0 ? isValidDnsAddress(p) : { valid: true as const };
      const sCheck = sec.length > 0 ? isValidDnsAddress(sec) : { valid: true as const };

      setDnsErrors({
        primary: pCheck.valid ? null : pCheck.error ?? 'Invalid DNS address',
        secondary: sCheck.valid ? null : sCheck.error ?? 'Invalid DNS address',
      });

      // Persist only entries that are present AND valid, preserving order.
      const next = [
        p.length > 0 && pCheck.valid ? p : '',
        sec.length > 0 && sCheck.valid ? sec : '',
      ].filter((v) => v.length > 0);
      persistTunnel({ customDns: next.length > 0 ? next : null });
    },
    [persistTunnel],
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

  // ── Auto-start (special: OS integration via set_autostart) ──────────────────
  const handleAutostart = useCallback(
    async (value: boolean) => {
      try {
        await invoke('set_autostart', { enabled: value });
      } catch {
        /* Autostart toggle failed — leave the setting unchanged */
        return;
      }
      persist({ autostart: value });
    },
    [persist],
  );

  // ── Biometric Unlock (special: keyring-backed + optional confirm) ───────────
  const handleBiometric = useCallback(
    async (value: boolean) => {
      setBiometricError(null);
      // When enabling, confirm the user can actually authenticate first.
      if (value) {
        try {
          const ok = await invoke<boolean>('authenticate_biometric', {
            reason: 'Confirm to enable biometric unlock',
          });
          if (!ok) {
            // User cancelled — leave it off, but say so (previously silent).
            setBiometricError('Verification was cancelled — biometric unlock stays off.');
            return;
          }
        } catch {
          setBiometricError('Could not verify with Windows Hello. Biometric unlock stays off.');
          return;
        }
      }
      try {
        await invoke('set_biometric_enabled', { enabled: value });
        setBiometric((prev) => (prev ? { ...prev, enabled: value } : prev));
      } catch {
        setBiometricError('Could not save that change. Please try again.');
      }
    },
    [],
  );

  return (
    // `relative` so the kill-switch confirmation can cover the tab, and OUTSIDE
    // the scroller so it stays centred no matter how far the list is scrolled.
    <div className="relative h-full">
      {/* Transparent so the App-level PixelCanvas backdrop shows through. */}
      <div className="h-full overflow-y-auto">
        {/* Tab-root header (no back button) */}
        <div className="px-5 pb-2 pt-6">
          <h1 className="text-[22px] font-semibold" style={{ color: '#FFFFFF' }}>
            Settings
          </h1>
        </div>

        <div className="flex flex-col gap-1 px-5 pb-12 pt-2">
          {/* ── APPEARANCE ─────────────────────────────────────────────── */}
          <BirdoSectionHeader title="Appearance" />
          <WindowPositionSelector corner={windowCorner} onSelect={setWindowCorner} />

          {/* ── CONNECTION ─────────────────────────────────────────────── */}
          <BirdoSectionHeader title="Connection" className="mt-2" />
          <BirdoCard padding="0.25rem">
            <BirdoToggleRow
              title="Auto-Connect"
              leadingIcon={Wifi}
              leadingTint={statusTokens.blue}
              checked={settings.autoConnect}
              onCheckedChange={(v) => persist({ autoConnect: v })}
            />
          </BirdoCard>

          {/* ── DISPLAY ────────────────────────────────────────────────── */}
          <BirdoSectionHeader title="Display" className="mt-2" />
          <BirdoCard padding="0.25rem">
            <BirdoToggleRow
              title="Notifications"
              leadingIcon={Bell}
              leadingTint={statusTokens.yellow}
              checked={settings.notifications}
              onCheckedChange={(v) => persist({ notifications: v })}
            />
            {/* Both sub-toggles only shape the CONTENT of a connection
                notification, so they stay hidden while notifications are off. */}
            {settings.notifications && (
              <>
                <BirdoToggleRow
                  title="Show IP Address"
                  leadingIcon={Bell}
                  leadingTint={white.w60}
                  checked={settings.showIpInNotification}
                  onCheckedChange={(v) => persist({ showIpInNotification: v })}
                />
                <BirdoToggleRow
                  title="Show Server Location"
                  leadingIcon={Bell}
                  leadingTint={white.w60}
                  checked={settings.showLocationInNotification}
                  onCheckedChange={(v) => persist({ showLocationInNotification: v })}
                />
              </>
            )}
          </BirdoCard>

          {/* ── SECURITY ───────────────────────────────────────────────── */}
          {/* The availability gate is on the biometric ROW, not the section: the
              OS may have no enrolled authenticator, but the kill switch and
              quantum protection below it always apply. */}
          <BirdoSectionHeader title="Security" className="mt-2" />
          <BirdoCard padding="0.25rem">
            {biometric?.available && (
              <>
                <BirdoToggleRow
                  title="Biometric Unlock"
                  leadingIcon={Fingerprint}
                  leadingTint={statusTokens.green}
                  checked={biometric.enabled}
                  onCheckedChange={handleBiometric}
                />
                {biometricError && (
                  <p className="px-3.5 pb-2.5 text-xs" style={{ color: statusTokens.red }}>
                    {biometricError}
                  </p>
                )}
              </>
            )}
            <BirdoToggleRow
              title="Quantum Protection"
              leadingIcon={Lock}
              leadingTint={brand.accent}
              checked={settings.quantumProtection}
              onCheckedChange={(v) => persistTunnel({ quantumProtection: v })}
            />
            {/* Kill switch defaults ON (the safe choice) but is user-toggleable.
                The Rust connect path only arms the firewall block when this is on
                (killswitch::arm reads the persisted setting), so turning it off
                genuinely lets traffic through if the tunnel drops. */}
            <BirdoToggleRow
              title="Kill Switch"
              leadingIcon={Shield}
              leadingTint={statusTokens.green}
              checked={settings.killSwitchEnabled}
              onCheckedChange={(v) => {
                // Enabling is immediate; disabling removes leak protection, so
                // require an explicit confirmation first (mobile parity).
                if (v) persistTunnel({ killSwitchEnabled: true });
                else setShowKsConfirm(true);
              }}
            />
          </BirdoCard>

          {/* ── STARTUP ────────────────────────────────────────────────── */}
          <BirdoSectionHeader title="Startup" className="mt-2" />
          <BirdoCard padding="0.25rem">
            <BirdoToggleRow
              title="Launch at Login"
              leadingIcon={Zap}
              leadingTint={brand.accent}
              checked={settings.autostart}
              onCheckedChange={handleAutostart}
            />
            <BirdoToggleRow
              title="Start Minimized"
              leadingIcon={Monitor}
              leadingTint={white.w60}
              checked={settings.startMinimized}
              onCheckedChange={(v) => persist({ startMinimized: v })}
            />
          </BirdoCard>

          {/* ── VPN ────────────────────────────────────────────────────── */}
          {/* Custom DNS and Port Forwarding sit beside the VPN Settings push row
              rather than inside it. Kill Switch Exceptions stays on the
              sub-screen (Windows-only); subscription / billing is on the web. */}
          <BirdoSectionHeader title="VPN" className="mt-2" />
          <BirdoCard padding="0.25rem">
            <BirdoNavRow
              title="VPN Settings"
              leadingIcon={SlidersHorizontal}
              leadingTint={statusTokens.blue}
              onClick={() => pushRoute('vpnSettings')}
            />

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
                        <p className="mt-1 pl-1 text-xs" style={{ color: statusTokens.red }}>
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
                        <p className="mt-1 pl-1 text-xs" style={{ color: statusTokens.red }}>
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

            <BirdoNavRow
              title="Port Forwarding"
              leadingIcon={ArrowLeftRight}
              leadingTint={statusTokens.blue}
              onClick={() => pushRoute('portForward')}
            />
          </BirdoCard>

          {/* ── SPEED TEST ─────────────────────────────────────────────── */}
          <BirdoSectionHeader title="Speed Test" className="mt-2" />
          <BirdoCard>
            <div className="flex items-center gap-3.5">
              <div
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full"
                style={{ backgroundColor: white.w05 }}
              >
                <Gauge size={18} color={statusTokens.greenLight} aria-hidden />
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-[15px] font-medium" style={{ color: white.w100 }}>
                  Connection Speed
                </div>
                {speedTestResult && (
                  <div className="mt-0.5 text-xs" style={{ color: white.w60 }}>
                    {`↓ ${speedTestResult.downloadMbps.toFixed(1)} / ↑ ${speedTestResult.uploadMbps.toFixed(1)} Mbps · ${Math.round(speedTestResult.latencyMs)}ms`}
                  </div>
                )}
              </div>
              <button
                type="button"
                onClick={runSpeedTest}
                disabled={speedTestRunning}
                className="shrink-0 rounded-birdo-sm px-3.5 py-2 text-[13px] font-semibold transition-all hover:brightness-125 active:scale-95 disabled:opacity-60"
                style={{ backgroundColor: brand.accentBg, color: brand.accentSoft }}
              >
                {speedTestRunning ? 'Running…' : 'Run'}
              </button>
            </div>
            {speedTestError && (
              <div className="mt-2 text-xs" style={{ color: statusTokens.red }}>
                {speedTestError}
              </div>
            )}
          </BirdoCard>

          {/* ── ABOUT ──────────────────────────────────────────────────── */}
          <BirdoSectionHeader title="About" className="mt-2" />

          <UpdateChecker />

          <div className="h-1" />
          <BirdoCard padding="0.25rem">
            <BirdoNavRow
              title="Privacy Policy"
              subtitle="birdo.app/privacy"
              leadingIcon={ShieldCheck}
              leadingTint={brand.accentSoft}
              onClick={() => openExternal(PRIVACY_URL).catch(() => {})}
            />
            <BirdoNavRow
              title="Terms of Service"
              subtitle="birdo.app/terms"
              leadingIcon={FileText}
              leadingTint={brand.accentSoft}
              onClick={() => openExternal(TERMS_URL).catch(() => {})}
            />
            <BirdoNavRow
              title="Manage on web"
              subtitle="dashboard.birdo.app"
              leadingIcon={ExternalLink}
              leadingTint={brand.accentSoft}
              onClick={() => openExternal(DASHBOARD_URL).catch(() => {})}
            />
          </BirdoCard>

          {/* App version footer */}
          <div className="mt-3 flex items-center gap-2 px-1">
            <Palette size={14} color={white.w40} aria-hidden />
            <span className="text-xs" style={{ color: white.w40 }}>
              BirdoVPN · v{appVersion || '...'}
            </span>
          </div>
        </div>
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
                  <Shield size={20} color={statusTokens.red} aria-hidden />
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
                      persistTunnel({ killSwitchEnabled: false });
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

/** Window-position picker: pin to a screen corner, or "free" (draggable). */
function WindowPositionSelector({
  corner,
  onSelect,
}: {
  corner: WindowCorner;
  onSelect: (c: WindowCorner) => void;
}) {
  const free = corner === 'free';
  return (
    <BirdoCard className="mt-2">
      <div className="flex items-center gap-3.5">
        <div
          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full"
          style={{ backgroundColor: white.w05 }}
        >
          <Monitor size={18} color={brand.accent} aria-hidden />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-[15px] font-medium text-white">Window position</div>
        </div>
      </div>
      <div
        className="mt-3 grid grid-cols-4 gap-1 rounded-birdo-sm p-1"
        style={{ backgroundColor: white.w05 }}
      >
        {CORNER_OPTIONS.map((opt) => {
          const active = corner === opt.value;
          const Icon = opt.icon;
          return (
            <button
              key={opt.value}
              type="button"
              onClick={() => onSelect(opt.value)}
              className="flex items-center justify-center gap-1 rounded-birdo-xs px-2 py-2 text-[12px] font-medium transition-all hover:shadow-[inset_0_0_0_1px_#ffffff29]"
              style={{
                backgroundColor: active ? brand.accentBg : 'transparent',
                border: active ? `1px solid ${brand.accent}` : '1px solid transparent',
                color: active ? brand.accentSoft : white.w60,
              }}
            >
              <Icon size={14} aria-hidden />
              {opt.label}
            </button>
          );
        })}
      </div>
      <button
        type="button"
        onClick={() => onSelect('free')}
        className="mt-1 flex w-full items-center justify-center gap-1.5 rounded-birdo-xs px-3 py-2 text-[13px] font-medium transition-all hover:shadow-[inset_0_0_0_1px_#ffffff29]"
        style={{
          backgroundColor: free ? brand.accentBg : white.w05,
          border: free ? `1px solid ${brand.accent}` : '1px solid transparent',
          color: free ? brand.accentSoft : white.w60,
        }}
      >
        <Move size={14} aria-hidden />
        Free (draggable)
      </button>
    </BirdoCard>
  );
}
