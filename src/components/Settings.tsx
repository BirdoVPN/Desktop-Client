/**
 * Settings — mobile-parity top-level TAB ROOT.
 *
 * Mirrors mobile's `SettingsScreen.kt`: a short scrollable list of
 * `BirdoSectionHeader` + `BirdoCard` groups built from `BirdoToggleRow` /
 * `BirdoNavRow`, with the heavy/configurable surfaces PUSHED to their own
 * sub-screens (VPN Settings, Split Tunneling, Port Forwarding, Subscription).
 *
 * As a TAB ROOT it renders its OWN title header (no pushed BirdoTopBar / back
 * button) — matching `ProfileScreen.kt` / Profile.tsx.
 *
 * Sections (mobile order): APPEARANCE (theme), CONNECTION (kill switch,
 * auto-connect, notifications + show-IP / show-location sub-toggles), SECURITY
 * (biometric unlock — hidden when unavailable), STARTUP (launch at login, start
 * minimized), MANAGE (push rows), ABOUT (version + updates + support links).
 *
 * Every settings write goes through the SAME full-object path used elsewhere:
 *   invoke('save_settings', { settings: settingsToRust(next) })
 * Partial saves are never sent. `get_settings` hydrates the store on mount.
 *
 * Specials:
 *   - Kill Switch is armed via `enable_killswitch` / `disable_killswitch`; the
 *     Rust `disable_killswitch` command is REJECTED while the VPN is up, so we
 *     surface that inline and reconcile the armed flag from `get_killswitch_status`.
 *   - Biometric Unlock uses `check_biometric_available` -> { available, enabled,
 *     method }; toggling calls `set_biometric_enabled` { enabled } and, when
 *     enabling, confirms with `authenticate_biometric` { reason }.
 *
 * Split-Tunnel + Multi-Hop have moved OUT of Settings (they live on the
 * dashboard / their own screens now).
 */
import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open as openExternal } from '@tauri-apps/plugin-shell';
import { motion, AnimatePresence } from 'framer-motion';
import { useShallow } from 'zustand/react/shallow';
import {
  Shield,
  Wifi,
  Bell,
  Eye,
  MapPin,
  Fingerprint,
  Zap,
  Monitor,
  SlidersHorizontal,
  Split,
  Router,
  CreditCard,
  ExternalLink,
  ShieldCheck,
  FileText,
  Palette,
  Moon,
  Sun,
  Laptop,
  AlertTriangle,
  Gauge,
} from 'lucide-react';
import { useAppStore } from '@/store/app-store';
import { settingsToRust, settingsFromRust, type RustSettings } from '@/utils/helpers';
import {
  BirdoCard,
  BirdoSectionHeader,
  BirdoToggleRow,
  BirdoNavRow,
} from '@/components/birdo';
import { UpdateChecker } from './UpdateChecker';
import {
  brand,
  status as statusTokens,
  surface,
  white,
  hairline,
  motion as motionTokens,
} from '@/lib/birdo-theme';
import type { ThemeMode } from '@/store/app-store';

const DASHBOARD_URL = 'https://dashboard.birdo.app';
const PRIVACY_URL = 'https://birdo.app/privacy';
const TERMS_URL = 'https://birdo.app/terms';

/** Shape returned by the Rust `get_killswitch_status` command. */
interface KillSwitchStatus {
  enabled: boolean;
  active: boolean;
  blocking_connections: number;
}

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

const THEME_OPTIONS: { value: ThemeMode; label: string; icon: typeof Moon }[] = [
  { value: 'dark', label: 'Dark', icon: Moon },
  { value: 'light', label: 'Light', icon: Sun },
  { value: 'system', label: 'System', icon: Laptop },
];

export function Settings() {
  const {
    settings,
    updateSettings,
    hydrateSettings,
    connectionState,
    theme,
    setTheme,
    pushRoute,
  } = useAppStore(
    useShallow((s) => ({
      settings: s.settings,
      updateSettings: s.updateSettings,
      hydrateSettings: s.hydrateSettings,
      connectionState: s.connectionState,
      theme: s.theme,
      setTheme: s.setTheme,
      pushRoute: s.pushRoute,
    })),
  );

  const [appVersion, setAppVersion] = useState('');
  const [killSwitchError, setKillSwitchError] = useState<string | null>(null);
  const [biometric, setBiometric] = useState<BiometricStatus | null>(null);

  // ── Speed test (on-device, through the tunnel via Rust) ───────────────────
  const [speedTestRunning, setSpeedTestRunning] = useState(false);
  const [speedTestResult, setSpeedTestResult] = useState<SpeedTestResult | null>(null);
  const runSpeedTest = useCallback(async () => {
    setSpeedTestRunning(true);
    setSpeedTestResult(null);
    try {
      const result = await invoke<SpeedTestResult>('run_speed_test_command');
      setSpeedTestResult(result);
    } catch {
      /* surfaced via the disabled->enabled re-enable; Rust logs detail */
    } finally {
      setSpeedTestRunning(false);
    }
  }, []);

  // The Rust `disable_killswitch` command is rejected unless the tunnel is fully
  // down. Mirror that here (anything other than disconnected/error counts as up).
  const vpnActive = connectionState !== 'disconnected' && connectionState !== 'error';

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

  // ── Reconcile the armed kill-switch flag with the backend source of truth ──
  useEffect(() => {
    invoke<KillSwitchStatus>('get_killswitch_status')
      .then((s) => {
        if (s.enabled !== useAppStore.getState().settings.killSwitchEnabled) {
          updateSettings({ killSwitchEnabled: s.enabled });
        }
      })
      .catch(() => {
        /* Rust logs; keep persisted preference */
      });
  }, [updateSettings]);

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

  // ── Kill Switch (special: armed via enable/disable_killswitch) ──────────────
  const handleKillSwitch = useCallback(
    async (value: boolean) => {
      setKillSwitchError(null);
      try {
        if (value) {
          await invoke('enable_killswitch');
        } else {
          await invoke('disable_killswitch');
        }
      } catch (err) {
        const msg = String(err);
        const lower = msg.toLowerCase();
        if (lower.includes('administrator') || lower.includes('root') || lower.includes('privilege')) {
          setKillSwitchError(
            'Kill switch requires administrator privileges. Run Birdo as administrator and try again.',
          );
        } else if (
          lower.includes('connected') ||
          lower.includes('connecting') ||
          lower.includes('disconnect first') ||
          lower.includes('vpn is')
        ) {
          setKillSwitchError('Cannot disable the kill switch while the VPN is connected. Disconnect first.');
        } else {
          setKillSwitchError(msg);
        }
        return;
      }
      persist({ killSwitchEnabled: value });
    },
    [persist],
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
      // When enabling, confirm the user can actually authenticate first.
      if (value) {
        try {
          const ok = await invoke<boolean>('authenticate_biometric', {
            reason: 'Confirm to enable biometric unlock',
          });
          if (!ok) return; // user cancelled — leave it off
        } catch {
          /* Auth failed/unavailable — abort enabling */
          return;
        }
      }
      try {
        await invoke('set_biometric_enabled', { enabled: value });
        setBiometric((prev) => (prev ? { ...prev, enabled: value } : prev));
      } catch {
        /* Persist failed — Rust logs the error */
      }
    },
    [],
  );

  return (
    <div className="h-full overflow-y-auto" style={{ backgroundColor: surface.s0 }}>
      {/* Tab-root header (no back button) */}
      <div data-tauri-drag-region className="px-5 pb-2 pt-6">
        <h1 className="text-[22px] font-semibold" style={{ color: '#FFFFFF' }}>
          Settings
        </h1>
        <p className="mt-0.5 text-[13px]" style={{ color: white.w60 }}>
          App preferences &amp; account
        </p>
      </div>

      <div className="flex flex-col gap-1 px-5 pb-12 pt-2">
        {/* ── APPEARANCE ─────────────────────────────────────────────── */}
        <BirdoSectionHeader title="Appearance" />
        <ThemeSelector theme={theme} onSelect={setTheme} />

        {/* ── CONNECTION ─────────────────────────────────────────────── */}
        <BirdoSectionHeader title="Connection" className="mt-2" />
        <BirdoCard padding="0.25rem">
          <BirdoToggleRow
            title="Kill Switch"
            subtitle="Block all traffic if the VPN connection drops"
            leadingIcon={Shield}
            leadingTint={statusTokens.green}
            checked={settings.killSwitchEnabled}
            onCheckedChange={handleKillSwitch}
          />
          <BirdoToggleRow
            title="Auto-Connect"
            subtitle="Connect to the VPN when the app starts"
            leadingIcon={Wifi}
            leadingTint={statusTokens.blue}
            checked={settings.autoConnect}
            onCheckedChange={(v) => persist({ autoConnect: v })}
          />
          <BirdoToggleRow
            title="Notifications"
            subtitle="Show connection status notifications"
            leadingIcon={Bell}
            leadingTint={statusTokens.yellow}
            checked={settings.notifications}
            onCheckedChange={(v) => persist({ notifications: v })}
          />

          {/* Expandable show-IP / show-location sub-toggles. */}
          <AnimatePresence initial={false}>
            {settings.notifications && (
              <motion.div
                className="overflow-hidden"
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{ opacity: 0, height: 0 }}
                transition={{ duration: motionTokens.fast, ease: motionTokens.ease }}
              >
                <div className="ml-2 border-l" style={{ borderColor: hairline.soft }}>
                  <BirdoToggleRow
                    title="Show IP in notification"
                    subtitle="Display your VPN IP address"
                    leadingIcon={Eye}
                    leadingTint={white.w60}
                    checked={settings.showIpInNotification}
                    onCheckedChange={(v) => updateSettings({ showIpInNotification: v })}
                  />
                  <BirdoToggleRow
                    title="Show location in notification"
                    subtitle="Display the server city / country"
                    leadingIcon={MapPin}
                    leadingTint={white.w60}
                    checked={settings.showLocationInNotification}
                    onCheckedChange={(v) => updateSettings({ showLocationInNotification: v })}
                  />
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </BirdoCard>

        <AnimatePresence>
          {killSwitchError && (
            <motion.div
              className="mt-2 flex items-start gap-2 rounded-birdo-sm px-3 py-2 text-xs"
              style={{
                backgroundColor: statusTokens.yellowBg,
                border: `1px solid ${hairline.soft}`,
                color: statusTokens.yellowLight,
              }}
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
            >
              <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden />
              <span>{killSwitchError}</span>
            </motion.div>
          )}
        </AnimatePresence>

        {vpnActive && (
          <p className="mt-1.5 px-1 text-[11px]" style={{ color: white.w40 }}>
            The kill switch can&apos;t be turned off while the VPN is connected. Disconnect first.
          </p>
        )}

        {/* ── SECURITY (biometric — hidden when unavailable) ───────────── */}
        {biometric?.available && (
          <>
            <BirdoSectionHeader title="Security" className="mt-2" />
            <BirdoCard padding="0.25rem">
              <BirdoToggleRow
                title="Biometric Unlock"
                subtitle={
                  biometric.method === 'touch_id'
                    ? 'Require Touch ID to open the app'
                    : 'Require Windows Hello to open the app'
                }
                leadingIcon={Fingerprint}
                leadingTint={statusTokens.green}
                checked={biometric.enabled}
                onCheckedChange={handleBiometric}
              />
            </BirdoCard>
          </>
        )}

        {/* ── STARTUP ────────────────────────────────────────────────── */}
        <BirdoSectionHeader title="Startup" className="mt-2" />
        <BirdoCard padding="0.25rem">
          <BirdoToggleRow
            title="Launch at Login"
            subtitle="Start Birdo VPN when your computer starts"
            leadingIcon={Zap}
            leadingTint={brand.purple}
            checked={settings.autostart}
            onCheckedChange={handleAutostart}
          />
          <BirdoToggleRow
            title="Start Minimized"
            subtitle="Start in the system tray instead of a full window"
            leadingIcon={Monitor}
            leadingTint={white.w60}
            checked={settings.startMinimized}
            onCheckedChange={(v) => persist({ startMinimized: v })}
          />
        </BirdoCard>

        {/* ── MANAGE (push rows) ─────────────────────────────────────── */}
        <BirdoSectionHeader title="Manage" className="mt-2" />
        <BirdoCard padding="0.25rem">
          <BirdoNavRow
            title="VPN Settings"
            subtitle="Protocol, DNS, kill switch & WireGuard tuning"
            leadingIcon={SlidersHorizontal}
            leadingTint={statusTokens.blue}
            onClick={() => pushRoute('vpnSettings')}
          />
          <BirdoNavRow
            title="Split Tunneling"
            subtitle="Choose which apps bypass the VPN"
            leadingIcon={Split}
            leadingTint={white.w60}
            onClick={() => pushRoute('splitTunnel')}
          />
          <BirdoNavRow
            title="Port Forwarding"
            subtitle="Forward external ports to your device"
            leadingIcon={Router}
            leadingTint={white.w60}
            onClick={() => pushRoute('portForward')}
          />
          <BirdoNavRow
            title="Subscription"
            subtitle="Manage your plan & billing"
            leadingIcon={CreditCard}
            leadingTint={brand.purpleSoft}
            onClick={() => pushRoute('subscription')}
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
              <div className="mt-0.5 text-xs" style={{ color: white.w60 }}>
                {speedTestResult
                  ? `↓ ${speedTestResult.downloadMbps.toFixed(1)} / ↑ ${speedTestResult.uploadMbps.toFixed(1)} Mbps · ${speedTestResult.latencyMs}ms`
                  : 'Measure download, upload & latency'}
              </div>
            </div>
            <button
              type="button"
              onClick={runSpeedTest}
              disabled={speedTestRunning}
              className="shrink-0 rounded-birdo-sm px-3.5 py-2 text-[13px] font-semibold transition-colors disabled:opacity-60"
              style={{ backgroundColor: brand.purpleBg, color: brand.purpleSoft }}
            >
              {speedTestRunning ? 'Running…' : 'Run'}
            </button>
          </div>
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
            leadingTint={brand.purpleSoft}
            onClick={() => openExternal(PRIVACY_URL)}
          />
          <BirdoNavRow
            title="Terms of Service"
            subtitle="birdo.app/terms"
            leadingIcon={FileText}
            leadingTint={brand.purpleSoft}
            onClick={() => openExternal(TERMS_URL)}
          />
          <BirdoNavRow
            title="Manage on web"
            subtitle="Open dashboard.birdo.app in browser"
            leadingIcon={ExternalLink}
            leadingTint={brand.purpleSoft}
            onClick={() => openExternal(DASHBOARD_URL)}
          />
        </BirdoCard>

        {/* App version footer */}
        <div className="mt-3 flex items-center gap-2 px-1">
          <Palette size={14} color={white.w40} aria-hidden />
          <span className="text-xs" style={{ color: white.w40 }}>
            Birdo VPN · v{appVersion || '...'}
          </span>
        </div>
      </div>
    </div>
  );
}

/** Segmented dark / light / system theme picker inside a BirdoCard. */
function ThemeSelector({
  theme,
  onSelect,
}: {
  theme: ThemeMode;
  onSelect: (mode: ThemeMode) => void;
}) {
  return (
    <BirdoCard>
      <div className="flex items-center gap-3.5">
        <div
          className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full"
          style={{ backgroundColor: white.w05 }}
        >
          <Palette size={18} color={brand.purple} aria-hidden />
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-[15px] font-medium text-white">Theme</div>
          <div className="mt-0.5 text-xs" style={{ color: white.w60 }}>
            Dark, light, or follow system
          </div>
        </div>
      </div>
      <div
        className="mt-3 grid grid-cols-3 gap-1 rounded-birdo-sm p-1"
        style={{ backgroundColor: white.w05 }}
      >
        {THEME_OPTIONS.map((opt) => {
          const active = theme === opt.value;
          const Icon = opt.icon;
          return (
            <button
              key={opt.value}
              type="button"
              onClick={() => onSelect(opt.value)}
              className="flex items-center justify-center gap-1.5 rounded-birdo-xs px-3 py-2 text-[13px] font-medium transition-colors"
              style={{
                backgroundColor: active ? brand.purpleBg : 'transparent',
                border: active ? `1px solid ${brand.purple}` : '1px solid transparent',
                color: active ? brand.purpleSoft : white.w60,
              }}
            >
              <Icon size={14} aria-hidden />
              {opt.label}
            </button>
          );
        })}
      </div>
    </BirdoCard>
  );
}
