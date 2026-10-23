/**
 * Settings — the Settings TAB ROOT, laid out as Android's SettingsScreen.kt
 * (owner, 2026-10-21: "exactly the same design as the mobile").
 *
 * Sections in the canonical order (P1-parity "Settings names and help text"):
 * Appearance (window position) · Privacy & Security (Kill Switch, Always-on
 * Kill Switch, Quantum Protection, Hide App Contents, Crash Reports, Save
 * Diagnostic Logs, Delete Logs Now) ·
 * Connection (Auto-Connect, Launch at Login, Start Minimized) · Notifications ·
 * VPN (VPN Settings, Custom DNS Servers, Port Forwarding, Kill Switch
 * Exceptions) · Speed Test · About. The desktop-only rows sit where mobile
 * would put them.
 *
 * One row per card: an icon chip, the title and the control. No row carries a
 * description (owner, 2026-10-21; this replaces W2-029's "every row says what
 * it does"). A row only says why it cannot be used, while it cannot.
 *
 * Every write goes through `persistSettings` (session/settings-persist.ts):
 * optimistic, full-object `save_settings`, rolled back and reported when the
 * save fails (W2-013). Settings are hydrated once per session by the session
 * controller, not on every visit to this tab (W2-023).
 */
import { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { openUrl as openExternal } from '@tauri-apps/plugin-opener';
import { useShallow } from 'zustand/react/shallow';
import {
  Wifi,
  Bell,
  EyeOff,
  Shield,
  ShieldPlus,
  Lock,
  Zap,
  Monitor,
  Minimize2,
  SlidersHorizontal,
  Globe,
  MapPin,
  Server,
  ArrowLeftRight,
  Split,
  ShieldCheck,
  FileText,
  LayoutDashboard,
  Info,
  Gauge,
  BadgeCheck,
  Bug,
  ScrollText,
  Trash2,
  Scale,
} from 'lucide-react';
import { useAppStore } from '@/store/app-store';
import { isMacPlatform, isPrivateDnsAddress, isValidDnsAddress, isWindowsPlatform } from '@/utils/helpers';
import {
  AppIconMark,
  BirdoTopBar,
  BirdoTextField,
  BirdoButton,
  BirdoDialog,
  BirdoRadioGroup,
  type RadioOption,
} from '@/components/birdo';
import {
  SettingIconChip,
  SettingsCard,
  SettingsLink,
  SettingsNote,
  SettingsSectionHeader,
  SettingsToggle,
} from './settings/SettingsRows';
import { UpdateChecker } from './UpdateChecker';
import { brand, status as statusTokens, white } from '@/lib/birdo-theme';
import { persistSettings, setKillSwitch, showSaveFailure } from '@/session/settings-persist';
import { loadAppVersion, useUpdater } from '@/session/updater';
import { DASHBOARD_URL, PRIVACY_URL, TERMS_URL } from '@/lib/links';
import { customDnsAvailable, lowestPlanWith, planHasFeature, planName } from '@/lib/plan';
import { parseDeleteLogsResult, type DeleteLogsResult } from '@/lib/ipc';
import type { Notice, WindowCorner } from '@/store/app-store';


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

// Labels only, as mobile's segmented Theme control.
const CORNER_OPTIONS: RadioOption<WindowCorner>[] = [
  { value: 'top-left', label: 'Top left' },
  { value: 'top-right', label: 'Top right' },
  { value: 'bottom-left', label: 'Bottom left' },
  { value: 'bottom-right', label: 'Bottom right' },
  { value: 'free', label: 'Free (draggable)' },
];

/** iOS / Android's shared disable-confirm text (P1-parity-031). */
export const KILL_SWITCH_DISABLE_BODY =
  'If the VPN drops while the kill switch is off, your apps fall back to your normal, ' +
  'unencrypted connection and can expose your real IP address and DNS queries until it ' +
  'reconnects. For the strongest protection, keep it on.';

/**
 * macOS only (MR-1124): the IPv6 block `tunnel_macos.rs` installs for every
 * session, kill switch on or off, until macOS routes IPv6 (the F-001 block
 * there). The wording was drafted in tunnel_macos.rs (MR-1124); it goes when
 * the block does. A note on its own, not a row's description: it is no
 * setting's doing.
 */
export const MACOS_IPV6_NOTE =
  "On macOS, IPv6 is blocked while you're connected, so your real address can't leak over it. " +
  "Sites that only work over IPv6 won't load until you disconnect.";

/**
 * MR-808: "Delete Logs Now" asks first, and the confirmation says what goes
 * (`birdo.log` and the crash files, `utils::file_log` in Rust).
 */
export const DELETE_LOGS_CONFIRM_BODY =
  "This deletes the diagnostic log and crash files on this device. It can't be undone.";

/** Added to the confirmation while the log is on: the next entry starts a new file. */
export const DELETE_LOGS_STILL_ON_NOTE = ' While Save Diagnostic Logs is on, new entries start a new log.';

export const DELETE_LOGS_FAILED_COPY = "Couldn't delete the logs. Please try again.";

const files = (n: number) => `${n} log file${n === 1 ? '' : 's'}`;

/**
 * What the notice says after `delete_logs` answered (MR-808). A failure
 * names no cause: Rust counts a file another program holds, one it may not
 * delete and a link where a folder should be alike.
 */
export function deleteLogsNotice(result: DeleteLogsResult): Omit<Notice, 'id'> {
  if (result.failed > 0) {
    const done = result.deleted > 0 ? `Deleted ${files(result.deleted)}, but ` : '';
    return {
      text: `${done}${files(result.failed)} couldn't be deleted. Please try again.`,
      tone: 'danger',
    };
  }
  if (result.deleted === 0) return { text: 'There were no logs to delete.', tone: 'info' };
  return { text: `Deleted ${files(result.deleted)}.`, tone: 'info' };
}

export function Settings() {
  const { settings, windowCorner, setWindowCorner, pushRoute, customDnsOffered, portForwardUnlocked, portForwardPlan } =
    useAppStore(
      useShallow((s) => ({
        settings: s.settings,
        windowCorner: s.windowCorner,
        setWindowCorner: s.setWindowCorner,
        pushRoute: s.pushRoute,
        customDnsOffered: customDnsAvailable(s.account.plan, s.customDnsByPlan),
        // MR-1517: the server's plan-gating table decides, the built-in one
        // where it is silent. `null` = the plan is not known yet (W2-011).
        portForwardUnlocked: planHasFeature(s.account.plan, s.planGates, 'portForwarding'),
        portForwardPlan: planName(lowestPlanWith('portForwarding', s.planGates) ?? 'SOVEREIGN'),
      })),
    );
  const appVersion = useUpdater((s) => s.appVersion);

  const [biometric, setBiometric] = useState<BiometricStatus | null>(null);
  const [biometricError, setBiometricError] = useState<string | null>(null);

  // Disabling the kill switch removes leak protection — gate it behind an
  // explicit confirmation (mobile parity). Enabling stays immediate.
  const [showKsConfirm, setShowKsConfirm] = useState(false);

  // "Delete Logs Now" asks first: it cannot be undone (MR-808).
  const [showDeleteLogs, setShowDeleteLogs] = useState(false);
  const [deletingLogs, setDeletingLogs] = useState(false);
  const deleteLogs = useCallback(async () => {
    setDeletingLogs(true);
    let notice: Omit<Notice, 'id'>;
    try {
      const result = parseDeleteLogsResult(await invoke('delete_logs'));
      notice = result ? deleteLogsNotice(result) : { text: DELETE_LOGS_FAILED_COPY, tone: 'danger' };
    } catch {
      notice = { text: DELETE_LOGS_FAILED_COPY, tone: 'danger' };
    } finally {
      setDeletingLogs(false);
      setShowDeleteLogs(false);
    }
    useAppStore.getState().showNotice(notice);
  }, []);

  // ── Speed test (on-device, through the tunnel via Rust) ───────────────────
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

  useEffect(() => {
    void loadAppVersion();
  }, []);

  useEffect(() => {
    invoke<BiometricStatus>('check_biometric_available')
      .then(setBiometric)
      .catch(() => setBiometric({ available: false, enabled: false, method: 'none' }));
  }, []);

  // ── Auto-start (OS integration via set_autostart) ──────────────────────────
  const handleAutostart = useCallback(async (value: boolean) => {
    try {
      await invoke('set_autostart', { enabled: value });
    } catch (e) {
      // An unverifiable settings file offers the reset (review of #222).
      showSaveFailure(e, "Couldn't change Launch at Login. Please try again.");
      return;
    }
    await persistSettings({ autostart: value });
  }, []);

  // ── Crash reports (opt-in; dedicated command, applied live) ────────────────
  const handleCrashReports = useCallback(async (value: boolean) => {
    const { updateSettings } = useAppStore.getState();
    updateSettings({ crashReportsEnabled: value });
    try {
      await invoke('set_crash_reports_enabled', { enabled: value });
    } catch (e) {
      // Not persisted: show the state Rust actually has, and say why.
      updateSettings({ crashReportsEnabled: !value });
      showSaveFailure(e, "Couldn't change crash reporting. Please try again.");
    }
  }, []);

  // ── Hide App Contents (the biometric cover) ─────────────────────────────
  const handleBiometric = useCallback(async (value: boolean) => {
    setBiometricError(null);
    // When enabling, confirm the user can actually authenticate first.
    if (value) {
      try {
        const ok = await invoke<boolean>('authenticate_biometric', {
          reason: 'Confirm to turn on Hide App Contents',
        });
        if (!ok) {
          setBiometricError('Verification was cancelled — Hide App Contents stays off.');
          return;
        }
      } catch {
        setBiometricError("Couldn't verify it's you. Hide App Contents stays off.");
        return;
      }
    }
    try {
      await invoke('set_biometric_enabled', { enabled: value });
      setBiometric((prev) => (prev ? { ...prev, enabled: value } : prev));
    } catch {
      setBiometricError("Couldn't save that change. Please try again.");
    }
  }, []);

  return (
    // `relative` so the kill-switch confirmation can cover the tab, and OUTSIDE
    // the scroller so it stays centred no matter how far the list is scrolled.
    <div className="relative flex h-full flex-col">
      {/* Tab-root header (no back button), as mobile's BirdoTopBar. */}
      <BirdoTopBar title="Settings" subtitle="App preferences & account" />

      {/* Transparent so the App-level PixelCanvas backdrop shows through. */}
      <div className="flex-1 overflow-y-auto">
        <div className="flex flex-col gap-3 px-5 pb-8 pt-4">
          {/* ── APPEARANCE ─────────────────────────────────────────────── */}
          <SettingsSectionHeader title="Appearance" />
          <SettingsCard padding="14px">
            <div className="mb-3 flex items-center gap-3">
              <SettingIconChip icon={Monitor} tint={brand.accent} />
              <div className="text-[14px] font-semibold" style={{ color: white.w100 }}>
                Window position
              </div>
            </div>
            <BirdoRadioGroup
              label="Window position"
              variant="segmented"
              columns={2}
              options={CORNER_OPTIONS}
              value={windowCorner}
              onChange={setWindowCorner}
            />
          </SettingsCard>

          {/* ── PRIVACY & SECURITY ─────────────────────────────────────── */}
          <SettingsSectionHeader title="Privacy & Security" />
          {/* The WFP / pf / iptables block lives in this process, so it
              protects only while the app is running, and after 10 failed
              reconnects auto_reconnect releases it unless Windows lockdown
              ("always-on") is on. The row no longer says so (owner,
              2026-10-21: no descriptions); the disable confirmation below
              still states what turning it off risks. */}
          <SettingsToggle
            icon={Shield}
            iconColor={brand.accent}
            title="Kill Switch"
            checked={settings.killSwitchEnabled}
            onCheckedChange={(v) => {
              // Enabling is immediate; disabling removes leak protection, so
              // require an explicit confirmation first (mobile parity).
              if (v) void setKillSwitch(true);
              else setShowKsConfirm(true);
            }}
          />
          {/* LOCKDOWN (D-21). Windows-only (the flag is hard false elsewhere)
              and only meaningful with the kill switch on. Persisted WITHOUT a
              live reapply: it takes effect from the next connection, so a
              toggle can never rebuild a live session's firewall state. */}
          {isWindowsPlatform() && settings.killSwitchEnabled && (
            <SettingsToggle
              icon={ShieldPlus}
              iconColor={brand.accent}
              title="Always-on Kill Switch"
              checked={settings.lockdownMode}
              onCheckedChange={(v) => void persistSettings({ lockdownMode: v })}
            />
          )}
          {/* macOS blocks ALL IPv6 for the whole connection, kill switch on
              or off (MR-1124). Not a description of a setting: a platform
              limit, shown as a note like mobile's VPN Settings note. */}
          {isMacPlatform() && <SettingsNote icon={Info}>{MACOS_IPV6_NOTE}</SettingsNote>}
          <SettingsToggle
            icon={Lock}
            iconColor={brand.accent}
            title="Quantum Protection"
            checked={settings.quantumProtection}
            onCheckedChange={(v) => void persistSettings({ quantumProtection: v }, { reapply: true })}
          />
          {/* The availability gate is on this ROW, not the section: the OS
              may have no enrolled authenticator, but everything else here
              always applies. Honest naming (iOS): it covers the screen and
              protects no data — it used to read "Biometric Unlock" under
              Security with a green icon (W2-026). */}
          {biometric?.available && (
            <>
              <SettingsToggle
                icon={EyeOff}
                iconColor={white.w60}
                title="Hide App Contents"
                checked={biometric.enabled}
                onCheckedChange={handleBiometric}
              />
              {biometricError && (
                <p role="alert" className="px-1 text-xs" style={{ color: statusTokens.red }}>
                  {biometricError}
                </p>
              )}
            </>
          )}
          {/* Crash reports are OPT-IN (audit C-3). The dedicated command
              persists the one field and applies it live in both directions. */}
          <SettingsToggle
            icon={Bug}
            iconColor={white.w60}
            title="Crash Reports"
            checked={settings.crashReportsEnabled}
            onCheckedChange={handleCrashReports}
          />
          {/* MR-808: the log kept on this device, which Crash Reports above
              (network, opt-in) is not. Saved like any setting and applied
              live by Rust, in both directions. */}
          <SettingsToggle
            icon={ScrollText}
            iconColor={white.w60}
            title="Save Diagnostic Logs"
            checked={settings.fileLoggingEnabled}
            onCheckedChange={(v) => void persistSettings({ fileLoggingEnabled: v })}
          />
          <SettingsLink
            icon={Trash2}
            iconColor={white.w60}
            title="Delete Logs Now"
            onClick={() => setShowDeleteLogs(true)}
          />

          {/* ── CONNECTION ─────────────────────────────────────────────── */}
          <SettingsSectionHeader title="Connection" />
          <SettingsToggle
            icon={Wifi}
            iconColor={statusTokens.blue}
            title="Auto-Connect"
            checked={settings.autoConnect}
            onCheckedChange={(v) => void persistSettings({ autoConnect: v })}
          />
          <SettingsToggle
            icon={Zap}
            iconColor={brand.accent}
            title="Launch at Login"
            checked={settings.autostart}
            onCheckedChange={handleAutostart}
          />
          <SettingsToggle
            icon={Minimize2}
            iconColor={white.w60}
            title="Start Minimized"
            checked={settings.startMinimized}
            onCheckedChange={(v) => void persistSettings({ startMinimized: v })}
          />

          {/* ── NOTIFICATIONS ──────────────────────────────────────────── */}
          <SettingsSectionHeader title="Notifications" />
          <SettingsToggle
            icon={Bell}
            iconColor={statusTokens.yellow}
            title="Notifications"
            checked={settings.notifications}
            onCheckedChange={(v) => void persistSettings({ notifications: v })}
          />
          {/* Both sub-toggles only shape the CONTENT of a connection
              notification, so they stay hidden while notifications are off. */}
          {settings.notifications && (
            <>
              <SettingsToggle
                icon={Globe}
                iconColor={white.w60}
                title="Show IP Address"
                checked={settings.showIpInNotification}
                onCheckedChange={(v) => void persistSettings({ showIpInNotification: v })}
              />
              <SettingsToggle
                icon={MapPin}
                iconColor={white.w60}
                title="Show Server Location"
                checked={settings.showLocationInNotification}
                onCheckedChange={(v) => void persistSettings({ showLocationInNotification: v })}
              />
            </>
          )}

          {/* ── VPN ────────────────────────────────────────────────────── */}
          <SettingsSectionHeader title="VPN" />
          <SettingsLink
            icon={SlidersHorizontal}
            iconColor={statusTokens.blue}
            title="VPN Settings"
            onClick={() => pushRoute('vpnSettings')}
          />
          {/* On every plan (owner decision D6): no lock and no upsell. Only
              an explicit `false` from the server for this plan (item 40)
              turns it off, and `useCustomDnsGate` then switches it off in
              Rust too, so the row never reads differently from the tunnel.
              The row then says why it cannot be switched on. */}
          <SettingsToggle
            icon={Server}
            iconColor={brand.accent}
            title="Custom DNS Servers"
            status={customDnsOffered ? undefined : 'Custom DNS is not available on your plan right now.'}
            enabled={customDnsOffered}
            checked={settings.customDnsEnabled && customDnsOffered}
            // Switching off keeps the addresses (P1-parity-042); it only
            // stops sending them, which is a tunnel change when any exist.
            onCheckedChange={(v) =>
              void persistSettings(
                { customDnsEnabled: v },
                { reapply: (settings.customDns ?? []).length > 0 },
              )
            }
          />
          {settings.customDnsEnabled && customDnsOffered && <CustomDnsFields />}
          {/* MR-1517: a plan without Port Forwarding sees the row locked,
              naming the plan it comes with. It still opens the screen, which
              shows the upgrade in place of the add form: rules made on a
              higher plan stay listed after a downgrade (detached, no DNAT:
              birdo-web MR-1706), and this screen is the only place a user can
              delete them. While the plan is not known yet (`null`) there is
              no lock and no upsell (W2-011). */}
          <SettingsLink
            icon={ArrowLeftRight}
            iconColor={statusTokens.blue}
            title="Port Forwarding"
            locked={portForwardUnlocked === false ? { label: portForwardPlan } : undefined}
            onClick={() => pushRoute('portForward')}
          />
          {/* Where mobile has Split Tunneling. WFP enforcement is
              Windows-only. Presented as "Kill Switch Exceptions", not "Split
              Tunneling": WFP permit filters exempt an app from the
              kill-switch block — they cannot route it outside the VPN (that
              needs a signed redirect callout driver). */}
          {isWindowsPlatform() && (
            <SettingsLink
              icon={Split}
              iconColor={white.w60}
              title="Kill Switch Exceptions"
              onClick={() => pushRoute('splitTunnel')}
            />
          )}

          {/* ── SPEED TEST ─────────────────────────────────────────────── */}
          <SettingsSectionHeader title="Speed Test" />
          <SettingsCard padding="14px">
            <div className="flex items-center gap-3">
              <SettingIconChip icon={Gauge} tint={brand.accentLight} />
              <div className="min-w-0 flex-1">
                <div className="text-[14px] font-semibold" style={{ color: white.w100 }}>
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
          </SettingsCard>

          {/* ── ABOUT ──────────────────────────────────────────────────── */}
          <SettingsSectionHeader title="About" />
          {/* Mobile's About card: the app, its version, a verified mark. */}
          <SettingsCard padding="16px">
            <div className="flex items-center gap-3.5">
              <span aria-hidden className="shrink-0">
                <AppIconMark size={44} />
              </span>
              <div className="min-w-0 flex-1">
                <div className="text-[15px] font-semibold" style={{ color: white.w100 }}>
                  BirdoVPN
                </div>
                <div className="mt-px text-xs" style={{ color: white.w60 }}>
                  Version {appVersion || '…'}
                </div>
              </div>
              <BadgeCheck size={20} color={brand.accent} aria-hidden className="shrink-0" />
            </div>
          </SettingsCard>

          <UpdateChecker />

          <SettingsLink
            icon={ShieldCheck}
            iconColor={white.w60}
            title="Privacy Policy"
            trailing="external"
            onClick={() => openExternal(PRIVACY_URL).catch(() => {})}
          />
          <SettingsLink
            icon={FileText}
            iconColor={white.w60}
            title="Terms of Service"
            trailing="external"
            onClick={() => openExternal(TERMS_URL).catch(() => {})}
          />
          <SettingsLink
            icon={LayoutDashboard}
            iconColor={white.w60}
            title="Manage on web"
            trailing="external"
            onClick={() => openExternal(DASHBOARD_URL).catch(() => {})}
          />
          {/* MR-1685: the third-party notices this package ships. */}
          <SettingsLink
            icon={Scale}
            iconColor={white.w60}
            title="Licences"
            onClick={() => pushRoute('licences')}
          />
        </div>
      </div>

      <BirdoDialog
        open={showKsConfirm}
        onClose={() => setShowKsConfirm(false)}
        title="Disable kill switch?"
        icon={Shield}
        iconColor={statusTokens.red}
      >
        <p className="text-[13px]" style={{ color: white.w60 }}>
          {KILL_SWITCH_DISABLE_BODY}
        </p>
        <div className="flex gap-2.5">
          <BirdoButton text="Cancel" variant="secondary" fullWidth onClick={() => setShowKsConfirm(false)} />
          <BirdoButton
            text="Turn off anyway"
            variant="danger"
            fullWidth
            onClick={() => {
              setShowKsConfirm(false);
              void setKillSwitch(false);
            }}
          />
        </div>
      </BirdoDialog>

      <BirdoDialog
        open={showDeleteLogs}
        onClose={() => setShowDeleteLogs(false)}
        title="Delete logs?"
        icon={Trash2}
        iconColor={statusTokens.red}
        busy={deletingLogs}
      >
        <p className="text-[13px]" style={{ color: white.w60 }}>
          {DELETE_LOGS_CONFIRM_BODY + (settings.fileLoggingEnabled ? DELETE_LOGS_STILL_ON_NOTE : '')}
        </p>
        <div className="flex gap-2.5">
          <BirdoButton
            text="Cancel"
            variant="secondary"
            fullWidth
            disabled={deletingLogs}
            onClick={() => setShowDeleteLogs(false)}
          />
          <BirdoButton
            text="Delete"
            variant="danger"
            fullWidth
            isLoading={deletingLogs}
            onClick={() => void deleteLogs()}
          />
        </div>
      </BirdoDialog>
    </div>
  );
}

/**
 * The two Custom DNS fields (W2-007). Each is local DRAFT text: typing never
 * saves, never rebuilds the tunnel, and is never overwritten from the store.
 * The pair is validated and saved when a field is left or Enter is pressed —
 * one save and at most one live reapply per edit.
 *
 * The old fields saved on every keystroke, compacted the list (an invalid
 * primary made the secondary move up into it), and mirrored the saved list
 * back into both inputs: the first Backspace in "1.1.1.1" emptied the field,
 * and a connected user got a fail-closed tunnel rebuild per pause in typing.
 */
function CustomDnsFields() {
  const saved = useAppStore((s) => s.settings.customDns);
  const lanSharing = useAppStore((s) => s.settings.localNetworkSharing);
  const [primary, setPrimary] = useState(saved?.[0] ?? '');
  const [secondary, setSecondary] = useState(saved?.[1] ?? '');
  const [errors, setErrors] = useState<{ primary: string | null; secondary: string | null }>({
    primary: null,
    secondary: null,
  });

  const commit = () => {
    const p = primary.trim();
    const sec = secondary.trim();
    const pErr = p ? isValidDnsAddress(p).error ?? null : null;
    const sErr = sec ? isValidDnsAddress(sec).error ?? null : null;
    setErrors({ primary: pErr, secondary: sErr });
    if (pErr || sErr) return;
    const list = [p, sec].filter((v) => v.length > 0);
    const next = list.length > 0 ? list : null;
    const current = useAppStore.getState().settings.customDns;
    if (JSON.stringify(next) === JSON.stringify(current ?? null)) return;
    void persistSettings({ customDns: next }, { reapply: true });
  };
  const onEnter = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') commit();
  };

  // Mobile shows the two fields as list items under the switch, each with its
  // label and placeholder only. The static helpers that sat under them (the
  // popular resolvers, the CGNAT note of MR-689) went with the owner's
  // no-descriptions rule; the warning about an address actually typed stays.
  return (
    <div className="space-y-3">
      <BirdoTextField
        label="Primary DNS"
        placeholder="e.g. 1.1.1.1"
        value={primary}
        onChange={(v) => {
          setPrimary(v);
          if (errors.primary) setErrors((e) => ({ ...e, primary: null }));
        }}
        onBlur={commit}
        onKeyDown={onEnter}
        errorText={errors.primary}
      />
      <BirdoTextField
        label="Secondary DNS (optional)"
        placeholder="e.g. 1.0.0.1"
        value={secondary}
        onChange={(v) => {
          setSecondary(v);
          if (errors.secondary) setErrors((e) => ({ ...e, secondary: null }));
        }}
        onBlur={commit}
        onKeyDown={onEnter}
        errorText={errors.secondary}
      />
      {/* REVIEW-WIN2-006: a resolver on the user's own network is reached
          outside the tunnel, and only with Local Network Sharing on. Shown
          only for an address the user typed, like a validation message. */}
      {[primary, secondary].some((v) => isPrivateDnsAddress(v.trim())) && (
        <p className="px-1 text-xs" style={{ color: white.w60 }}>
          {lanSharing
            ? 'A DNS server on your own network is reached directly, outside the VPN tunnel.'
            : 'A DNS server on your own network can be reached only with Local Network Sharing on.'}
        </p>
      )}
    </div>
  );
}
