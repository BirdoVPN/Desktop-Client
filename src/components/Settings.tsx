/**
 * Settings — the Settings TAB ROOT, mirroring iOS SettingsView / Android
 * SettingsScreen.
 *
 * Sections in the canonical order (P1-parity "Settings names and help text"):
 * Appearance (window position) · Privacy & Security (Kill Switch, Always-on
 * Kill Switch, Quantum Protection, Hide App Contents, Crash Reports, Save
 * Diagnostic Logs, Delete Logs Now) ·
 * Connection (Auto-Connect, Launch at Login, Start Minimized) · Notifications ·
 * VPN (VPN Settings, Custom DNS Servers, Port Forwarding) · Speed Test · About.
 * Every row says what it does and when it applies (W2-029).
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
  Lock,
  Zap,
  Monitor,
  SlidersHorizontal,
  Globe,
  ArrowLeftRight,
  ExternalLink,
  ShieldCheck,
  FileText,
  Info,
  Gauge,
  ArrowUpLeft,
  ArrowUpRight,
  ArrowDownLeft,
  ArrowDownRight,
  Move,
  Bug,
  ScrollText,
  Trash2,
  Scale,
} from 'lucide-react';
import { useAppStore } from '@/store/app-store';
import { isMacPlatform, isPrivateDnsAddress, isValidDnsAddress, isWindowsPlatform } from '@/utils/helpers';
import {
  BirdoCard,
  BirdoSectionHeader,
  BirdoListItem,
  BirdoToggleRow,
  BirdoNavRow,
  BirdoTextField,
  BirdoButton,
  BirdoDialog,
  BirdoRadioGroup,
  type RadioOption,
} from '@/components/birdo';
import { UpdateChecker } from './UpdateChecker';
import { brand, status as statusTokens, white } from '@/lib/birdo-theme';
import { persistSettings, setKillSwitch, showSaveFailure } from '@/session/settings-persist';
import { loadAppVersion, useUpdater } from '@/session/updater';
import { DASHBOARD_URL, PRIVACY_URL, TERMS_URL } from '@/lib/links';
import { customDnsAvailable } from '@/lib/plan';
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

const CORNER_OPTIONS: RadioOption<WindowCorner>[] = [
  { value: 'top-left', label: 'Top left', icon: ArrowUpLeft },
  { value: 'top-right', label: 'Top right', icon: ArrowUpRight },
  { value: 'bottom-left', label: 'Bottom left', icon: ArrowDownLeft },
  { value: 'bottom-right', label: 'Bottom right', icon: ArrowDownRight },
  { value: 'free', label: 'Free (draggable)', icon: Move },
];

/** iOS / Android's shared disable-confirm text (P1-parity-031). */
export const KILL_SWITCH_DISABLE_BODY =
  'If the VPN drops while the kill switch is off, your apps fall back to your normal, ' +
  'unencrypted connection and can expose your real IP address and DNS queries until it ' +
  'reconnects. For the strongest protection, keep it on.';

/** Under the Custom DNS fields (MR-689). */
export const CUSTOM_DNS_NOT_LAN_COPY =
  'A DNS server at a carrier-grade NAT address (100.64.x.x) or a public address is not ' +
  'treated as on your own network, so Local Network Sharing does not apply to it.';

/**
 * macOS only (MR-1124): the IPv6 block `tunnel_macos.rs` installs for every
 * session, kill switch on or off, until macOS routes IPv6 (the F-001 block
 * there). The wording was drafted in tunnel_macos.rs (MR-1124); it goes when
 * the block does.
 */
export const MACOS_IPV6_NOTE =
  "On macOS, IPv6 is blocked while you're connected, so your real address can't leak over it. " +
  "Sites that only work over IPv6 won't load until you disconnect.";

/**
 * MR-808: the diagnostic log kept on this device (`birdo.log` and the crash
 * files, `utils::file_log` in Rust). What it holds, how long, that the app
 * never sends it, and what "off" does and does not do. Applied live, so no
 * restart note.
 */
export const FILE_LOGGING_COPY =
  'Keeps a log of connection events, errors and crashes on this device, trimmed to the last ' +
  '7 days each time the app starts. The app never sends it. Turning this off stops new ' +
  'entries but does not delete existing logs.';

export const DELETE_LOGS_COPY = 'Deletes the diagnostic log and crash files from this device.';

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
  const { settings, windowCorner, setWindowCorner, pushRoute, connected, customDnsOffered } = useAppStore(
    useShallow((s) => ({
      settings: s.settings,
      windowCorner: s.windowCorner,
      setWindowCorner: s.setWindowCorner,
      pushRoute: s.pushRoute,
      connected: s.connectionState === 'connected',
      customDnsOffered: customDnsAvailable(s.account.plan, s.customDnsByPlan),
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
  const authName = biometric?.method === 'touch_id' ? 'Touch ID' : 'Windows Hello';
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
          <BirdoCard className="mt-1">
            <div className="mb-3 flex items-center gap-3.5">
              <div
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full"
                style={{ backgroundColor: white.w05 }}
              >
                <Monitor size={18} color={brand.accent} aria-hidden />
              </div>
              <div className="text-[15px] font-medium text-white">Window position</div>
            </div>
            <BirdoRadioGroup
              label="Window position"
              variant="segmented"
              columns={2}
              options={CORNER_OPTIONS}
              value={windowCorner}
              onChange={setWindowCorner}
            />
          </BirdoCard>

          {/* ── PRIVACY & SECURITY ─────────────────────────────────────── */}
          <BirdoSectionHeader title="Privacy & Security" className="mt-2" />
          <BirdoCard padding="0.25rem">
            {/* Copy per the 2026-09-29 audit (D-7): no "never leaks" absolute.
                The WFP / pf / iptables block lives in this process, so it
                protects only while the app is running. After 10 failed
                reconnects auto_reconnect releases the block unless Windows
                lockdown ("always-on") is on, so say so there.
                macOS blocks ALL IPv6 for the whole connection, kill switch on
                or off, so IPv6-only sites fail there. It is not this toggle's
                doing, so it is not in this subtitle: MACOS_IPV6_NOTE says it
                below, on macOS only (MR-1124). */}
            <BirdoToggleRow
              title="Kill Switch"
              subtitle={
                'If the tunnel drops unexpectedly, the app blocks traffic until it reconnects. ' +
                'Protection applies while the app is running.' +
                (!isWindowsPlatform() || !settings.lockdownMode
                  ? ' If reconnecting keeps failing, the app stops blocking.'
                  : '')
              }
              subtitleWrap
              leadingIcon={Shield}
              leadingTint={brand.accent}
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
              <BirdoToggleRow
                title="Always-on Kill Switch"
                subtitle="Keeps traffic outside the tunnel blocked for the whole session, including while reconnecting. Applies from your next connection."
                subtitleWrap
                leadingIcon={Lock}
                leadingTint={brand.accent}
                checked={settings.lockdownMode}
                onCheckedChange={(v) => void persistSettings({ lockdownMode: v })}
              />
            )}
            {isMacPlatform() && (
              <p className="px-3.5 pb-2.5 text-xs" style={{ color: white.w60 }}>
                {MACOS_IPV6_NOTE}
              </p>
            )}
            <BirdoToggleRow
              title="Quantum Protection"
              subtitle={
                'Adds a WireGuard pre-shared key derived with ML-KEM-1024 (BirdoPQ) to each connection.' +
                (connected ? ' Reconnects briefly to apply.' : '')
              }
              subtitleWrap
              leadingIcon={Lock}
              leadingTint={brand.accent}
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
                <BirdoToggleRow
                  title="Hide App Contents"
                  subtitle={
                    `Covers the screen with a ${authName} prompt when you open the app. Hides what is ` +
                    'on screen only — it protects no data, and the VPN keeps running behind it, ' +
                    'including Auto-Connect.'
                  }
                  subtitleWrap
                  leadingIcon={EyeOff}
                  leadingTint={white.w60}
                  checked={biometric.enabled}
                  onCheckedChange={handleBiometric}
                />
                {biometricError && (
                  <p role="alert" className="px-3.5 pb-2.5 text-xs" style={{ color: statusTokens.red }}>
                    {biometricError}
                  </p>
                )}
              </>
            )}
            {/* Crash reports are OPT-IN (audit C-3). The dedicated command
                persists the one field and applies it live in both directions. */}
            <BirdoToggleRow
              title="Crash Reports"
              subtitle="Off by default. When on, the app sends crash and error reports to Sentry: crashes, and errors when an app feature such as connecting fails, with the app and OS version and device model. No account details, IP address or browsing data."
              subtitleWrap
              leadingIcon={Bug}
              leadingTint={white.w60}
              checked={settings.crashReportsEnabled}
              onCheckedChange={handleCrashReports}
            />
            {/* MR-808: the log kept on this device, which Crash Reports above
                (network, opt-in) is not. Saved like any setting and applied
                live by Rust, in both directions. */}
            <BirdoToggleRow
              title="Save Diagnostic Logs"
              subtitle={FILE_LOGGING_COPY}
              subtitleWrap
              leadingIcon={ScrollText}
              leadingTint={white.w60}
              checked={settings.fileLoggingEnabled}
              onCheckedChange={(v) => void persistSettings({ fileLoggingEnabled: v })}
            />
            <BirdoListItem
              title="Delete Logs Now"
              subtitle={DELETE_LOGS_COPY}
              subtitleWrap
              leadingIcon={Trash2}
              leadingTint={white.w60}
              onClick={() => setShowDeleteLogs(true)}
            />
          </BirdoCard>

          {/* ── CONNECTION ─────────────────────────────────────────────── */}
          <BirdoSectionHeader title="Connection" className="mt-2" />
          <BirdoCard padding="0.25rem">
            <BirdoToggleRow
              title="Auto-Connect"
              subtitle="Connect to VPN on app startup."
              leadingIcon={Wifi}
              leadingTint={statusTokens.blue}
              checked={settings.autoConnect}
              onCheckedChange={(v) => void persistSettings({ autoConnect: v })}
            />
            <BirdoToggleRow
              title="Launch at Login"
              subtitle="Start BirdoVPN when you sign in to your computer."
              subtitleWrap
              leadingIcon={Zap}
              leadingTint={brand.accent}
              checked={settings.autostart}
              onCheckedChange={handleAutostart}
            />
            <BirdoToggleRow
              title="Start Minimized"
              subtitle="Open in the system tray."
              leadingIcon={Monitor}
              leadingTint={white.w60}
              checked={settings.startMinimized}
              onCheckedChange={(v) => void persistSettings({ startMinimized: v })}
            />
          </BirdoCard>

          {/* ── NOTIFICATIONS ──────────────────────────────────────────── */}
          <BirdoSectionHeader title="Notifications" className="mt-2" />
          <BirdoCard padding="0.25rem">
            <BirdoToggleRow
              title="Notifications"
              subtitle="Show connection notifications."
              leadingIcon={Bell}
              leadingTint={statusTokens.yellow}
              checked={settings.notifications}
              onCheckedChange={(v) => void persistSettings({ notifications: v })}
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
                  onCheckedChange={(v) => void persistSettings({ showIpInNotification: v })}
                />
                <BirdoToggleRow
                  title="Show Server Location"
                  leadingIcon={Bell}
                  leadingTint={white.w60}
                  checked={settings.showLocationInNotification}
                  onCheckedChange={(v) => void persistSettings({ showLocationInNotification: v })}
                />
              </>
            )}
          </BirdoCard>

          {/* ── VPN ────────────────────────────────────────────────────── */}
          <BirdoSectionHeader title="VPN" className="mt-2" />
          <BirdoCard padding="0.25rem">
            <BirdoNavRow
              title="VPN Settings"
              subtitle="Local network, port, and MTU"
              leadingIcon={SlidersHorizontal}
              leadingTint={statusTokens.blue}
              onClick={() => pushRoute('vpnSettings')}
            />
            {/* On every plan (owner decision D6): no lock and no upsell. Only
                an explicit `false` from the server for this plan (item 40)
                turns it off, and `useCustomDnsGate` then switches it off in
                Rust too, so the row never reads differently from the tunnel. */}
            <BirdoToggleRow
              title="Custom DNS Servers"
              subtitle={
                customDnsOffered
                  ? 'Use your own DNS servers instead of the VPN defaults.'
                  : 'Custom DNS is not available on your plan right now.'
              }
              subtitleWrap
              leadingIcon={Globe}
              leadingTint={brand.accent}
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
            <BirdoNavRow
              title="Port Forwarding"
              subtitle="Expose ports through your VPN tunnel."
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
                <Gauge size={18} color={brand.accentLight} aria-hidden />
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
            {/* MR-1685: the third-party notices this package ships. */}
            <BirdoNavRow
              title="Licences"
              subtitle="Third-party software notices"
              leadingIcon={Scale}
              leadingTint={brand.accentSoft}
              onClick={() => pushRoute('licences')}
            />
          </BirdoCard>

          {/* App version footer */}
          <div className="mt-3 flex items-center gap-2 px-1">
            <Info size={14} color={white.w40} aria-hidden />
            <span className="text-xs" style={{ color: white.w60 }}>
              BirdoVPN · v{appVersion || '…'}
            </span>
          </div>
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

  return (
    <div className="space-y-3 px-3.5 pb-3.5 pt-1">
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
      <p className="text-xs" style={{ color: white.w60 }}>
        Popular: 1.1.1.1 (Cloudflare), 8.8.8.8 (Google), 9.9.9.9 (Quad9). Saved when you leave a field.
      </p>
      {/* MR-689: "your own network" means the ranges Local Network Sharing
          opens, on every platform: 10/8, 172.16/12, 192.168/16 and
          link-local. A LAN numbered from carrier-grade NAT space (100.64/10)
          or a public range is not one of them, and a public-range LAN
          resolver cannot be told from an internet one, so this is said up
          front rather than per address. */}
      <p className="text-xs" style={{ color: white.w60 }}>
        {CUSTOM_DNS_NOT_LAN_COPY}
      </p>
      {/* REVIEW-WIN2-006: a resolver on the user's own network is reached
          outside the tunnel, and only with Local Network Sharing on. */}
      {[primary, secondary].some((v) => isPrivateDnsAddress(v.trim())) && (
        <p className="text-xs" style={{ color: white.w60 }}>
          {lanSharing
            ? 'A DNS server on your own network is reached directly, outside the VPN tunnel.'
            : 'A DNS server on your own network can be reached only with Local Network Sharing on.'}
        </p>
      )}
    </div>
  );
}
