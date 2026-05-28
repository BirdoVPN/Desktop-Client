/**
 * Dashboard — Connect screen mirroring mobile's HomeScreen.kt.
 *
 * Layout (replaces the previous tab-bar structure):
 *  - Full-bleed WorldGlobe background (auto-rotates when not connected)
 *  - Top bar: brand mark + email + settings + logout buttons
 *  - Floating status pill below top bar
 *  - Bottom translucent panel: stats (when connected) → kill switch alert →
 *    error banner → server selector card → compact connect button
 *  - Server picker is a modal bottom sheet (not a separate tab)
 *  - Settings opens as a full-screen slide-over
 */
import { useState, useEffect, useRef, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { useAppStore, ConnectionState } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ArrowDown,
  ArrowUp,
  Clock,
  Power,
  Settings as SettingsIcon,
  LogOut,
  Shield,
  ShieldAlert,
  ShieldOff,
  AlertTriangle,
  AlertCircle,
  ChevronRight,
  RefreshCw,
  WifiOff,
} from 'lucide-react';
import { Settings } from './Settings';
import { MultiHopCard } from './MultiHopCard';
import { SplitTunnelCard } from './SplitTunnelCard';
import { OfflineBanner } from './OfflineBanner';
import {
  BirdoBadge,
  BirdoCard,
  WorldGlobe,
  ServerSelectorSheet,
  type BadgeTone,
} from './birdo';
import {
  formatBytes,
  formatUptime,
  countryCodeToFlag,
  settingsFromRust,
  friendlyVpnError,
  type RustSettings,
} from '@/utils/helpers';
import { initNotifications, notifyConnected, notifyDisconnected } from '@/utils/notifications';
import { gradient, brand, status, white, hairline, surface } from '@/lib/birdo-theme';

interface RustVpnStats {
  bytes_in: number;
  bytes_out: number;
  packets_in: number;
  packets_out: number;
  uptime_seconds: number;
  current_latency_ms: number | null;
}

interface RustVpnStatus {
  state: string;
  bytes_sent: number;
  bytes_received: number;
  connected_at: string | null;
  server_name: string | null;
  stealthActive?: boolean;
  quantumActive?: boolean;
  pqMode?: 'disabled' | 'server_provided' | 'bilateral';
}

interface RustServer {
  id: string;
  name: string;
  country: string;
  country_code?: string;
  countryCode?: string;
  city: string;
  hostname?: string;
  ip_address?: string;
  ipAddress?: string;
  port?: number;
  load?: number;
  is_premium?: boolean;
  is_streaming?: boolean;
  is_p2p?: boolean;
  is_online?: boolean;
  accessible?: boolean;
}

export function Dashboard() {
  const [showSettings, setShowSettings] = useState(false);
  const [showServerSheet, setShowServerSheet] = useState(false);
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);
  const [liveStats, setLiveStats] = useState<RustVpnStats | null>(null);
  /** Step shown to the user during a Multi-Hop connect attempt. */
  const [mhStep, setMhStep] = useState<'idle' | 'entry' | 'forwarding' | 'exit'>('idle');
  const statsInterval = useRef<ReturnType<typeof setInterval> | null>(null);
  const mhStepTimers = useRef<ReturnType<typeof setTimeout>[]>([]);

  const {
    connectionState,
    currentServer,
    servers,
    favoriteServers,
    userEmail,
    settings,
    errorMessage,
    isAdmin,
    setConnectionState,
    setCurrentServer,
    setServers,
    setServerPing,
    toggleFavorite,
    setAccount,
    logout,
    setAuthenticated,
    hydrateSettings,
    setErrorMessage,
    setIsAdmin,
    setVpnIp,
  } = useAppStore(
    useShallow((s) => ({
      connectionState: s.connectionState,
      currentServer: s.currentServer,
      servers: s.servers,
      favoriteServers: s.favoriteServers,
      userEmail: s.userEmail,
      settings: s.settings,
      errorMessage: s.errorMessage,
      isAdmin: s.isAdmin,
      setConnectionState: s.setConnectionState,
      setCurrentServer: s.setCurrentServer,
      setServers: s.setServers,
      setServerPing: s.setServerPing,
      toggleFavorite: s.toggleFavorite,
      setAccount: s.setAccount,
      logout: s.logout,
      setAuthenticated: s.setAuthenticated,
      hydrateSettings: s.hydrateSettings,
      setErrorMessage: s.setErrorMessage,
      setIsAdmin: s.setIsAdmin,
      setVpnIp: s.setVpnIp,
    }))
  );

  const isConnected = connectionState === 'connected';
  const isConnecting =
    connectionState === 'connecting'
    || connectionState === 'reconnecting'
    || connectionState === 'rekeying'
    || connectionState === 'authenticating'
    || connectionState === 'stealth_connecting';
  const isDisconnecting = connectionState === 'disconnecting';
  const isError = connectionState === 'error';
  const isKillSwitchActive = connectionState === 'kill_switch_active';

  // ── Hydrate settings from Rust ────────────────────────────────────
  useEffect(() => {
    invoke<RustSettings>('get_settings')
      .then((rs) => hydrateSettings(settingsFromRust(rs)))
      .catch(() => { /* silent */ });
  }, [hydrateSettings]);

  // ── Admin status ──────────────────────────────────────────────────
  useEffect(() => {
    invoke<boolean>('get_admin_status')
      .then(setIsAdmin)
      .catch(() => setIsAdmin(false));
  }, [setIsAdmin]);

  // ── Account / subscription ────────────────────────────────────────
  useEffect(() => {
    invoke<{
      plan: string;
      status: string;
      expires_at: string | null;
      devices_used: number;
      devices_limit: number;
      bandwidth_used: number;
      bandwidth_limit: number | null;
    }>('get_subscription_status')
      .then((sub) => {
        setAccount({
          plan: sub.plan?.toUpperCase() || 'RECON',
          status: (['active', 'expired', 'cancelled'] as const).includes(sub.status as 'active')
            ? (sub.status as 'active' | 'expired' | 'cancelled')
            : 'unknown',
          expiresAt: sub.expires_at ?? null,
          activeDevices: sub.devices_used ?? 0,
          maxDevices: sub.devices_limit ?? 1,
          bandwidthUsed: sub.bandwidth_used ?? 0,
          bandwidthLimit: sub.bandwidth_limit ?? 0,
        });
      })
      .catch(() => { /* silent */ });
  }, [setAccount]);

  // ── Servers + ping ────────────────────────────────────────────────
  useEffect(() => {
    invoke<RustServer[]>('get_servers')
      .then(async (raw) => {
        const mapped = raw.map((s) => ({
          id: s.id,
          name: s.name,
          country: s.country,
          countryCode: s.country_code || s.countryCode || '',
          city: s.city,
          hostname: s.hostname,
          ipAddress: s.ip_address || s.ipAddress,
          port: s.port,
          load: s.load ?? 0,
          ping: undefined,
          isPremium: s.is_premium ?? false,
          isStreaming: s.is_streaming ?? false,
          isP2p: s.is_p2p ?? false,
          isOnline: s.is_online ?? true,
          isAccessible: s.accessible ?? true,
        }));
        setServers(mapped);

        const PING_BATCH = 5;
        const pingable = mapped.filter((srv) => srv.hostname || srv.ipAddress);
        for (let i = 0; i < pingable.length; i += PING_BATCH) {
          const batch = pingable.slice(i, i + PING_BATCH);
          await Promise.allSettled(
            batch.map((srv) =>
              invoke<number | null>('ping_server', {
                hostname: srv.hostname || srv.ipAddress,
                port: srv.port ?? 51820,
              }).then((p) => { if (p != null) setServerPing(srv.id, p); })
            )
          );
        }
      })
      .catch(() => { /* silent */ });
  }, [setServers, setServerPing]);

  // ── Auto-connect ──────────────────────────────────────────────────
  useEffect(() => {
    if (!settings.autoConnect) return;
    if (connectionState !== 'disconnected') return;
    const timer = setTimeout(async () => {
      const cur = useAppStore.getState();
      if (!cur.settings.autoConnect || cur.connectionState !== 'disconnected') return;
      try {
        setConnectionState('connecting');
        await invoke('quick_connect');
      } catch (err) {
        setErrorMessage(friendlyVpnError(err));
        setConnectionState('error');
      }
    }, 1500);
    return () => clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Tray events ───────────────────────────────────────────────────
  useEffect(() => {
    const unlistenConnect = listen('tray-quick-connect', async () => {
      const s = useAppStore.getState();
      if (s.connectionState !== 'disconnected') return;
      s.setConnectionState('connecting');
      try {
        await invoke('quick_connect');
      } catch (err) {
        useAppStore.getState().setErrorMessage(friendlyVpnError(err));
        useAppStore.getState().setConnectionState('error');
      }
    });
    const unlistenDisconnect = listen('tray-disconnect', async () => {
      const s = useAppStore.getState();
      if (s.connectionState !== 'connected') return;
      s.setConnectionState('disconnecting');
      try {
        await invoke('disconnect_vpn');
        const ns = useAppStore.getState();
        ns.setConnectionState('disconnected');
        ns.setCurrentServer(null);
        ns.setVpnIp(null);
      } catch (err) {
        useAppStore.getState().setErrorMessage(friendlyVpnError(err));
        useAppStore.getState().setConnectionState('error');
      }
    });
    return () => {
      unlistenConnect.then((f) => f()).catch(() => {});
      unlistenDisconnect.then((f) => f()).catch(() => {});
    };
  }, []);

  // ── Notifications ─────────────────────────────────────────────────
  useEffect(() => { initNotifications(); }, []);

  const prevConnectionState = useRef(connectionState);
  useEffect(() => {
    if (prevConnectionState.current !== connectionState) {
      if (connectionState === 'connected') {
        notifyConnected(currentServer?.name ?? 'VPN Server');
      } else if (connectionState === 'disconnected' && prevConnectionState.current === 'connected') {
        notifyDisconnected();
      }
      prevConnectionState.current = connectionState;
    }
  }, [connectionState, currentServer]);

  // ── Status polling ────────────────────────────────────────────────
  const isActive = isConnected || isConnecting;
  useEffect(() => {
    if (!isActive) {
      setLiveStats(null);
      if (statsInterval.current) {
        clearInterval(statsInterval.current);
        statsInterval.current = null;
      }
      return;
    }
    let cancelled = false;
    const poll = async () => {
      try {
        const [st, stats] = await Promise.all([
          invoke<RustVpnStatus>('get_vpn_status'),
          invoke<RustVpnStats>('get_vpn_stats'),
        ]);
        if (cancelled) return;
        const valid = new Set<string>([
          'disconnected','connecting','authenticating','stealth_connecting',
          'connected','disconnecting','reconnecting','rekeying',
          'kill_switch_active','error',
        ]);
        const cur = useAppStore.getState().connectionState;
        if (valid.has(st.state) && st.state !== cur && cur !== 'connecting' && cur !== 'disconnecting') {
          setConnectionState(st.state as ConnectionState);
        }
        if (st.state === 'connected' || st.state === 'rekeying') {
          setLiveStats(stats);
        }
      } catch { /* silent */ }
    };
    poll();
    statsInterval.current = setInterval(poll, 2000);
    return () => {
      cancelled = true;
      if (statsInterval.current) clearInterval(statsInterval.current);
    };
  }, [isActive, setConnectionState]);

  // ── Handlers ──────────────────────────────────────────────────────
  const handleConnect = useCallback(async () => {
    if (isConnecting || isDisconnecting) return;

    if (isKillSwitchActive || isConnected) {
      setConnectionState('disconnecting');
      setErrorMessage(null);
      try {
        await invoke('disconnect_vpn');
        setConnectionState('disconnected');
        setCurrentServer(null);
        setVpnIp(null);
      } catch (err) {
        setErrorMessage(friendlyVpnError(err));
        setConnectionState('error');
      }
      return;
    }

    // Multi-hop
    if (settings.multiHopEnabled && settings.multiHopEntryNodeId && settings.multiHopExitNodeId) {
      const entry = servers.find((s) => s.id === settings.multiHopEntryNodeId);
      const exit = servers.find((s) => s.id === settings.multiHopExitNodeId);
      setConnectionState('connecting');
      setCurrentServer(entry || null);
      setErrorMessage(null);

      // Drive the visible step indicator. The Rust call is monolithic so we
      // approximate progress with timers; if the call resolves earlier the
      // final state will overwrite these.
      mhStepTimers.current.forEach(clearTimeout);
      mhStepTimers.current = [];
      setMhStep('entry');
      mhStepTimers.current.push(setTimeout(() => setMhStep('forwarding'), 1800));
      mhStepTimers.current.push(setTimeout(() => setMhStep('exit'), 3600));

      try {
        await invoke<boolean>('connect_multi_hop', {
          entryNodeId: settings.multiHopEntryNodeId,
          exitNodeId: settings.multiHopExitNodeId,
        });
        mhStepTimers.current.forEach(clearTimeout);
        mhStepTimers.current = [];
        setMhStep('idle');
        setConnectionState('connected');
        // Surface the route in the current-server label.
        if (entry && exit) {
          setCurrentServer({
            ...entry,
            name: `${entry.city || entry.country} \u2192 ${exit.city || exit.country}`,
          });
        }
      } catch (err) {
        mhStepTimers.current.forEach(clearTimeout);
        mhStepTimers.current = [];
        setMhStep('idle');
        setErrorMessage(friendlyVpnError(err));
        setConnectionState('error');
        setCurrentServer(null);
        setVpnIp(null);
      }
      return;
    }

    const target = (currentServer?.isOnline && currentServer.isAccessible)
      ? currentServer
      : servers.find((s) => s.isOnline && s.isAccessible);
    if (!target) {
      setErrorMessage('No accessible online servers are available for this account.');
      return;
    }

    setConnectionState('connecting');
    setCurrentServer(target);
    setErrorMessage(null);
    try {
      await invoke<boolean>('connect_vpn', { serverId: target.id });
      setConnectionState('connected');
    } catch (err) {
      setErrorMessage(friendlyVpnError(err));
      setConnectionState('error');
      setCurrentServer(null);
      setVpnIp(null);
    }
  }, [
    isConnecting, isDisconnecting, isConnected, isKillSwitchActive,
    settings.multiHopEnabled, settings.multiHopEntryNodeId, settings.multiHopExitNodeId,
    servers, currentServer,
    setConnectionState, setCurrentServer, setErrorMessage, setVpnIp,
  ]);

  const handleLogout = useCallback(async () => {
    const cur = useAppStore.getState().connectionState;
    if (cur === 'connected' || cur === 'connecting' || cur === 'reconnecting') {
      try { await invoke('disconnect_vpn'); } catch { /* best effort */ }
    }
    try { await invoke('logout'); } catch { /* best effort */ }
    logout();
    setAuthenticated(false);
    setShowLogoutConfirm(false);
  }, [logout, setAuthenticated]);

  // ── Status pill props ─────────────────────────────────────────────
  const pill = statusPill({ isConnected, isConnecting, isDisconnecting, isError });

  return (
    <div className="relative h-full overflow-hidden" style={{ backgroundColor: surface.s0 }}>
      {/* Drag region */}
      <div data-tauri-drag-region className="absolute inset-x-0 top-0 z-50 h-8" />

      {/* Globe background — hidden while server sheet open to avoid flicker */}
      {!showServerSheet && (
        <WorldGlobe
          servers={servers}
          selectedServerId={currentServer?.id ?? null}
          isConnected={isConnected}
          autoRotate
        />
      )}

      {/* Offline banner */}
      <div className="relative z-30">
        <OfflineBanner />
      </div>

      {/* Top bar */}
      <div
        className="relative z-20 flex items-center gap-2 px-4 pt-9 pb-2"
        style={{ backgroundColor: 'rgba(11,11,16,0.55)', backdropFilter: 'blur(8px)' }}
      >
        <BrandLockup />
        <div className="flex-1" />
        {userEmail && (
          <span
            className="max-w-[140px] truncate text-xs"
            style={{ color: white.w40 }}
          >
            {userEmail}
          </span>
        )}
        <IconButton
          icon={SettingsIcon}
          ariaLabel="Settings"
          onClick={() => setShowSettings(true)}
        />
        <IconButton
          icon={LogOut}
          ariaLabel="Log out"
          onClick={() => setShowLogoutConfirm(true)}
        />
      </div>

      {/* Status pill */}
      <div className="relative z-10 mt-3 flex justify-center">
        <BirdoBadge
          text={pill.text}
          tone={pill.tone}
          icon={pill.icon}
          pulseDot={pill.pulse}
        />
      </div>

      {/* Spacer to push panel to bottom */}
      <div className="absolute inset-0 flex flex-col pointer-events-none">
        <div className="flex-1" />
        {/* Bottom panel */}
        <div
          className="pointer-events-auto rounded-t-3xl px-5 pt-4 pb-4"
          style={{
            backgroundColor: 'rgba(11,11,16,0.92)',
            borderTop: `1px solid ${hairline.soft}`,
            backdropFilter: 'blur(12px)',
          }}
        >
          {/* Stats (connected) */}
          <AnimatePresence>
            {isConnected && (
              <motion.div
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.24, delay: 0.08 }}
              >
                <StatsRow stats={liveStats} />
                <div className="h-2.5" />
              </motion.div>
            )}
          </AnimatePresence>

          {/* Admin warning */}
          {!isAdmin && (
            <>
              <BannerRow
                icon={ShieldAlert}
                color="#FBBF24"
                bg="rgba(245,158,11,0.10)"
                border="rgba(245,158,11,0.30)"
                text="Not running as administrator — VPN cannot connect."
              />
              <div className="h-2.5" />
            </>
          )}

          {/* Kill switch alert */}
          {isKillSwitchActive && (
            <>
              <BannerRow
                icon={ShieldOff}
                color={status.red}
                bg={status.redBg}
                border="rgba(248,113,113,0.30)"
                text="Kill switch is blocking all traffic"
              />
              <div className="h-2.5" />
            </>
          )}

          {/* Error */}
          {isError && errorMessage && (
            <>
              <BannerRow
                icon={AlertCircle}
                color={status.red}
                bg={status.redBg}
                border="rgba(248,113,113,0.30)"
                text={errorMessage}
              />
              <div className="h-2.5" />
            </>
          )}

          {/* Multi-Hop progress banner */}
          {isConnecting && settings.multiHopEnabled && mhStep !== 'idle' && (
            <>
              <MultiHopProgressBanner step={mhStep} />
              <div className="h-2.5" />
            </>
          )}

          {/* Split tunneling applies to the next VPN session. */}
          <SplitTunnelCard busy={isConnecting || isDisconnecting} />
          <div className="h-2.5" />

          {/* Multi-Hop selector card (Sovereign-only; clicking when not Sovereign opens an upgrade modal) */}
          <MultiHopCard busy={isConnecting || isDisconnecting} />
          <div className="h-2.5" />

          {/* Server selector */}
          <ServerSelectorCard
            server={currentServer}
            disabled={isConnecting || isDisconnecting}
            onClick={() => {
              if (servers.length > 0) setShowServerSheet(true);
            }}
          />
          <div className="h-2.5" />

          {/* Compact connect button */}
          <CompactConnectButton
            isConnected={isConnected}
            isConnecting={isConnecting}
            isDisconnecting={isDisconnecting}
            onClick={handleConnect}
          />
        </div>
      </div>

      {/* Server selector sheet */}
      <ServerSelectorSheet
        open={showServerSheet}
        servers={servers}
        selectedServerId={currentServer?.id ?? null}
        favoriteServers={favoriteServers}
        onSelect={(s) => setCurrentServer(s)}
        onToggleFavorite={(id) => toggleFavorite(id)}
        onDismiss={() => setShowServerSheet(false)}
      />

      {/* Settings slide-over */}
      <AnimatePresence>
        {showSettings && (
          <motion.div
            className="absolute inset-0 z-40 overflow-y-auto"
            style={{ backgroundColor: surface.s0 }}
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 28, stiffness: 280 }}
          >
            <SettingsHeader onBack={() => setShowSettings(false)} />
            <Settings />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Logout confirm modal */}
      <AnimatePresence>
        {showLogoutConfirm && (
          <motion.div
            className="absolute inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <motion.div
              className="mx-6 w-full max-w-sm rounded-2xl p-6 text-center"
              style={{
                backgroundColor: surface.s2,
                border: `1px solid ${hairline.soft}`,
              }}
              initial={{ scale: 0.92, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.92, opacity: 0 }}
            >
              <AlertTriangle
                size={36}
                color={status.yellowLight}
                className="mx-auto mb-3"
              />
              <h3 className="mb-2 text-lg font-semibold" style={{ color: white.w100 }}>
                Log Out?
              </h3>
              <p className="mb-5 text-sm" style={{ color: white.w60 }}>
                {isConnected
                  ? 'You are still connected. Logging out will disconnect.'
                  : 'Are you sure you want to log out?'}
              </p>
              <div className="flex gap-3">
                <button
                  type="button"
                  onClick={() => setShowLogoutConfirm(false)}
                  className="flex-1 rounded-xl py-2.5 text-sm font-medium transition-colors hover:bg-white/10"
                  style={{
                    backgroundColor: white.w05,
                    color: white.w100,
                    border: `1px solid ${hairline.soft}`,
                  }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleLogout}
                  className="flex-1 rounded-xl py-2.5 text-sm font-medium transition-colors hover:bg-red-500/30"
                  style={{
                    backgroundColor: 'rgba(248,113,113,0.18)',
                    color: status.red,
                    border: '1px solid rgba(248,113,113,0.30)',
                  }}
                >
                  Log Out
                </button>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────

function statusPill(args: {
  isConnected: boolean;
  isConnecting: boolean;
  isDisconnecting: boolean;
  isError: boolean;
}): { text: string; tone: BadgeTone; icon?: typeof SettingsIcon; pulse: boolean } {
  if (args.isConnected) return { text: 'Protected', tone: 'success', pulse: true };
  if (args.isConnecting) return { text: 'Connecting...', tone: 'warning', icon: RefreshCw, pulse: false };
  if (args.isDisconnecting) return { text: 'Disconnecting...', tone: 'warning', icon: RefreshCw, pulse: false };
  if (args.isError) return { text: 'Connection Error', tone: 'danger', icon: AlertCircle, pulse: false };
  return { text: 'Not Connected', tone: 'neutral', icon: WifiOff, pulse: false };
}

function BrandLockup() {
  return (
    <div className="flex items-center gap-2.5">
      <div
        className="flex h-8 w-8 items-center justify-center rounded-[10px]"
        style={{ background: gradient.primary }}
      >
        <Shield size={18} color="#FFFFFF" />
      </div>
      <span className="text-base font-semibold" style={{ color: white.w100 }}>
        BirdoVPN
      </span>
    </div>
  );
}

interface IconButtonProps {
  icon: typeof SettingsIcon;
  ariaLabel: string;
  onClick: () => void;
}

function IconButton({ icon: Icon, ariaLabel, onClick }: IconButtonProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={ariaLabel}
      className="flex h-9 w-9 items-center justify-center rounded-full transition-colors hover:bg-white/10"
    >
      <Icon size={18} color={white.w60} />
    </button>
  );
}

interface BannerRowProps {
  icon: typeof Shield;
  color: string;
  bg: string;
  border: string;
  text: string;
}

function BannerRow({ icon: Icon, color, bg, border, text }: BannerRowProps) {
  return (
    <div
      className="flex items-center gap-2.5 rounded-2xl px-3.5 py-3"
      style={{ backgroundColor: bg, border: `1px solid ${border}` }}
    >
      <Icon size={18} color={color} className="shrink-0" />
      <p className="flex-1 text-xs leading-tight" style={{ color }}>
        {text}
      </p>
    </div>
  );
}

// ── Multi-Hop progress banner ────────────────────────────────────────
interface MultiHopProgressBannerProps {
  step: 'idle' | 'entry' | 'forwarding' | 'exit';
}

function MultiHopProgressBanner({ step }: MultiHopProgressBannerProps) {
  const steps: Array<{ key: 'entry' | 'forwarding' | 'exit'; label: string }> = [
    { key: 'entry', label: 'Entry' },
    { key: 'forwarding', label: 'Forwarding' },
    { key: 'exit', label: 'Exit' },
  ];
  const stepIdx = steps.findIndex((s) => s.key === step);
  const currentLabel =
    step === 'entry'
      ? 'Establishing entry tunnel\u2026'
      : step === 'forwarding'
      ? 'Setting up multi-hop forwarding\u2026'
      : step === 'exit'
      ? 'Routing through exit server\u2026'
      : '';

  return (
    <div
      className="rounded-2xl px-3.5 py-3"
      style={{
        backgroundColor: 'rgba(168,85,247,0.08)',
        border: '1px solid rgba(168,85,247,0.30)',
      }}
    >
      <div className="mb-2 flex items-center gap-2">
        <RefreshCw size={14} color="#A855F7" className="animate-spin" />
        <p className="flex-1 text-xs font-medium" style={{ color: '#C4B5FD' }}>
          {currentLabel}
        </p>
      </div>
      <div className="flex items-center gap-1.5">
        {steps.map((s, i) => (
          <div key={s.key} className="flex flex-1 items-center gap-1.5">
            <div
              className="h-1 flex-1 rounded-full transition-all"
              style={{
                backgroundColor: i <= stepIdx ? '#A855F7' : 'rgba(255,255,255,0.10)',
              }}
            />
          </div>
        ))}
      </div>
      <div className="mt-1 flex justify-between text-[10px] uppercase tracking-wide" style={{ color: 'rgba(255,255,255,0.40)' }}>
        {steps.map((s, i) => (
          <span
            key={s.key}
            style={{
              color: i <= stepIdx ? '#C4B5FD' : 'rgba(255,255,255,0.40)',
              fontWeight: i === stepIdx ? 600 : 400,
            }}
          >
            {s.label}
          </span>
        ))}
      </div>
    </div>
  );
}


interface StatsRowProps {
  stats: RustVpnStats | null;
}

function StatsRow({ stats }: StatsRowProps) {
  return (
    <div className="grid grid-cols-3 gap-2">
      <StatTile
        icon={Clock}
        tint={brand.purpleSoft}
        label="Duration"
        value={stats ? formatUptime(stats.uptime_seconds) : '—'}
      />
      <StatTile
        icon={ArrowDown}
        tint={status.greenLight}
        label="Down"
        value={stats ? formatBytes(stats.bytes_in) : '—'}
      />
      <StatTile
        icon={ArrowUp}
        tint={status.blue}
        label="Up"
        value={stats ? formatBytes(stats.bytes_out) : '—'}
      />
    </div>
  );
}

interface StatTileProps {
  icon: typeof Clock;
  tint: string;
  label: string;
  value: string;
}

function StatTile({ icon: Icon, tint, label, value }: StatTileProps) {
  return (
    <BirdoCard cornerRadius={12} padding="0.5rem 0.5rem">
      <div className="flex items-center justify-center gap-1.5">
        <Icon size={14} color={tint} aria-label={label} />
        <span
          className="truncate text-xs font-semibold"
          style={{ color: white.w100 }}
        >
          {value}
        </span>
      </div>
    </BirdoCard>
  );
}

interface ServerSelectorCardProps {
  server: { city: string; country: string; countryCode: string } | null;
  disabled: boolean;
  onClick: () => void;
}

function ServerSelectorCard({ server, disabled, onClick }: ServerSelectorCardProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="w-full text-left transition-opacity disabled:opacity-50"
    >
      <BirdoCard cornerRadius={16} padding="0.875rem">
        <div className="flex items-center gap-3">
          <span
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-base"
            style={{ backgroundColor: white.w10 }}
          >
            {server ? countryCodeToFlag(server.countryCode) : '🌐'}
          </span>
          <div className="min-w-0 flex-1">
            <div
              className="truncate text-sm font-semibold"
              style={{ color: white.w100 }}
            >
              {server ? server.city : 'Choose a server'}
            </div>
            <div className="truncate text-xs" style={{ color: white.w60 }}>
              {server ? server.country : 'Tap to browse locations'}
            </div>
          </div>
          <ChevronRight size={18} color={white.w40} />
        </div>
      </BirdoCard>
    </button>
  );
}

interface CompactConnectButtonProps {
  isConnected: boolean;
  isConnecting: boolean;
  isDisconnecting: boolean;
  onClick: () => void;
}

function CompactConnectButton({
  isConnected,
  isConnecting,
  isDisconnecting,
  onClick,
}: CompactConnectButtonProps) {
  const busy = isConnecting || isDisconnecting;
  const bgImage =
    isConnected ? gradient.connectGreen
    : busy ? gradient.connectBusy
    : gradient.connectIdle;
  const label =
    isConnected ? 'Disconnect'
    : isConnecting ? 'Connecting...'
    : isDisconnecting ? 'Disconnecting...'
    : 'Connect';
  const shadowColor =
    isConnected ? 'rgba(34,197,94,0.45)' : 'rgba(168,85,247,0.45)';

  return (
    <motion.button
      type="button"
      onClick={onClick}
      disabled={busy}
      aria-label={label}
      whileTap={!busy ? { scale: 0.98 } : undefined}
      className="relative flex h-[60px] w-full items-center justify-center gap-2.5 rounded-2xl transition-opacity disabled:cursor-not-allowed"
      style={{
        backgroundImage: bgImage,
        border: `1px solid ${hairline.strong}`,
        boxShadow: `0 14px 32px -10px ${shadowColor}`,
        opacity: busy ? 0.85 : 1,
      }}
    >
      {busy ? (
        <span
          className="h-[20px] w-[20px] animate-spin rounded-full border-2 border-white/30 border-t-white"
          aria-hidden
        />
      ) : (
        <Power size={22} color="#FFFFFF" aria-hidden />
      )}
      <span className="text-base font-semibold text-white">{label}</span>
    </motion.button>
  );
}

interface SettingsHeaderProps { onBack: () => void; }
function SettingsHeader({ onBack }: SettingsHeaderProps) {
  return (
    <div
      className="sticky top-0 z-10 flex items-center gap-2 px-4 pt-9 pb-3"
      style={{
        backgroundColor: 'rgba(11,11,16,0.95)',
        borderBottom: `1px solid ${hairline.soft}`,
        backdropFilter: 'blur(8px)',
      }}
    >
      <button
        type="button"
        onClick={onBack}
        aria-label="Back"
        className="flex h-9 w-9 items-center justify-center rounded-full transition-colors hover:bg-white/10"
        style={{ color: white.w80 }}
      >
        <ChevronRight size={20} className="rotate-180" />
      </button>
      <h1 className="text-lg font-semibold" style={{ color: white.w100 }}>
        Settings
      </h1>
    </div>
  );
}
