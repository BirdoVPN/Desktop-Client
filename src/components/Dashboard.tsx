/**
 * Dashboard — Connect screen mirroring mobile's HomeScreen.kt.
 *
 * Layout:
 *  - Full-bleed WorldGlobe background (auto-rotates when not connected)
 *  - HomeTopBar: multi-hop toggle (left) + brand mark + email + logout (right)
 *  - Floating <StatusPill/> below the top bar
 *  - Bottom translucent rounded-t-[24px] panel: stats (when connected) →
 *    admin banner → error banner → server selector (single, or Entry/Exit pair
 *    when multi-hop is armed) → compact connect button
 *  - Server picker is a modal bottom sheet (not a separate tab)
 *  - Settings is now a bottom-nav tab (no in-file slide-over)
 *
 * Connection logic (polling, handleConnect, tray listeners, handleLogout) is
 * preserved byte-for-behavior from the previous revision.
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
  LogOut,
  ShieldAlert,
  ShieldOff,
  AlertTriangle,
  AlertCircle,
  ChevronRight,
  Route as AltRoute,
  Lock,
  EyeOff,
} from 'lucide-react';
import {
  BirdoCard,
  BirdoIconAction,
  CompactConnectButton,
  StatusPill,
  WorldGlobe,
  ServerSelectorSheet,
  type ConnectButtonState,
} from './birdo';
import type { Server } from '@/store/app-store';
import {
  formatBytes,
  formatUptime,
  countryCodeToFlag,
  settingsFromRust,
  settingsToRust,
  friendlyVpnError,
  type RustSettings,
} from '@/utils/helpers';
import {
  initNotifications,
  notifyConnected,
  notifyDisconnected,
  notifyReconnected,
  notifyConnectionLost,
  notifyKillSwitchActive,
} from '@/utils/notifications';
import { brand, status, white, hairline, surface } from '@/lib/birdo-theme';

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

/** Which hop the multi-hop server sheet is currently picking. */
type MultiHopTarget = 'entry' | 'exit';

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

export function Dashboard() {
  const [showServerSheet, setShowServerSheet] = useState(false);
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);
  const [liveStats, setLiveStats] = useState<RustVpnStats | null>(null);
  // Live security posture from get_vpn_status — surfaced as chips under the
  // status pill so the user can SEE that stealth / post-quantum are actually
  // engaged on the tunnel (not just toggled in settings).
  const [liveSecurity, setLiveSecurity] = useState<{ stealth: boolean }>({
    stealth: false,
  });
  /** Which hop the multi-hop picker sheet is editing (null = closed). */
  const [multiHopPickerTarget, setMultiHopPickerTarget] = useState<MultiHopTarget | null>(null);
  /** Transient toast shown when a locked feature is tapped. */
  const [toast, setToast] = useState<string | null>(null);
  const statsInterval = useRef<ReturnType<typeof setInterval> | null>(null);
  const toastTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const {
    connectionState,
    currentServer,
    servers,
    favoriteServers,
    userEmail,
    settings,
    account,
    errorMessage,
    isAdmin,
    setConnectionState,
    setCurrentServer,
    setServers,
    setServerPing,
    toggleFavorite,
    setAccount,
    updateSettings,
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
      account: s.account,
      errorMessage: s.errorMessage,
      isAdmin: s.isAdmin,
      setConnectionState: s.setConnectionState,
      setCurrentServer: s.setCurrentServer,
      setServers: s.setServers,
      setServerPing: s.setServerPing,
      toggleFavorite: s.toggleFavorite,
      setAccount: s.setAccount,
      updateSettings: s.updateSettings,
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

  // ── Multi-Hop arm state (mirrors mobile's top-bar toggle) ─────────────
  // The arm + entry/exit selection live in `settings` so they survive a
  // restart and ride the existing `save_settings` full-object persistence.
  const isSovereign = planLevel(account?.plan) >= 2;
  const multiHopArmed = settings.multiHopEnabled;
  const entryServer = servers.find((s) => s.id === settings.multiHopEntryNodeId) || null;
  const exitServer = servers.find((s) => s.id === settings.multiHopExitNodeId) || null;
  const sameServer = !!(entryServer && exitServer && entryServer.id === exitServer.id);
  const multiHopReady = !!(multiHopArmed && entryServer && exitServer && !sameServer);
  const multiHopBlocked = multiHopArmed && !multiHopReady && !isConnected;

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
          // Backend no longer reports bandwidth usage (always 0).
          bandwidthUsed: 0,
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
    const prev = prevConnectionState.current;
    if (prev !== connectionState) {
      const serverName = currentServer?.name ?? 'VPN Server';
      const details = {
        ip: currentServer?.ipAddress ?? null,
        location: currentServer
          ? [currentServer.city, currentServer.country].filter(Boolean).join(', ')
          : null,
      };
      if (connectionState === 'connected') {
        // Distinguish a fresh connect from recovery after a drop so the toast
        // copy matches what actually happened.
        if (prev === 'reconnecting' || prev === 'rekeying') {
          notifyReconnected(serverName, details);
        } else {
          notifyConnected(serverName, details);
        }
      } else if (connectionState === 'disconnected' && prev === 'connected') {
        notifyDisconnected();
      } else if (connectionState === 'reconnecting' && prev === 'connected') {
        notifyConnectionLost();
      } else if (connectionState === 'kill_switch_active') {
        notifyKillSwitchActive();
      }
      prevConnectionState.current = connectionState;
    }
  }, [connectionState, currentServer]);

  // ── Status polling ────────────────────────────────────────────────
  const isActive = isConnected || isConnecting;
  useEffect(() => {
    if (!isActive) {
      setLiveStats(null);
      setLiveSecurity({ stealth: false });
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
          setLiveSecurity({ stealth: !!st.stealthActive });
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

  // ── Toast auto-dismiss ────────────────────────────────────────────
  useEffect(() => {
    return () => { if (toastTimer.current) clearTimeout(toastTimer.current); };
  }, []);
  const showToast = useCallback((msg: string) => {
    setToast(msg);
    if (toastTimer.current) clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 3200);
  }, []);

  // ── Settings persistence (full-object save_settings path) ─────────
  // Mirrors the previous MultiHopCard.persist: patch Zustand, then push the
  // FULL settings object to Rust via the unchanged invoke contract.
  const persistSettings = useCallback(
    async (patch: Partial<typeof settings>) => {
      const next = { ...useAppStore.getState().settings, ...patch };
      updateSettings(patch);
      try {
        await invoke('save_settings', { settings: settingsToRust(next) });
      } catch {
        /* Rust will log */
      }
    },
    [updateSettings]
  );

  // ── Handlers ──────────────────────────────────────────────────────
  const handleToggleMultiHop = useCallback(() => {
    if (isConnecting || isDisconnecting) return;
    if (!isSovereign) {
      showToast('Multi-Hop is a SOVEREIGN feature. Upgrade to enable.');
      return;
    }
    if (multiHopArmed) {
      // Disarm: clear the route so the single selector returns clean.
      persistSettings({
        multiHopEnabled: false,
        multiHopEntryNodeId: null,
        multiHopExitNodeId: null,
      });
    } else {
      persistSettings({ multiHopEnabled: true });
    }
  }, [isConnecting, isDisconnecting, isSovereign, multiHopArmed, persistSettings, showToast]);

  const handlePickMultiHopServer = useCallback(
    (server: Server) => {
      if (multiHopPickerTarget === 'entry') {
        persistSettings({ multiHopEntryNodeId: server.id });
      } else if (multiHopPickerTarget === 'exit') {
        persistSettings({ multiHopExitNodeId: server.id });
      }
      setMultiHopPickerTarget(null);
    },
    [multiHopPickerTarget, persistSettings]
  );

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
      // Defense-in-depth: never invoke a multi-hop connect with identical
      // entry/exit (the UI already blocks this via multiHopBlocked, but guard
      // here too so no future caller can send an invalid route to Rust).
      if (settings.multiHopEntryNodeId === settings.multiHopExitNodeId) {
        setErrorMessage('Entry and exit must be different servers.');
        return;
      }
      const entry = servers.find((s) => s.id === settings.multiHopEntryNodeId);
      const exit = servers.find((s) => s.id === settings.multiHopExitNodeId);
      setConnectionState('connecting');
      setCurrentServer(entry || null);
      setErrorMessage(null);

      try {
        await invoke<boolean>('connect_multi_hop', {
          entryNodeId: settings.multiHopEntryNodeId,
          exitNodeId: settings.multiHopExitNodeId,
        });
        setConnectionState('connected');
        // Surface the route in the current-server label.
        if (entry && exit) {
          setCurrentServer({
            ...entry,
            name: `${entry.city || entry.country} → ${exit.city || exit.country}`,
          });
        }
      } catch (err) {
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

  // Picking a server from the sheet. When already on the tunnel this performs a
  // real SWITCH, not just a label change: connect_vpn to the new node, which (in
  // Rust) tears down the old tunnel and brings up a FRESH session with new
  // WireGuard keys, while the always-on WFP kill switch stays armed across the
  // gap — so traffic is fully blocked until the new tunnel is up (no leak).
  const handleSelectServer = useCallback(
    async (s: Server) => {
      const prev = useAppStore.getState().currentServer;
      const st = useAppStore.getState().connectionState;
      const onTunnel =
        st === 'connected' ||
        st === 'reconnecting' ||
        st === 'rekeying' ||
        st === 'kill_switch_active';

      setCurrentServer(s);

      // Not connected, or re-picking the node we're already on → just selection.
      if (!onTunnel || prev?.id === s.id) return;

      if (!s.isOnline || !s.isAccessible) {
        setErrorMessage('That server is offline or not included in your plan.');
        return;
      }

      setConnectionState('connecting');
      setErrorMessage(null);
      setVpnIp(null);
      try {
        await invoke<boolean>('connect_vpn', { serverId: s.id });
        setConnectionState('connected');
      } catch (err) {
        setErrorMessage(friendlyVpnError(err));
        setConnectionState('error');
        setCurrentServer(null);
      }
    },
    [setCurrentServer, setConnectionState, setErrorMessage, setVpnIp],
  );

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

  // ── Connect button state/label derivation ─────────────────────────
  const busy = isConnecting || isDisconnecting;
  const connectState: ConnectButtonState =
    isConnected ? 'connected'
    : busy ? 'busy'
    : multiHopReady ? 'multiHopReady'
    : multiHopBlocked ? 'multiHopBlocked'
    : 'idle';
  const connectLabel =
    isConnected ? 'Disconnect'
    : isConnecting ? 'Connecting…'
    : isDisconnecting ? 'Disconnecting…'
    : multiHopBlocked ? 'Choose entry & exit'
    : multiHopReady ? 'Connect Multi-Hop'
    : 'Connect';
  // When multi-hop is armed but not fully configured, the button is inert.
  const handleConnectClick = useCallback(() => {
    if (multiHopBlocked) return;
    handleConnect();
  }, [multiHopBlocked, handleConnect]);

  return (
    // Transparent root so the App-level PixelCanvas backdrop shows through
    // behind/around the globe (matches the Profile / Settings tab roots — an
    // opaque surface.s0 here was hiding the animated pixel grid).
    <div className="relative h-full overflow-hidden">
      {/* Globe background — hidden while server sheet open to avoid flicker */}
      {!showServerSheet && multiHopPickerTarget === null && (
        <WorldGlobe
          servers={servers}
          selectedServerId={currentServer?.id ?? null}
          isConnected={isConnected}
          autoRotate
        />
      )}

      {/* Top bar */}
      <HomeTopBar
        userEmail={userEmail}
        multiHopArmed={multiHopArmed}
        multiHopUnlocked={isSovereign}
        onToggleMultiHop={handleToggleMultiHop}
        onLogout={() => setShowLogoutConfirm(true)}
      />

      {/* Status pill */}
      <div className="relative z-10 mt-3 flex justify-center">
        <StatusPill state={connectionState} />
      </div>

      {/* Live security chip — Stealth only. (Post-Quantum chip removed per
          owner request; PQ is still on by default, just not badged here.) */}
      <AnimatePresence>
        {isConnected && liveSecurity.stealth && (
          <motion.div
            className="relative z-10 mt-2 flex justify-center gap-2"
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            <SecurityChip icon={EyeOff} label="Stealth" />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Spacer to push panel to bottom */}
      <div className="absolute inset-0 flex flex-col pointer-events-none">
        <div className="flex-1" />
        {/* Bottom panel */}
        <div
          className="pointer-events-auto rounded-t-[24px] px-5 pt-4 pb-4"
          style={{
            // Near-opaque fill instead of backdrop-filter blur — the blur
            // shader smears the repainting globe canvas into vertical streaks
            // on WebView2 GPUs (the "lines stretching" artifact).
            backgroundColor: 'rgba(11,11,16,0.97)',
            borderTop: `1px solid ${hairline.soft}`,
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

          {/* Server selector — single, or Entry/Exit pair when multi-hop armed */}
          {multiHopArmed ? (
            <MultiHopServerPair
              entry={entryServer}
              exit={exitServer}
              sameServer={sameServer}
              disabled={busy}
              onPickEntry={() => setMultiHopPickerTarget('entry')}
              onPickExit={() => setMultiHopPickerTarget('exit')}
            />
          ) : (
            <ServerSelectorCard
              server={currentServer}
              disabled={busy}
              onClick={() => {
                if (servers.length > 0) setShowServerSheet(true);
              }}
            />
          )}
          <div className="h-2.5" />

          {/* Compact connect button */}
          <CompactConnectButton
            state={connectState}
            label={connectLabel}
            busy={busy}
            onClick={handleConnectClick}
          />
        </div>
      </div>

      {/* Toast / snackbar (locked-feature notice) */}
      <AnimatePresence>
        {toast && (
          <motion.div
            className="pointer-events-none absolute inset-x-0 bottom-6 z-50 flex justify-center px-6"
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 16 }}
          >
            <div
              className="max-w-sm rounded-2xl px-4 py-3 text-center text-xs font-medium shadow-lg"
              style={{
                backgroundColor: surface.s3,
                border: `1px solid ${hairline.soft}`,
                color: white.w100,
              }}
            >
              {toast}
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Server selector sheet (single-hop) */}
      <ServerSelectorSheet
        open={showServerSheet}
        servers={servers}
        selectedServerId={currentServer?.id ?? null}
        favoriteServers={favoriteServers}
        onSelect={handleSelectServer}
        onToggleFavorite={(id) => toggleFavorite(id)}
        onDismiss={() => setShowServerSheet(false)}
      />

      {/* Server selector sheet (multi-hop entry/exit picker) */}
      <ServerSelectorSheet
        open={multiHopPickerTarget !== null}
        servers={servers}
        selectedServerId={
          multiHopPickerTarget === 'entry'
            ? settings.multiHopEntryNodeId
            : settings.multiHopExitNodeId
        }
        favoriteServers={favoriteServers}
        onSelect={handlePickMultiHopServer}
        onToggleFavorite={(id) => toggleFavorite(id)}
        onDismiss={() => setMultiHopPickerTarget(null)}
      />

      {/* Logout confirm modal */}
      <AnimatePresence>
        {showLogoutConfirm && (
          <motion.div
            className="absolute inset-0 z-50 flex items-center justify-center bg-black/85"
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
// Top bar
// ─────────────────────────────────────────────────────────────────────────

interface HomeTopBarProps {
  userEmail: string | null;
  multiHopArmed: boolean;
  multiHopUnlocked: boolean;
  onToggleMultiHop: () => void;
  onLogout: () => void;
}

function HomeTopBar({
  userEmail,
  multiHopArmed,
  multiHopUnlocked,
  onToggleMultiHop,
  onLogout,
}: HomeTopBarProps) {
  return (
    <div
      className="relative z-20 flex items-center gap-2 px-4 pt-3 pb-2"
      // No backdrop-filter blur (smears the animating globe into vertical
      // streaks on WebView2 GPUs); a near-opaque fill reads the same.
      style={{ backgroundColor: 'rgba(11,11,16,0.92)' }}
    >
      <MultiHopTopAction
        armed={multiHopArmed}
        unlocked={multiHopUnlocked}
        onClick={onToggleMultiHop}
      />
      <div className="flex-1" />
      {userEmail && (
        <span
          className="max-w-[160px] truncate text-xs"
          style={{ color: white.w40 }}
        >
          {userEmail}
        </span>
      )}
      <BirdoIconAction
        icon={LogOut}
        contentDescription="Log out"
        onClick={onLogout}
        tint={white.w60}
      />
    </div>
  );
}

interface MultiHopTopActionProps {
  armed: boolean;
  unlocked: boolean;
  onClick: () => void;
}

/** Compact 40px icon toggle in the top-left that arms Multi-Hop. */
function MultiHopTopAction({ armed, unlocked, onClick }: MultiHopTopActionProps) {
  const active = armed && unlocked;
  const tint = !unlocked ? white.w40 : active ? brand.purple : white.w80;
  const bg = active ? brand.purpleBg : white.w05;
  const border = active ? 'rgba(168,85,247,0.55)' : hairline.soft;

  return (
    <button
      type="button"
      onClick={onClick}
      aria-label="Multi-Hop"
      aria-pressed={active}
      className="relative flex h-10 w-10 shrink-0 items-center justify-center rounded-xl transition-colors"
      style={{ backgroundColor: bg, border: `1px solid ${border}` }}
    >
      <AltRoute size={20} color={tint} aria-hidden />
      {!unlocked && (
        <span
          className="absolute bottom-0.5 right-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-full"
          style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}
        >
          <Lock size={9} color="#FFFFFF" aria-hidden />
        </span>
      )}
    </button>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Banners
// ─────────────────────────────────────────────────────────────────────────

interface BannerRowProps {
  icon: typeof ShieldAlert;
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

// A small pill shown under the status indicator when stealth / post-quantum is
// actively engaged on the live tunnel (driven by get_vpn_status).
function SecurityChip({ icon: Icon, label }: { icon: typeof Lock; label: string }) {
  return (
    <div
      className="flex items-center gap-1.5 rounded-full px-2.5 py-1"
      style={{ backgroundColor: brand.purpleBg, border: `1px solid ${hairline.soft}` }}
    >
      <Icon size={12} color={brand.purpleLight} className="shrink-0" />
      <span className="text-[11px] font-medium" style={{ color: brand.purpleLight }}>
        {label}
      </span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────
// Stats
// ─────────────────────────────────────────────────────────────────────────

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

// ─────────────────────────────────────────────────────────────────────────
// Server selectors
// ─────────────────────────────────────────────────────────────────────────

interface ServerSelectorCardProps {
  server: { city: string; country: string; countryCode: string } | null;
  disabled: boolean;
  onClick: () => void;
}

function ServerSelectorCard({ server, disabled, onClick }: ServerSelectorCardProps) {
  return (
    <button
      type="button"
      data-testid="server-selector"
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

interface MultiHopServerPairProps {
  entry: Server | null;
  exit: Server | null;
  sameServer: boolean;
  disabled: boolean;
  onPickEntry: () => void;
  onPickExit: () => void;
}

/** Two stacked Entry/Exit selector cards shown when Multi-Hop is armed. */
function MultiHopServerPair({
  entry,
  exit,
  sameServer,
  disabled,
  onPickEntry,
  onPickExit,
}: MultiHopServerPairProps) {
  return (
    <div className="w-full">
      <MultiHopServerCard label="Entry server" server={entry} disabled={disabled} onClick={onPickEntry} />
      <div className="flex justify-center py-2">
        <ArrowDown size={18} color={white.w40} aria-hidden />
      </div>
      <MultiHopServerCard label="Exit server" server={exit} disabled={disabled} onClick={onPickExit} />
      {sameServer && (
        <p className="mt-1.5 text-[11px]" style={{ color: status.red }}>
          Entry and exit must be different servers.
        </p>
      )}
    </div>
  );
}

interface MultiHopServerCardProps {
  label: string;
  server: Server | null;
  disabled: boolean;
  onClick: () => void;
}

function MultiHopServerCard({ label, server, disabled, onClick }: MultiHopServerCardProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className="w-full text-left transition-opacity disabled:opacity-50"
    >
      <BirdoCard cornerRadius={16} padding="0.875rem">
        <div className="flex items-center gap-3.5">
          <span
            className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl text-[22px]"
            style={{ backgroundColor: white.w05, border: `1px solid ${hairline.soft}` }}
          >
            {server ? countryCodeToFlag(server.countryCode) : '🌐'}
          </span>
          <div className="min-w-0 flex-1">
            <div
              className="text-[10px] font-bold uppercase tracking-wider"
              style={{ color: brand.purple }}
            >
              {label}
            </div>
            <div
              className="mt-0.5 truncate text-sm font-semibold"
              style={{ color: white.w100 }}
            >
              {server ? server.name : 'Choose…'}
            </div>
            {server && (
              <div className="truncate text-xs" style={{ color: white.w60 }}>
                {(server.city || server.country)} · {server.load}% load
              </div>
            )}
          </div>
          <ChevronRight size={18} color={white.w40} />
        </div>
      </BirdoCard>
    </button>
  );
}
