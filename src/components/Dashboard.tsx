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
  Gauge,
  LogOut,
  ShieldAlert,
  ShieldOff,
  AlertTriangle,
  AlertCircle,
  ChevronRight,
  Route as AltRoute,
  Lock,
  EyeOff,
  Globe,
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

/**
 * Shape of `get_servers`. The Rust `ServerInfo` is `#[serde(rename_all =
 * "camelCase")]`, so the wire fields are camelCase; the snake_case spellings are
 * kept only as a defensive fallback. Reading snake_case *first* is what made
 * `isOnline` fall through to its `?? true` default for every server.
 */
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
  isPremium?: boolean;
  min_plan?: string | null;
  minPlan?: string | null;
  is_high_speed?: boolean;
  isHighSpeed?: boolean;
  is_port_forwarding?: boolean;
  isPortForwarding?: boolean;
  is_online?: boolean;
  isOnline?: boolean;
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
    deepLinkAction,
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
    vpnIp,
  } = useAppStore(
    useShallow((s) => ({
      connectionState: s.connectionState,
      currentServer: s.currentServer,
      vpnIp: s.vpnIp,
      servers: s.servers,
      deepLinkAction: s.deepLinkAction,
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
          isPremium: s.isPremium ?? s.is_premium ?? false,
          minPlan: s.minPlan ?? s.min_plan ?? undefined,
          isHighSpeed: s.isHighSpeed ?? s.is_high_speed ?? false,
          isPortForwarding: s.isPortForwarding ?? s.is_port_forwarding ?? false,
          isOnline: s.isOnline ?? s.is_online ?? true,
          isAccessible: s.accessible ?? true,
        }));
        setServers(mapped);

        // Restore the server the user last connected to. Without this the app
        // forgets the choice on every launch, shows "Choose a server", and — if
        // the user just hits Connect — silently picks whichever accessible server
        // sorts first, so the same click lands them somewhere different each day.
        const st = useAppStore.getState();
        if (!st.currentServer && st.lastServerId) {
          const remembered = mapped.find(
            (srv) => srv.id === st.lastServerId && srv.isOnline && srv.isAccessible,
          );
          if (remembered) setCurrentServer(remembered);
        }

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
  }, [setServers, setServerPing, setCurrentServer]);

  /**
   * Label the current server after a quick-connect.
   *
   * `quick_connect` picks the node on the Rust side, so unlike the explicit
   * connect paths the UI never learns which one it got. Without this the header
   * shows no server at all after auto-connect or a tray connect. Matches the
   * chosen node by name against the loaded list so we keep full server metadata
   * (flag, city, load) rather than just a string.
   *
   * Deliberately best-effort: a failure here must never turn a WORKING tunnel
   * into a UI error, which is the failure mode this whole area just had.
   */
  const refreshCurrentServerFromStatus = useCallback(async () => {
    try {
      const st = await invoke<RustVpnStatus>('get_vpn_status');
      if (!st.server_name) return;
      const list = useAppStore.getState().servers;
      const match = list.find((sv) => sv.name === st.server_name);
      useAppStore.getState().setCurrentServer(
        match ?? ({ name: st.server_name } as (typeof list)[number]),
      );
    } catch {
      /* label only — never fail a live connection over it */
    }
  }, []);

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
        // MUST settle the optimistic state here. The status poll deliberately
        // refuses to promote out of 'connecting' (it would otherwise stomp a
        // real in-progress connect back to disconnected), so leaving it set
        // makes the UI terminal: Connect/Disconnect inert, tray actions gated
        // out, tunnel actually up and bytes flowing, locked until relaunch.
        setConnectionState('connected');
        await refreshCurrentServerFromStatus();
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
        // Same reason as the auto-connect path above: the poll will not
        // promote out of 'connecting', so this must settle it itself.
        useAppStore.getState().setConnectionState('connected');
        await refreshCurrentServerFromStatus();
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
    // refreshCurrentServerFromStatus is a useCallback with an empty dep list, so
    // it is referentially stable and listing it cannot re-register the tray
    // listeners. Declared rather than suppressed, so a future change that gives
    // it real dependencies is caught here instead of silently going stale.
  }, [refreshCurrentServerFromStatus]);

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
  // Closing the window only HIDES it (minimize-to-tray), so this interval used to
  // keep firing two IPC round-trips every 2s — waking the WebView2 renderer, the
  // Rust side, and the CPU ~43k times a day to refresh byte counters nobody can
  // see. The cadence is now visibility-aware: 2s while the window is on screen,
  // 15s while it is in the tray. It cannot stop entirely when hidden because the
  // tray icon + tooltip are driven off `connectionState`, which only this poll
  // feeds — a reconnect or kill-switch trip must still reach the one surface the
  // user can actually see. On re-show we poll immediately so the UI is never
  // stale by more than a frame.
  const VISIBLE_POLL_MS = 2_000;
  const HIDDEN_POLL_MS = 15_000;
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

    const schedule = () => {
      if (statsInterval.current) clearInterval(statsInterval.current);
      statsInterval.current = setInterval(
        poll,
        document.hidden ? HIDDEN_POLL_MS : VISIBLE_POLL_MS,
      );
    };
    const onVisibility = () => {
      if (!document.hidden) poll(); // catch up the instant we're seen again
      schedule();
    };

    poll();
    schedule();
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      cancelled = true;
      document.removeEventListener('visibilitychange', onVisibility);
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
      // Route to the plans screen (Multi-Hop is Sovereign) instead of a
      // dead-end toast — give the upsell an actual destination.
      showToast('Multi-Hop is a Sovereign feature.');
      useAppStore.getState().pushRoute('pricing');
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
        // Apparent public IP = the EXIT node's endpoint (matches mobile's
        // extractServerIp — the exit is where traffic egresses).
        setVpnIp(exit?.ipAddress ?? exit?.hostname ?? null);
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
      setVpnIp(target.ipAddress ?? target.hostname ?? null);
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
        setVpnIp(s.ipAddress ?? s.hostname ?? null);
      } catch (err) {
        setErrorMessage(friendlyVpnError(err));
        setConnectionState('error');
        setCurrentServer(null);
      }
    },
    [setCurrentServer, setConnectionState, setErrorMessage, setVpnIp],
  );

  // ── Deep links (birdo://connect/<server-id>) ──────────────────────
  // App.tsx validates the URL and stages { action:'connect', serverId } in the
  // store; this effect is the consumer that actually connects. If the server
  // list hasn't loaded yet the action is kept until it has (the effect re-runs
  // on `servers`), so a cold-start deep link still works. Declared after
  // handleSelectServer because it participates in the deps array.
  useEffect(() => {
    if (!deepLinkAction) return;
    if (deepLinkAction.action !== 'connect' || !deepLinkAction.serverId) {
      // 'settings' etc. are handled by App.tsx's setTab — nothing to do here.
      if (deepLinkAction.action !== 'connect') {
        useAppStore.getState().setDeepLinkAction(null);
      }
      return;
    }

    const target = servers.find((s) => s.id === deepLinkAction.serverId);
    if (!target) {
      if (servers.length > 0) {
        // List is loaded and the id isn't in it — surface and drop the action.
        setErrorMessage('The server in that link is unknown for this account.');
        useAppStore.getState().setDeepLinkAction(null);
      }
      return;
    }

    useAppStore.getState().setDeepLinkAction(null);

    if (!target.isOnline || !target.isAccessible) {
      setErrorMessage('That server is offline or not included in your plan.');
      return;
    }

    const st = useAppStore.getState().connectionState;
    if (st === 'connected' || st === 'reconnecting' || st === 'rekeying' || st === 'kill_switch_active') {
      // On-tunnel: handleSelectServer performs a real switch to the target.
      handleSelectServer(target);
      return;
    }
    if (st !== 'disconnected' && st !== 'error') return; // mid-transition — ignore

    setCurrentServer(target);
    (async () => {
      setConnectionState('connecting');
      setErrorMessage(null);
      setVpnIp(null);
      try {
        await invoke<boolean>('connect_vpn', { serverId: target.id });
        setConnectionState('connected');
        setVpnIp(target.ipAddress ?? target.hostname ?? null);
      } catch (err) {
        setErrorMessage(friendlyVpnError(err));
        setConnectionState('error');
        setCurrentServer(null);
      }
    })();
  }, [deepLinkAction, servers, handleSelectServer, setCurrentServer, setConnectionState, setErrorMessage, setVpnIp]);

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
          // Rotate only while idle (what the header has always claimed). Connected
          // is the steady state a VPN client sits in for days — an infinite
          // transform animation there means the compositor never idles, burning
          // battery on a background decoration nobody is watching.
          autoRotate={!isConnected}
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
                {vpnIp && (
                  <div
                    className="mt-2 flex items-center justify-center gap-1.5 text-xs"
                    style={{ color: white.w60 }}
                  >
                    <Globe size={12} aria-hidden />
                    <span>Public IP</span>
                    <span className="font-mono" style={{ color: white.w80 }}>
                      {vpnIp}
                    </span>
                  </div>
                )}
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

          {/* Error. Gated on errorMessage alone, NOT on connectionState==='error':
              a connect failure that leaves the state untouched (e.g. a mid-tunnel
              switch to a server that turns out to be offline) still has something
              to tell the user. The store clears errorMessage on every non-error
              transition, so a stale message can't outlive the condition. */}
          {errorMessage && (
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
  const tint = !unlocked ? white.w40 : active ? brand.accent : white.w80;
  const bg = active ? brand.accentBg : white.w05;
  const border = active ? 'rgba(16,185,129,0.55)' : hairline.soft;

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
      style={{ backgroundColor: brand.accentBg, border: `1px solid ${hairline.soft}` }}
    >
      <Icon size={12} color={brand.accentLight} className="shrink-0" />
      <span className="text-[11px] font-medium" style={{ color: brand.accentLight }}>
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

/**
 * Four tiles: duration, latency, down, up. Latency is the newcomer — the Rust
 * side has been reporting `current_latency_ms` on every 2s poll since forever and
 * the UI threw it away, so the one number a VPN user actually watches was the one
 * number we didn't show.
 *
 * Each tile carries a visible caption. Down vs Up used to be distinguishable only
 * by arrow direction and a green/blue tint, which is no signal at all for a
 * colour-blind user glancing at two byte counts.
 */
function StatsRow({ stats }: StatsRowProps) {
  const latency = stats?.current_latency_ms;
  return (
    <div className="grid grid-cols-4 gap-2">
      <StatTile
        icon={Clock}
        tint={brand.accentSoft}
        label="Uptime"
        value={stats ? formatUptime(stats.uptime_seconds) : '—'}
      />
      <StatTile
        icon={Gauge}
        tint={
          latency == null ? white.w60
          : latency < 80 ? status.greenLight
          : latency < 160 ? status.yellowLight
          : status.red
        }
        label="Ping"
        value={latency != null && Number.isFinite(latency) ? `${Math.round(latency)}ms` : '—'}
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
    <BirdoCard cornerRadius={12} padding="0.4rem 0.35rem">
      <div className="flex flex-col items-center gap-0.5">
        <div className="flex items-center gap-1">
          <Icon size={12} color={tint} aria-hidden />
          <span
            className="truncate text-xs font-semibold tabular-nums"
            style={{ color: white.w100 }}
          >
            {value}
          </span>
        </div>
        <span
          className="text-[9px] font-medium uppercase tracking-wide"
          style={{ color: white.w55 }}
        >
          {label}
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
              style={{ color: brand.accent }}
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
