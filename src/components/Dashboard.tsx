import { useState, useEffect, useRef, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { useAppStore, ConnectionState } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';
import { ConnectionButton } from './ConnectionButton';
import { ServerList } from './ServerList';
import { Settings } from './Settings';
import { OfflineBanner } from './OfflineBanner';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Globe,
  Server,
  SettingsIcon,
  User,
  LogOut,
  ArrowDown,
  ArrowUp,
  Clock,
  Wifi,
  Shield,
  AlertTriangle,
} from 'lucide-react';
import { formatBytes, formatUptime } from '@/utils/helpers';
import { initNotifications, notifyConnected, notifyDisconnected } from '@/utils/notifications';

type Tab = 'connect' | 'servers' | 'account' | 'settings';

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
}

export function Dashboard() {
  const [activeTab, setActiveTab] = useState<Tab>('connect');
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);
  const [liveStats, setLiveStats] = useState<RustVpnStats | null>(null);
  const statsInterval = useRef<ReturnType<typeof setInterval> | null>(null);

  const {
    connectionState,
    currentServer,
    userEmail,
    account,
    settings,
    errorMessage,
    isAdmin,
    setConnectionState,
    setServers,
    setServerPing,
    setAccount,
    logout,
    setAuthenticated,
    hydrateSettings,
    setErrorMessage,
    setIsAdmin,
  } = useAppStore(
    useShallow((s) => ({
      connectionState: s.connectionState,
      currentServer: s.currentServer,
      userEmail: s.userEmail,
      account: s.account,
      settings: s.settings,
      errorMessage: s.errorMessage,
      isAdmin: s.isAdmin,
      setConnectionState: s.setConnectionState,
      setServers: s.setServers,
      setServerPing: s.setServerPing,
      setAccount: s.setAccount,
      logout: s.logout,
      setAuthenticated: s.setAuthenticated,
      hydrateSettings: s.hydrateSettings,
      setErrorMessage: s.setErrorMessage,
      setIsAdmin: s.setIsAdmin,
    }))
  );

  const isConnected = connectionState === 'connected';

  // ── Hydrate settings from Rust on mount ──────────────────────────
  useEffect(() => {
    const hydrate = async () => {
      try {
        const rustSettings = await invoke<any>('get_settings');
        hydrateSettings({
          killSwitchEnabled: rustSettings.killswitch_enabled ?? true,
          autoConnect: rustSettings.auto_connect ?? false,
          autostart: rustSettings.autostart ?? false,
          startMinimized: rustSettings.start_minimized ?? false,
          notifications: rustSettings.notifications_enabled ?? true,
          preferredServerId: rustSettings.preferred_server_id ?? null,
          splitTunnelingEnabled: rustSettings.split_tunneling_enabled ?? false,
          splitTunnelApps: rustSettings.split_tunnel_apps ?? [],
          customDns: rustSettings.custom_dns ?? null,
          protocol: 'wireguard',
          localNetworkSharing: rustSettings.local_network_sharing ?? false,
          wireGuardPort: rustSettings.wireguard_port ?? 'auto',
          wireGuardMtu: rustSettings.wireguard_mtu ?? 0,
          multiHopEnabled: rustSettings.multi_hop_enabled ?? false,
          multiHopEntryNodeId: rustSettings.multi_hop_entry_node_id ?? null,
          multiHopExitNodeId: rustSettings.multi_hop_exit_node_id ?? null,
          stealthMode: rustSettings.stealth_mode ?? false,
          quantumProtection: rustSettings.quantum_protection ?? false,
        });
      } catch (err) {
        console.warn('Failed to hydrate settings from backend:', err);
      }
    };
    hydrate();
  }, [hydrateSettings]);

  // ── Check admin status on mount ──────────────────────────────────
  useEffect(() => {
    invoke<boolean>('get_admin_status')
      .then((admin) => setIsAdmin(admin))
      .catch(() => setIsAdmin(false));
  }, [setIsAdmin]);

  // ── Fetch account / subscription info on mount ───────────────────
  useEffect(() => {
    const fetchAccount = async () => {
      try {
        const sub = await invoke<{
          plan: string;
          status: string;
          expires_at: string | null;
          devices_used: number;
          devices_limit: number;
          bandwidth_used: number;
          bandwidth_limit: number | null;
        }>('get_subscription_status');
        setAccount({
          plan: sub.plan?.toUpperCase() || 'RECON',
          status: (sub.status as any) || 'active',
          expiresAt: sub.expires_at ?? null,
          activeDevices: sub.devices_used ?? 0,
          maxDevices: sub.devices_limit ?? 1,
          bandwidthUsed: sub.bandwidth_used ?? 0,
          bandwidthLimit: sub.bandwidth_limit ?? 0,
        });
      } catch (err) {
        console.warn('Failed to fetch subscription info:', err);
      }
    };
    fetchAccount();
  }, [setAccount]);

  // ── Fetch servers on mount ───────────────────────────────────────
  useEffect(() => {
    const fetchServers = async () => {
      try {
        const servers = await invoke<any[]>('get_servers');
        const mapped = servers.map((s: any) => ({
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
        }));
        setServers(mapped);

        // Ping servers in background
        for (const srv of mapped) {
          if (srv.hostname || srv.ipAddress) {
            invoke<number | null>('ping_server', {
              hostname: srv.hostname || srv.ipAddress,
              port: srv.port ?? 51820,
            })
              .then((ping) => {
                if (ping != null) setServerPing(srv.id, ping);
              })
              .catch(() => {});
          }
        }
      } catch (err) {
        console.error('Failed to fetch servers:', err);
      }
    };
    fetchServers();
  }, [setServers, setServerPing]);

  // ── Auto-connect on mount (if enabled) ───────────────────────────
  useEffect(() => {
    if (!settings.autoConnect) return;
    if (connectionState !== 'disconnected') return;

    const autoConnect = async () => {
      // Re-read from store to use Rust-hydrated settings (not stale localStorage)
      const current = useAppStore.getState();
      if (!current.settings.autoConnect) return;
      if (current.connectionState !== 'disconnected') return;

      try {
        setConnectionState('connecting');
        await invoke('quick_connect');
        setConnectionState('connected');
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.warn('Auto-connect failed:', msg);
        setErrorMessage(msg);
        setConnectionState('error');
      }
    };

    // Small delay to let servers load first
    const timer = setTimeout(autoConnect, 1500);
    return () => clearTimeout(timer);
    // Run only once on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Listen for system tray events ────────────────────────────────
  useEffect(() => {
    const unlistenConnect = listen('tray-quick-connect', async () => {
      const store = useAppStore.getState();
      if (store.connectionState !== 'disconnected') return;
      store.setConnectionState('connecting');
      try {
        await invoke('quick_connect');
        useAppStore.getState().setConnectionState('connected');
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        useAppStore.getState().setErrorMessage(msg);
        useAppStore.getState().setConnectionState('error');
      }
    });
    const unlistenDisconnect = listen('tray-disconnect', async () => {
      const store = useAppStore.getState();
      if (store.connectionState !== 'connected') return;
      store.setConnectionState('disconnecting');
      try {
        await invoke('disconnect_vpn');
        const s = useAppStore.getState();
        s.setConnectionState('disconnected');
        s.setCurrentServer(null);
        s.setVpnIp(null);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        useAppStore.getState().setErrorMessage(msg);
        useAppStore.getState().setConnectionState('error');
      }
    });
    return () => {
      unlistenConnect.then(f => f());
      unlistenDisconnect.then(f => f());
    };
  }, []);

  // ── Initialize notifications ─────────────────────────────────────
  useEffect(() => { initNotifications(); }, []);

  // ── Notify on connection state changes ───────────────────────────
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

  // ── Poll VPN status + stats while active ────────────────────────
  const isActive = connectionState === 'connected' || connectionState === 'connecting' || connectionState === 'reconnecting';
  useEffect(() => {
    if (!isActive) {
      setLiveStats(null);
      if (statsInterval.current) {
        clearInterval(statsInterval.current);
        statsInterval.current = null;
      }
      return;
    }

    const poll = async () => {
      try {
        const [status, stats] = await Promise.all([
          invoke<RustVpnStatus>('get_vpn_status'),
          invoke<RustVpnStats>('get_vpn_stats'),
        ]);

        // Sync connection state from Rust backend
        // Skip overwriting transient UI states (connecting/disconnecting)
        const current = useAppStore.getState().connectionState;
        if (status.state !== current && current !== 'connecting' && current !== 'disconnecting') {
          setConnectionState(status.state as ConnectionState);
        }
        if (status.state === 'connected' || status.state === 'rekeying') {
          setLiveStats(stats);
        }
      } catch {
        // Silently fail — backend might not be ready yet
      }
    };

    poll();
    statsInterval.current = setInterval(poll, 2000);
    return () => {
      if (statsInterval.current) clearInterval(statsInterval.current);
    };
  }, [isActive, setConnectionState]);

  // ── Logout handler ───────────────────────────────────────────────
  const handleLogout = useCallback(async () => {
    // Disconnect VPN first if tunnel is active
    const { connectionState: currentState } = useAppStore.getState();
    if (currentState === 'connected' || currentState === 'connecting' || currentState === 'reconnecting') {
      try {
        await invoke('disconnect_vpn');
      } catch {
        // Best-effort disconnect
      }
    }
    try {
      await invoke('logout');
    } catch {
      // Best-effort server logout
    }
    logout();
    setAuthenticated(false);
    setShowLogoutConfirm(false);
  }, [logout, setAuthenticated]);

  // ── Status helper ────────────────────────────────────────────────
  const statusLabel = (): string => {
    switch (connectionState) {
      case 'connected':
        return 'Protected';
      case 'connecting':
        return 'Connecting...';
      case 'disconnecting':
        return 'Disconnecting...';
      case 'reconnecting':
        return 'Reconnecting...';
      case 'rekeying':
        return 'Rekeying...';
      case 'error':
        return 'Connection Error';
      default:
        return 'Unprotected';
    }
  };

  const statusColor = isConnected
    ? 'text-green-400'
    : connectionState === 'error'
    ? 'text-red-400'
    : 'text-white/60';

  // ─── TABS ────────────────────────────────────────────────────────
  const tabs: { id: Tab; label: string; icon: typeof Globe }[] = [
    { id: 'connect', label: 'Connect', icon: Globe },
    { id: 'servers', label: 'Servers', icon: Server },
    { id: 'account', label: 'Account', icon: User },
    { id: 'settings', label: 'Settings', icon: SettingsIcon },
  ];

  return (
    <div className="flex h-full flex-col">
      {/* ── Titlebar drag zone (overlay — doesn't consume flow space) ── */}
      <div
        data-tauri-drag-region
        className="absolute inset-x-0 top-0 z-50 h-8"
      />

      {/* ── Offline Banner ─────────────────────────────────────── */}
      <OfflineBanner />

      {/* ── Content area ───────────────────────────────────────── */}
      <div className="relative flex-1 overflow-hidden">
        <AnimatePresence mode="wait">
          {activeTab === 'connect' && (
            <motion.div
              key="connect"
              className="absolute inset-0 flex flex-col items-center justify-between pt-10 pb-6 px-4"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
            >
              {/* Status area */}
              <div className="flex flex-col items-center gap-1">
                <div className="flex items-center gap-2">
                  <span
                    className={`inline-block h-2 w-2 rounded-full ${
                      isConnected
                        ? 'bg-green-400'
                        : connectionState === 'error'
                        ? 'bg-red-400'
                        : 'bg-white/30'
                    }`}
                  />
                  <span className={`text-sm font-medium ${statusColor}`}>
                    {statusLabel()}
                  </span>
                </div>

                {/* Admin warning banner */}
                {!isAdmin && (
                  <div className="mt-1 max-w-[280px] rounded-lg bg-amber-500/10 border border-amber-500/30 px-3 py-2">
                    <div className="flex items-center gap-1.5 justify-center">
                      <Shield size={12} className="text-amber-400 shrink-0" />
                      <p className="text-xs text-amber-300 text-center leading-tight">
                        Not running as administrator — VPN cannot connect.
                      </p>
                    </div>
                  </div>
                )}

                {/* Admin confirmed badge */}
                {isAdmin && (
                  <div className="mt-1 flex items-center gap-1 justify-center">
                    <Shield size={11} className="text-emerald-400" />
                    <span className="text-[11px] text-emerald-400/80 font-medium">
                      Administrator
                    </span>
                  </div>
                )}

                {/* Error message */}
                {connectionState === 'error' && errorMessage && (
                  <div className="mt-1 max-w-[280px] rounded-lg bg-red-500/10 border border-red-500/20 px-3 py-2">
                    <p className="text-xs text-red-300 text-center leading-tight">
                      {errorMessage}
                    </p>
                  </div>
                )}

                {/* Current server info */}
                {currentServer && isConnected && (
                  <span className="text-xs text-white/50">
                    {currentServer.city}, {currentServer.country}
                  </span>
                )}
              </div>

              {/* Connection button */}
              <ConnectionButton />

              {/* Live stats (visible when connected) */}
              {isConnected && liveStats ? (
                <div className="w-full rounded-2xl glass-card p-4 space-y-3">
                  {/* Row 1: Download / Upload */}
                  <div className="flex justify-between text-xs">
                    <div className="flex items-center gap-2 text-white/70">
                      <ArrowDown size={14} className="text-green-400" />
                      <span>{formatBytes(liveStats.bytes_in)}</span>
                    </div>
                    <div className="flex items-center gap-2 text-white/70">
                      <ArrowUp size={14} className="text-purple-400" />
                      <span>{formatBytes(liveStats.bytes_out)}</span>
                    </div>
                  </div>

                  {/* Row 2: Uptime / Latency */}
                  <div className="flex justify-between text-xs">
                    <div className="flex items-center gap-2 text-white/50">
                      <Clock size={14} />
                      <span>{formatUptime(liveStats.uptime_seconds)}</span>
                    </div>
                    {liveStats.current_latency_ms != null && (
                      <div className="flex items-center gap-2 text-white/50">
                        <Wifi size={14} />
                        <span>{liveStats.current_latency_ms} ms</span>
                      </div>
                    )}
                  </div>

                  {/* Row 3: Kill switch / Protocol */}
                  <div className="flex justify-between text-xs text-white/40">
                    <div className="flex items-center gap-1.5">
                      <Shield size={12} />
                      <span>
                        Kill Switch{' '}
                        {settings.killSwitchEnabled ? 'On' : 'Off'}
                      </span>
                    </div>
                    <span>WireGuard</span>
                  </div>

                  {/* Row 4: Plan badge */}
                  {account.plan && (
                    <div className="flex justify-center pt-1">
                      <span className="rounded-full bg-white/5 border border-white/10 px-3 py-0.5 text-[10px] font-semibold uppercase tracking-wider text-white/50">
                        {account.plan}
                      </span>
                    </div>
                  )}
                </div>
              ) : (
                /* Placeholder when disconnected */
                <div className="w-full rounded-2xl glass-card p-4 text-center text-xs text-white/30">
                  Connect to a server to see live stats
                </div>
              )}
            </motion.div>
          )}

          {activeTab === 'servers' && (
            <motion.div
              key="servers"
              className="absolute inset-0"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
            >
              <ServerList />
            </motion.div>
          )}

          {activeTab === 'account' && (
            <motion.div
              key="account"
              className="absolute inset-0 overflow-y-auto pt-10 px-4 pb-4 space-y-4"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
            >
              <AccountPanel
                email={userEmail ?? account.email}
                plan={account.plan}
                status={account.status}
                maxDevices={account.maxDevices}
                activeDevices={account.activeDevices}
                expiresAt={account.expiresAt}
                onLogout={() => setShowLogoutConfirm(true)}
              />
            </motion.div>
          )}

          {activeTab === 'settings' && (
            <motion.div
              key="settings"
              className="absolute inset-0 overflow-y-auto pt-8"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              transition={{ duration: 0.2 }}
            >
              <Settings />
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* ── Bottom tab bar ─────────────────────────────────────── */}
      <nav className="flex shrink-0 border-t border-white/5 glass-strong">
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            aria-label={label}
            className={`flex flex-1 flex-col items-center gap-1 py-2.5 text-[10px] transition
              ${
                activeTab === id
                  ? 'text-white'
                  : 'text-white/40 hover:text-white/70'
              }`}
          >
            <Icon size={18} />
            <span>{label}</span>
          </button>
        ))}
      </nav>

      {/* ── Logout confirmation modal ──────────────────────────── */}
      <AnimatePresence>
        {showLogoutConfirm && (
          <motion.div
            className="absolute inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
          >
            <motion.div
              className="mx-6 w-full rounded-2xl glass-card p-6 text-center space-y-4"
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
            >
              <AlertTriangle size={36} className="mx-auto text-yellow-400" />
              <h3 className="text-lg font-semibold text-white">Log Out?</h3>
              <p className="text-sm text-white/60">
                {isConnected
                  ? 'You are still connected to the VPN. Logging out will disconnect you.'
                  : 'Are you sure you want to log out?'}
              </p>
              <div className="flex gap-3">
                <button
                  onClick={() => setShowLogoutConfirm(false)}
                  className="flex-1 rounded-xl py-2.5 btn-secondary text-sm"
                >
                  Cancel
                </button>
                <button
                  onClick={handleLogout}
                  className="flex-1 rounded-xl bg-red-500/20 border border-red-500/30 py-2.5 text-sm text-red-400 hover:bg-red-500/30 transition"
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

// ──── Account sub-panel ─────────────────────────────────────────────
interface AccountPanelProps {
  email: string | null;
  plan: string | null;
  status: string;
  maxDevices: number;
  activeDevices: number;
  expiresAt: string | null;
  onLogout: () => void;
}

function AccountPanel({
  email,
  plan,
  status,
  maxDevices,
  activeDevices,
  expiresAt,
  onLogout,
}: AccountPanelProps) {
  const planLabel = plan ?? 'Free';
  const statusBadge =
    status === 'active'
      ? 'bg-green-500/20 text-green-400 border-green-500/30'
      : status === 'expired'
      ? 'bg-red-500/20 text-red-400 border-red-500/30'
      : 'bg-white/10 text-white/60 border-white/20';

  const formattedExpiry = expiresAt
    ? new Date(expiresAt).toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      })
    : null;

  return (
    <div className="space-y-4">
      {/* Profile card */}
      <div className="rounded-2xl glass-card p-5 space-y-4">
        {/* Avatar + email */}
        <div className="flex items-center gap-3">
          <div className="flex h-12 w-12 items-center justify-center rounded-full bg-white/10 text-lg font-bold text-white">
            {email ? email[0].toUpperCase() : '?'}
          </div>
          <div className="flex-1 min-w-0">
            <p className="truncate text-sm font-medium text-white">
              {email ?? 'Unknown'}
            </p>
            <div className="flex items-center gap-2 mt-1">
              <span
                className={`inline-block rounded-full border px-2 py-0.5 text-[10px] font-medium ${statusBadge}`}
              >
                {status === 'active'
                  ? 'Active'
                  : status === 'expired'
                  ? 'Expired'
                  : status === 'cancelled'
                  ? 'Cancelled'
                  : 'Unknown'}
              </span>
              <span className="text-xs text-white/50">{planLabel}</span>
            </div>
          </div>
        </div>

        {/* Divider */}
        <div className="border-t border-white/5" />

        {/* Details */}
        <div className="space-y-2.5">
          <DetailRow label="Devices" value={`${activeDevices} / ${maxDevices}`} />
          {formattedExpiry && (
            <DetailRow label="Expires" value={formattedExpiry} />
          )}
          <DetailRow label="Protocol" value="WireGuard" />
        </div>
      </div>

      {/* Logout button */}
      <button
        onClick={onLogout}
        className="flex w-full items-center justify-center gap-2 rounded-xl py-3 text-sm text-red-400 glass-card hover:bg-red-500/10 transition"
      >
        <LogOut size={16} />
        Log Out
      </button>
    </div>
  );
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between text-xs">
      <span className="text-white/40">{label}</span>
      <span className="text-white/80">{value}</span>
    </div>
  );
}
