import { create } from 'zustand';
import { persist } from 'zustand/middleware';

export interface Server {
  id: string;
  name: string;
  country: string;
  countryCode: string;
  city: string;
  hostname?: string;
  ipAddress?: string;
  port?: number;
  load: number;
  ping?: number;
  isPremium: boolean;
  isStreaming: boolean;
  isP2p: boolean;
  isOnline: boolean;
  isAccessible: boolean;
}

export interface ConnectionStats {
  bytesSent: number;
  bytesReceived: number;
  connectedAt: string | null;
  serverName: string | null;
}

export type ConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'authenticating'
  | 'stealth_connecting'
  | 'connected'
  | 'disconnecting'
  | 'reconnecting'
  | 'rekeying'
  | 'kill_switch_active'
  | 'error';

export interface AccountInfo {
  email: string | null;
  plan: string | null;
  accountId: string | null;
  maxDevices: number;
  activeDevices: number;
  expiresAt: string | null;
  bandwidthUsed: number;
  bandwidthLimit: number;
  status: 'active' | 'expired' | 'cancelled' | 'unknown';
}

export type Protocol = 'wireguard';

export type ThemeMode = 'dark' | 'light' | 'system';

/**
 * Where the (frameless) window sits. The four corners pin it to that corner of
 * the monitor it's currently on (non-movable); 'free' restores the native title
 * bar so it can be dragged anywhere. Frontend-only preference (persisted).
 */
export type WindowCorner =
  | 'top-left'
  | 'top-right'
  | 'bottom-left'
  | 'bottom-right'
  | 'free';

// ── Navigation (mobile-parity 3-tab bottom nav + push sub-screens) ──────────
export type TabId = 'profile' | 'home' | 'settings';
export type RouteId =
  | 'vpnSettings'
  | 'splitTunnel'
  | 'portForward'
  | 'subscription';

export interface AppSettings {
  killSwitchEnabled: boolean;
  autoConnect: boolean;
  autostart: boolean;
  startMinimized: boolean;
  notifications: boolean;
  // Notification detail sub-toggles. Frontend-only preference (persisted in
  // localStorage), NOT part of the Rust `save_settings` payload — the backend
  // `AppSettings` struct has no matching fields, so these never go through
  // `settingsToRust`.
  showIpInNotification: boolean;
  showLocationInNotification: boolean;
  preferredServerId: string | null;
  splitTunnelingEnabled: boolean;
  splitTunnelApps: string[];
  customDns: string[] | null;
  protocol: Protocol;
  // VPN settings (matching Android VpnSettingsScreen)
  localNetworkSharing: boolean;
  wireGuardPort: string; // 'auto' | '51820' | '53' | custom port
  wireGuardMtu: number;  // 0 = automatic, 1280-1500 custom
  // Multi-Hop (Double VPN)
  multiHopEnabled: boolean;
  multiHopEntryNodeId: string | null;
  multiHopExitNodeId: string | null;
  // Stealth & Quantum
  stealthMode: boolean;
  quantumProtection: boolean;
}

export interface MultiHopRoute {
  entryNodeId: string;
  exitNodeId: string;
  entryCountry: string;
  exitCountry: string;
}

export interface PortForward {
  id: string;
  externalPort: number;
  internalPort: number;
  protocol: string;
  enabled: boolean;
  serverNodeId?: string;
  createdAt?: string;
}

interface AppState {
  // Auth
  isAuthenticated: boolean;
  isLoading: boolean;
  userEmail: string | null;

  // Consent
  hasAcceptedConsent: boolean;

  // Account
  account: AccountInfo;

  // Connection
  connectionState: ConnectionState;
  currentServer: Server | null;
  stats: ConnectionStats;
  vpnIp: string | null;

  // Servers
  servers: Server[];
  favoriteServers: string[];

  // Settings
  settings: AppSettings;
  settingsHydrated: boolean;

  // Multi-Hop & Port Forwarding
  multiHopRoutes: MultiHopRoute[];
  portForwards: PortForward[];

  // Actions — Auth
  setAuthenticated: (auth: boolean) => void;
  setLoading: (loading: boolean) => void;
  setUserEmail: (email: string | null) => void;

  // Actions — Consent
  setConsent: (accepted: boolean) => void;

  // Actions — Account
  setAccount: (account: Partial<AccountInfo>) => void;

  // Admin status
  isAdmin: boolean;
  setIsAdmin: (admin: boolean) => void;

  // Error
  errorMessage: string | null;
  setErrorMessage: (msg: string | null) => void;

  // Actions — Connection
  setConnectionState: (state: ConnectionState) => void;
  setCurrentServer: (server: Server | null) => void;
  setStats: (stats: ConnectionStats) => void;
  setVpnIp: (ip: string | null) => void;

  // Actions — Servers
  setServers: (servers: Server[]) => void;
  toggleFavorite: (serverId: string) => void;
  setServerPing: (serverId: string, ping: number) => void;

  // Actions — Settings
  updateSettings: (settings: Partial<AppSettings>) => void;
  hydrateSettings: (settings: AppSettings) => void;

  // Actions — Multi-Hop & Port Forwarding
  setPortForwards: (forwards: PortForward[]) => void;

  // Network
  isOnline: boolean;
  setOnline: (online: boolean) => void;

  // Theme
  theme: ThemeMode;
  setTheme: (theme: ThemeMode) => void;

  // Window position (frameless corner anchor / draggable). Persisted.
  windowCorner: WindowCorner;
  setWindowCorner: (corner: WindowCorner) => void;

  // Deep link
  deepLinkAction: { action: string; serverId?: string } | null;
  setDeepLinkAction: (action: { action: string; serverId?: string } | null) => void;

  // ── Navigation (mobile-parity router; NOT persisted) ──────────────────
  // Bottom-nav tabs + a per-session push stack for slide-in sub-screens.
  tab: TabId;
  navStack: RouteId[];
  setTab: (tab: TabId) => void;
  pushRoute: (route: RouteId) => void;
  popRoute: () => void;

  // Actions — Logout
  logout: () => void;
}

const defaultAccount: AccountInfo = {
  email: null,
  plan: null,
  accountId: null,
  maxDevices: 0,
  activeDevices: 0,
  expiresAt: null,
  bandwidthUsed: 0,
  bandwidthLimit: 0,
  status: 'unknown',
};

const defaultSettings: AppSettings = {
  killSwitchEnabled: true,
  autoConnect: false,
  autostart: false,
  startMinimized: false,
  notifications: true,
  showIpInNotification: false,
  showLocationInNotification: false,
  preferredServerId: null,
  splitTunnelingEnabled: false,
  splitTunnelApps: [],
  customDns: null,
  protocol: 'wireguard',
  localNetworkSharing: false,
  wireGuardPort: 'auto',
  wireGuardMtu: 0,
  multiHopEnabled: false,
  multiHopEntryNodeId: null,
  multiHopExitNodeId: null,
  stealthMode: false,
  // Post-quantum protection (BirdoPQ / ML-KEM-1024) is ON by default for all
  // users — available on every plan, negligible overhead. Matches the Rust
  // `AppSettings::default()` so a fresh install agrees on both sides.
  quantumProtection: true,
};

export const useAppStore = create<AppState>()(
  persist(
    (set, get) => ({
      // Initial state
      isAuthenticated: false,
      isLoading: false,
      userEmail: null,
      hasAcceptedConsent: false,
      isOnline: true,
      account: { ...defaultAccount },

      // Theme
      theme: 'dark' as ThemeMode,
      setTheme: (theme) => set({ theme }),

      windowCorner: 'bottom-left' as WindowCorner,
      setWindowCorner: (windowCorner) => set({ windowCorner }),

      // Deep link
      deepLinkAction: null,
      setDeepLinkAction: (action) => set({ deepLinkAction: action }),

      // Navigation (not persisted — see partialize)
      tab: 'home' as TabId,
      navStack: [],
      setTab: (tab) => set({ tab, navStack: [] }),
      pushRoute: (route) =>
        set((state) => ({ navStack: [...state.navStack, route] })),
      popRoute: () =>
        set((state) => ({ navStack: state.navStack.slice(0, -1) })),

      connectionState: 'disconnected' as ConnectionState,
      currentServer: null,
      isAdmin: false,
      errorMessage: null,
      stats: {
        bytesSent: 0,
        bytesReceived: 0,
        connectedAt: null,
        serverName: null,
      },
      vpnIp: null,

      servers: [],
      favoriteServers: [],

      settings: { ...defaultSettings },
      settingsHydrated: false,

      multiHopRoutes: [],
      portForwards: [],

      // Auth actions
      setAuthenticated: (auth) => set({ isAuthenticated: auth }),
      setLoading: (loading) => set({ isLoading: loading }),
      setUserEmail: (email) => set({ userEmail: email }),

      // Consent actions
      setConsent: (accepted) => set({ hasAcceptedConsent: accepted }),

      // Network actions
      setOnline: (online) => set({ isOnline: online }),

      // Account actions
      setAccount: (partial) =>
        set((state) => ({
          account: { ...state.account, ...partial },
        })),

      // Error actions
      setErrorMessage: (msg) => set({ errorMessage: msg }),
      setIsAdmin: (admin) => set({ isAdmin: admin }),

      // Connection actions
      setConnectionState: (connectionState) => set({ connectionState, ...(connectionState !== 'error' ? { errorMessage: null } : {}) }),
      setCurrentServer: (server) => set({ currentServer: server }),
      setStats: (stats) => set({ stats }),
      setVpnIp: (ip) => set({ vpnIp: ip }),

      // Server actions
      setServers: (servers) => set({ servers }),
      toggleFavorite: (serverId) => {
        const favorites = get().favoriteServers;
        if (favorites.includes(serverId)) {
          set({ favoriteServers: favorites.filter((id) => id !== serverId) });
        } else {
          set({ favoriteServers: [...favorites, serverId] });
        }
      },
      setServerPing: (serverId, ping) => {
        const servers = get().servers.map((s) =>
          s.id === serverId ? { ...s, ping } : s
        );
        set({ servers });
      },

      // Settings actions
      updateSettings: (partial) =>
        set((state) => ({
          settings: { ...state.settings, ...partial },
        })),
      hydrateSettings: (s) =>
        set((state) => ({
          // Keep frontend-only preferences (notification detail sub-toggles)
          // that the Rust backend doesn't round-trip; merge the Rust-owned
          // fields on top of defaults + the current (localStorage) state.
          settings: {
            ...defaultSettings,
            ...s,
            // These come back as `false` from settingsFromRust (the Rust
            // backend doesn't store them) — re-apply the live localStorage
            // value so the user's choice survives a get_settings hydrate.
            showIpInNotification: state.settings.showIpInNotification,
            showLocationInNotification: state.settings.showLocationInNotification,
          },
          settingsHydrated: true,
        })),

      // Multi-Hop & Port Forwarding actions
      setPortForwards: (forwards) => set({ portForwards: forwards }),

      // Logout
      logout: () =>
        set({
          isAuthenticated: false,
          userEmail: null,
          account: { ...defaultAccount },
          connectionState: 'disconnected' as ConnectionState,
          currentServer: null,
          vpnIp: null,
          errorMessage: null,
          stats: {
            bytesSent: 0,
            bytesReceived: 0,
            connectedAt: null,
            serverName: null,
          },
          // Reset navigation so a logged-out user doesn't return to a stale
          // deep screen (settings/server list) on next login.
          tab: 'home' as TabId,
          navStack: [],
        }),
    }),
    {
      name: 'birdo-vpn-storage',
      // SECURITY: Only non-sensitive preferences persisted in localStorage.
      // Auth tokens and VPN keys remain in Rust-side native secure storage.
      partialize: (state) => ({
        favoriteServers: state.favoriteServers,
        settings: state.settings,
        hasAcceptedConsent: state.hasAcceptedConsent,
        theme: state.theme,
        windowCorner: state.windowCorner,
      }),
    }
  )
);
