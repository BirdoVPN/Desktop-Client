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
  | 'connected'
  | 'disconnecting'
  | 'reconnecting'
  | 'rekeying'
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

export interface AppSettings {
  killSwitchEnabled: boolean;
  autoConnect: boolean;
  autostart: boolean;
  startMinimized: boolean;
  notifications: boolean;
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
  setKillSwitch: (enabled: boolean) => void;
  setAutoConnect: (enabled: boolean) => void;
  setNotifications: (enabled: boolean) => void;

  // Actions — Multi-Hop & Port Forwarding
  setMultiHopRoutes: (routes: MultiHopRoute[]) => void;
  setPortForwards: (forwards: PortForward[]) => void;

  // Network
  isOnline: boolean;
  setOnline: (online: boolean) => void;

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
        set({
          settings: { ...defaultSettings, ...s },
          settingsHydrated: true,
        }),

      // Settings shortcuts
      setKillSwitch: (enabled) =>
        set((state) => ({
          settings: { ...state.settings, killSwitchEnabled: enabled },
        })),
      setAutoConnect: (enabled) =>
        set((state) => ({
          settings: { ...state.settings, autoConnect: enabled },
        })),
      setNotifications: (enabled) =>
        set((state) => ({
          settings: { ...state.settings, notifications: enabled },
        })),

      // Multi-Hop & Port Forwarding actions
      setMultiHopRoutes: (routes) => set({ multiHopRoutes: routes }),
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
        }),
    }),
    {
      name: 'birdo-vpn-storage',
      // SECURITY: Only non-sensitive preferences persisted in localStorage.
      // Auth tokens and VPN keys remain in Rust-side Windows Credential Manager.
      partialize: (state) => ({
        favoriteServers: state.favoriteServers,
        settings: state.settings,
        hasAcceptedConsent: state.hasAcceptedConsent,
      }),
    }
  )
);
