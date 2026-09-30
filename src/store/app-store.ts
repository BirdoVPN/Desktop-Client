import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import type { IpcError, LiveMultiHop, VpnPhase, VpnState, VpnStats, VpnStatus } from '@/lib/ipc';
import { giveUpKind, type GiveUpKind } from '@/lib/errors';

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
  isPremium: boolean;
  /** Minimum plan required to connect: 'RECON' | 'OPERATIVE' | 'SOVEREIGN'. */
  minPlan?: string;
  /** Low-load / high-throughput node. Not a streaming-unblocking claim. */
  isHighSpeed: boolean;
  /** Node supports inbound port forwarding. Not a torrenting offer. */
  isPortForwarding: boolean;
  isOnline: boolean;
  isAccessible: boolean;
}

/**
 * The connection state RUST reports (contract v2 §1). The old union also had
 * `authenticating` / `stealth_connecting` (now `connecting` + `phase`) and
 * `rekeying` / `kill_switch_active`, which no Rust path ever produced (W2-004,
 * W2-039) — the "Kill switch is blocking" banner they gated was unreachable.
 * Blocking is the separate `killSwitchBlocking` bit now, because it is true
 * across several states (reconnecting, switching, error, always-on idle).
 */
export type ConnectionState = VpnState;

/**
 * A command the USER started that has not settled yet. Kept apart from
 * `connectionState` so an optimistic "Disconnecting…" is never mistaken for a
 * Rust reading, and a Rust reading can never be overwritten by an optimistic
 * guess (the stale-poll flip-back, W2-009). See `selectDisplayState`.
 */
export type PendingAction = 'connecting' | 'disconnecting' | 'switching';

export type LoadStatus = 'idle' | 'loading' | 'ready' | 'error';

export interface AccountInfo {
  email: string | null;
  /**
   * `null` = NOT KNOWN YET (W2-011). `get_auth_state` never carries a plan, so
   * this stays null until `get_subscription_status` answers, and a null read
   * as Recon showed paying users locks, upsells and "Free plan". Consumers go
   * through `lib/plan.ts`, whose rank is `null` for unknown.
   */
  plan: string | null;
  accountId: string | null;
  maxDevices: number;
  activeDevices: number;
  expiresAt: string | null;
  bandwidthUsed: number;
  bandwidthLimit: number;
  status: 'active' | 'expired' | 'cancelled' | 'unknown';
  /**
   * Whether the account has a password. SSO accounts have none, so the UI must
   * not demand one from them. Defaults to `true` so an unknown identity keeps
   * the confirmation prompt rather than silently dropping it.
   */
  hasPassword: boolean;
}

export type Protocol = 'wireguard';

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

// ── Navigation (the canonical four tabs + push sub-screens) ───────────────
export type TabId = 'profile' | 'home' | 'limit' | 'settings';
export type RouteId =
  | 'vpnSettings'
  | 'splitTunnel'
  | 'portForward'
  | 'pricing';

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
  /**
   * The user's Custom DNS addresses, kept while the feature is switched OFF
   * (P1-parity-042): Rust has one `custom_dns` field and no on/off flag, so
   * `settingsToRust` sends these only while `customDnsEnabled` is on and
   * `null` otherwise. Turning the switch off therefore no longer throws the
   * addresses away — they stay here (localStorage) until it is turned back on.
   */
  customDns: string[] | null;
  /** Frontend-only, like the notification sub-toggles. See `customDns`. */
  customDnsEnabled: boolean;
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
  // BirdoShield (OPEN-WORK D18): per-device DNS filtering (ads, trackers,
  // malware domains) at the VPN resolver. Sent as the `dnsFiltering` connect
  // flag by the Rust dial paths; OFF by default, available on every plan.
  dnsFiltering: boolean;
  // LOCKDOWN (always-on kill switch, Windows WFP). ON by default on Windows
  // (Rust `AppSettings::default()`, desktop #34); switchable in Settings ›
  // Privacy & Security › "Always-on Kill Switch" (Windows only, applies from
  // the next connection). Carried in the store so settings saves round-trip it
  // instead of silently resetting the persisted flag to the Rust serde default.
  lockdownMode: boolean;
  // Crash reports to Sentry. OPT-IN, OFF by default (audit 2026-09-29, C-3).
  // Written through the dedicated `set_crash_reports_enabled` command (consent
  // screen, Settings › Privacy & Security) and round-tripped by every full save.
  crashReportsEnabled: boolean;
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

/** `get_usage_stats` (/vpn/stats), camelCase on the wire. */
export interface UsageStats {
  plan: string | null;
  bandwidthLimitGb: number | null;
  bandwidthUsedGb: number | null;
  bandwidthPeriodEnd: string | null;
  bandwidthLastSyncAt: string | null;
  bandwidthIsFresh: boolean | null;
}

/** Why auto-reconnect stopped (P1-parity-020); rendered by `giveUpMessage`. */
export interface GiveUp {
  kind: GiveUpKind;
  attempts: number | null;
}

/**
 * The one transient message surface (W2-013): settings that failed to save, a
 * live reapply that failed, upsells, deep-link refusals. Rendered once, by
 * `NoticeHost`, as a polite live region — instead of each screen hand-rolling
 * its own toast or dropping the failure on the floor.
 */
export interface Notice {
  id: number;
  text: string;
  tone: 'info' | 'danger';
  actionLabel?: string;
  onAction?: () => void;
}

export interface AppState {
  // Auth
  isAuthenticated: boolean;
  isLoading: boolean;
  userEmail: string | null;
  /** Set when Rust (or a command) ended the session; Login shows why (W2-006). */
  sessionEndedReason: 'expired' | 'revoked' | null;

  // Consent
  hasAcceptedConsent: boolean;

  // Account
  account: AccountInfo;
  planStatus: LoadStatus;

  // Connection — what Rust last reported (see applyVpnStatus)
  connectionState: ConnectionState;
  vpnPhase: VpnPhase | null;
  reconnectAttempt: number | null;
  reconnectMax: number | null;
  killSwitchBlocking: boolean;
  /** The error Rust attached to the status (contract §1: non-null iff `error`). */
  vpnError: IpcError | null;
  /**
   * The error the user's own last command rejected with. Separate from
   * `vpnError` so a status reading that says nothing about errors (a pre-v2
   * backend, or a refusal that left Rust in `disconnected`) cannot erase the
   * answer to what the user just clicked. Cleared by the next command, or once
   * a tunnel is up.
   */
  commandError: IpcError | null;
  giveUp: GiveUp | null;
  liveServerId: string | null;
  /** Fallback for resolving the live server on a backend without `server_id`. */
  liveServerName: string | null;
  liveMultiHop: LiveMultiHop | null;
  stealthActive: boolean;
  connectedAt: string | null;
  /**
   * Byte counters, uptime and latency from `get_vpn_stats`, polled only while
   * the window is visible and a tunnel is up. Its own field so a 2 s counter
   * tick re-renders the stats row and nothing else.
   */
  liveStats: VpnStats | null;
  /**
   * Physical adapters whose DNS this session could not verifiably park or put
   * back. Held across every connection state on purpose: the failure that
   * matters most is an adapter left un-restored AFTER a disconnect, and clearing
   * it on disconnect would hide exactly the case it exists for.
   */
  dnsDegraded: string[];
  /** Last applied status `seq`; statuses older than this are dropped (W2-009). */
  statusSeq: number;
  pendingAction: PendingAction | null;

  /** The user's server choice (not necessarily the one the tunnel is on). */
  currentServer: Server | null;
  /**
   * The server the user last actually connected to. Persisted (currentServer is
   * not), so a cold start restores the node you always use instead of showing
   * "Choose a server" and then silently connecting you to whichever server
   * happens to sort first in the list.
   */
  lastServerId: string | null;

  // Servers
  servers: Server[];
  serversStatus: LoadStatus;
  /**
   * Latency per server id, kept apart from `servers` so a ping result touches
   * one map instead of re-creating every server object (and re-rendering every
   * subscriber) per probe, and so a list refresh keeps the last measurements
   * instead of blanking them (W2-023).
   */
  serverPings: Record<string, number>;
  favoriteServers: string[];

  // Usage (Limit tab)
  usage: UsageStats | null;
  usageStatus: LoadStatus;

  // Settings
  settings: AppSettings;
  settingsHydrated: boolean;
  /** A live `reapply_vpn_settings` is in flight (VPN Settings says so). */
  reapplying: boolean;

  /**
   * BirdoShield (D18) FLEET GATE, from `GET /api/client-config`
   * (`dnsFilteringAvailable` = the backend's `DNS_FILTERING_ENABLED`).
   *
   * Distinct from the per-device `settings.dnsFiltering` preference: this says
   * whether turning that preference on can do anything. With the gate off the
   * backend ignores the connect flag and hands out the normal resolver, so a
   * toggle that read ON would be reassurance from missing data.
   *
   * DEFAULTS TO TRUE, and is deliberately NOT persisted (see `partialize`) and
   * NOT cleared on logout — it is a property of the fleet, not of the account.
   * True is the safe default because the failure mode it guards is asymmetric:
   * a wrongly-`false` value HIDES a feature that works (and loses the user
   * filtering they paid attention to), while a wrongly-`true` one costs a
   * greyed-out row appearing a moment late. Only an explicit `false` from the
   * server disables the row; an unreachable server, a 500, an older web deploy
   * that predates the field, or a cold start before the fetch all leave it on.
   *
   * Typed `boolean | undefined`, not `boolean`, so the type carries the
   * tri-state the rule is written against: consumers must test `=== false`,
   * and a `!available` that treats unknown as off is then a type-visible
   * change of meaning rather than an invisible one.
   */
  dnsFilteringAvailable: boolean | undefined;
  setDnsFilteringAvailable: (available: boolean) => void;

  portForwards: PortForward[];

  /** `null` until `get_admin_status` answers, so the warning cannot flash at startup. */
  isAdmin: boolean | null;

  notice: Notice | null;

  // Network
  isOnline: boolean;

  // Window position (frameless corner anchor / draggable). Persisted.
  windowCorner: WindowCorner;

  // Deep link
  deepLinkAction: { action: string; serverId?: string } | null;
  /**
   * A birdo://connect target staged for an explicit Accept (W2 "must not be
   * broken": a link is third-party input and never moves the egress on its
   * own). Rendered by AppShell so it shows on whatever tab is open.
   */
  deepLinkConfirm: Server | null;

  // ── Navigation (NOT persisted) ─────────────────────────────────────────
  tab: TabId;
  navStack: RouteId[];

  // Actions
  setAuthenticated: (auth: boolean) => void;
  setLoading: (loading: boolean) => void;
  setUserEmail: (email: string | null) => void;
  setSessionEndedReason: (reason: 'expired' | 'revoked' | null) => void;
  setConsent: (accepted: boolean) => void;
  setAccount: (account: Partial<AccountInfo>) => void;
  setPlanStatus: (status: LoadStatus) => void;
  setIsAdmin: (admin: boolean) => void;
  /**
   * Apply a Rust status reading. Returns false when it was dropped for being
   * older than what is already on screen. Writes only the fields that changed,
   * so an idle resync re-renders nothing (W2-037).
   */
  applyVpnStatus: (status: VpnStatus) => boolean;
  /** A local mirror of a state Rust is known to have reached (no seq). */
  setConnectionState: (state: ConnectionState) => void;
  setPendingAction: (action: PendingAction | null) => void;
  setCommandError: (error: IpcError | null) => void;
  setLiveStats: (stats: VpnStats | null) => void;
  setCurrentServer: (server: Server | null) => void;
  setLastServerId: (id: string | null) => void;
  setServers: (servers: Server[]) => void;
  setServersStatus: (status: LoadStatus) => void;
  mergeServerPings: (pings: Record<string, number>) => void;
  toggleFavorite: (serverId: string) => void;
  setUsage: (usage: UsageStats | null, status: LoadStatus) => void;
  updateSettings: (settings: Partial<AppSettings>) => void;
  hydrateSettings: (settings: AppSettings) => void;
  setReapplying: (reapplying: boolean) => void;
  setPortForwards: (forwards: PortForward[]) => void;
  showNotice: (notice: Omit<Notice, 'id'>) => number;
  dismissNotice: (id: number) => void;
  setOnline: (online: boolean) => void;
  setWindowCorner: (corner: WindowCorner) => void;
  setDeepLinkAction: (action: { action: string; serverId?: string } | null) => void;
  setDeepLinkConfirm: (server: Server | null) => void;
  setTab: (tab: TabId) => void;
  pushRoute: (route: RouteId) => void;
  popRoute: () => void;
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
  hasPassword: true,
};

export const defaultSettings: AppSettings = {
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
  customDnsEnabled: false,
  protocol: 'wireguard',
  localNetworkSharing: false,
  wireGuardPort: 'auto',
  wireGuardMtu: 0,
  multiHopEnabled: false,
  multiHopEntryNodeId: null,
  multiHopExitNodeId: null,
  stealthMode: false,
  // BirdoShield is opt-in — matches the Rust `AppSettings::default()`.
  dnsFiltering: false,
  // Post-quantum protection (BirdoPQ / ML-KEM-1024) is ON by default for all
  // users — available on every plan, negligible overhead. Matches the Rust
  // `AppSettings::default()` so a fresh install agrees on both sides.
  quantumProtection: true,
  // Matches the Rust `default_true` serde default for lockdown_mode.
  lockdownMode: true,
  // Crash reporting is opt-in — matches the Rust `AppSettings::default()`.
  crashReportsEnabled: false,
};

/** The session's connection fields, as they are with no tunnel and no reading. */
const idleConnection = {
  connectionState: 'disconnected' as ConnectionState,
  vpnPhase: null,
  reconnectAttempt: null,
  reconnectMax: null,
  killSwitchBlocking: false,
  vpnError: null,
  commandError: null,
  giveUp: null,
  liveServerId: null,
  liveServerName: null,
  liveMultiHop: null,
  stealthActive: false,
  connectedAt: null,
  liveStats: null,
  pendingAction: null,
};

const sameStrings = (a: readonly string[], b: readonly string[]) =>
  a.length === b.length && a.every((v, i) => v === b[i]);

const sameError = (a: IpcError | null, b: IpcError | null) =>
  a === b || (!!a && !!b && a.code === b.code && a.message === b.message);

const sameRoute = (a: LiveMultiHop | null, b: LiveMultiHop | null) =>
  a === b || (!!a && !!b && a.entryId === b.entryId && a.exitId === b.exitId);

let noticeSeq = 0;

/** The store's state, for helpers that take a snapshot (selectors, tests). */
export type AppStateSnapshot = AppState;

export const useAppStore = create<AppState>()(
  persist(
    (set, get) => ({
      isAuthenticated: false,
      isLoading: false,
      userEmail: null,
      sessionEndedReason: null,
      hasAcceptedConsent: false,
      isOnline: true,
      account: { ...defaultAccount },
      planStatus: 'idle',

      ...idleConnection,
      dnsDegraded: [],
      statusSeq: -1,

      currentServer: null,
      lastServerId: null,
      servers: [],
      serversStatus: 'idle',
      serverPings: {},
      favoriteServers: [],
      usage: null,
      usageStatus: 'idle',

      settings: { ...defaultSettings },
      settingsHydrated: false,
      reapplying: false,

      // See the AppState doc comment: true until the server says otherwise.
      dnsFilteringAvailable: true,
      setDnsFilteringAvailable: (dnsFilteringAvailable) => set({ dnsFilteringAvailable }),

      portForwards: [],
      isAdmin: null,
      notice: null,
      windowCorner: 'bottom-left' as WindowCorner,
      deepLinkAction: null,
      deepLinkConfirm: null,
      tab: 'home' as TabId,
      navStack: [],

      setAuthenticated: (auth) => set({ isAuthenticated: auth }),
      setLoading: (loading) => set({ isLoading: loading }),
      setUserEmail: (email) => set({ userEmail: email }),
      setSessionEndedReason: (sessionEndedReason) => set({ sessionEndedReason }),
      setConsent: (accepted) => set({ hasAcceptedConsent: accepted }),
      setAccount: (partial) => set((state) => ({ account: { ...state.account, ...partial } })),
      setPlanStatus: (planStatus) => set({ planStatus }),
      setIsAdmin: (admin) => set({ isAdmin: admin }),

      applyVpnStatus: (st) => {
        const s = get();
        // Contract §1: drop anything older than what is already applied. An
        // EQUAL seq is the same state re-read (a resync), so it is applied —
        // it can only refresh fields, never move the state backwards.
        if (st.seq !== null && st.seq < s.statusSeq) return false;

        const patch: Partial<AppState> = {};
        if (st.seq !== null && st.seq !== s.statusSeq) patch.statusSeq = st.seq;
        if (st.state !== s.connectionState) patch.connectionState = st.state;
        if (st.phase !== s.vpnPhase) patch.vpnPhase = st.phase;
        if (st.reconnectAttempt !== s.reconnectAttempt) patch.reconnectAttempt = st.reconnectAttempt;
        if (st.reconnectMax !== s.reconnectMax) patch.reconnectMax = st.reconnectMax;
        if (st.killSwitchBlocking !== s.killSwitchBlocking) patch.killSwitchBlocking = st.killSwitchBlocking;
        if (st.serverId !== s.liveServerId) patch.liveServerId = st.serverId;
        if (st.serverName !== s.liveServerName) patch.liveServerName = st.serverName;
        if (!sameRoute(st.multiHop, s.liveMultiHop)) patch.liveMultiHop = st.multiHop;
        if (st.stealthActive !== s.stealthActive) patch.stealthActive = st.stealthActive;
        if (st.connectedAt !== s.connectedAt) patch.connectedAt = st.connectedAt;
        if (st.dnsDegraded !== undefined && !sameStrings(st.dnsDegraded, s.dnsDegraded)) {
          patch.dnsDegraded = st.dnsDegraded;
        }

        // `undefined` = a pre-v2 backend that does not send the field: it
        // says nothing about errors, so it changes nothing.
        if (st.error !== undefined && !sameError(st.error, s.vpnError)) patch.vpnError = st.error;
        if (st.state === 'connected' && s.commandError) patch.commandError = null;

        // Auto-reconnect gave up: the only way into `error` from `reconnecting`.
        if (s.connectionState === 'reconnecting' && st.state === 'error') {
          patch.giveUp = {
            kind: giveUpKind(st.error ?? null),
            attempts: st.reconnectAttempt ?? st.reconnectMax,
          };
        } else if (st.state !== 'error' && s.giveUp) {
          patch.giveUp = null;
        }

        if (Object.keys(patch).length > 0) set(patch);
        return true;
      },
      setConnectionState: (connectionState) =>
        set({
          connectionState,
          ...(connectionState !== 'error' ? { vpnError: null, commandError: null, giveUp: null } : {}),
          ...(connectionState === 'disconnected' ? { killSwitchBlocking: false } : {}),
        }),
      setPendingAction: (pendingAction) => set({ pendingAction }),
      setCommandError: (commandError) => set({ commandError }),
      setLiveStats: (liveStats) => set({ liveStats }),
      setCurrentServer: (currentServer) => set({ currentServer }),
      setLastServerId: (lastServerId) => set({ lastServerId }),

      setServers: (servers) => set({ servers }),
      setServersStatus: (serversStatus) => set({ serversStatus }),
      mergeServerPings: (pings) =>
        set((state) => ({ serverPings: { ...state.serverPings, ...pings } })),
      toggleFavorite: (serverId) => {
        const favorites = get().favoriteServers;
        set({
          favoriteServers: favorites.includes(serverId)
            ? favorites.filter((id) => id !== serverId)
            : [...favorites, serverId],
        });
      },
      setUsage: (usage, usageStatus) => set({ usage, usageStatus }),

      updateSettings: (partial) =>
        set((state) => ({ settings: { ...state.settings, ...partial } })),
      hydrateSettings: (s) =>
        set((state) => ({
          // Keep frontend-only preferences that the Rust backend doesn't
          // round-trip; merge the Rust-owned fields on top of defaults + the
          // current (localStorage) state.
          settings: {
            ...defaultSettings,
            ...s,
            // These come back as `false` from settingsFromRust (the Rust
            // backend doesn't store them) — re-apply the live localStorage
            // value so the user's choice survives a get_settings hydrate.
            showIpInNotification: state.settings.showIpInNotification,
            showLocationInNotification: state.settings.showLocationInNotification,
            // Rust sends `custom_dns: null` while Custom DNS is switched off;
            // the addresses the user entered live here (see AppSettings).
            customDns: s.customDns ?? state.settings.customDns,
          },
          settingsHydrated: true,
        })),
      setReapplying: (reapplying) => set({ reapplying }),
      setPortForwards: (forwards) => set({ portForwards: forwards }),

      showNotice: (notice) => {
        const id = ++noticeSeq;
        set({ notice: { ...notice, id } });
        return id;
      },
      dismissNotice: (id) => {
        if (get().notice?.id === id) set({ notice: null });
      },

      setOnline: (online) => set({ isOnline: online }),
      setWindowCorner: (windowCorner) => set({ windowCorner }),
      setDeepLinkAction: (action) => set({ deepLinkAction: action }),
      setDeepLinkConfirm: (deepLinkConfirm) => set({ deepLinkConfirm }),

      setTab: (tab) => set({ tab, navStack: [] }),
      pushRoute: (route) => set((state) => ({ navStack: [...state.navStack, route] })),
      popRoute: () => set((state) => ({ navStack: state.navStack.slice(0, -1) })),

      logout: () =>
        set({
          isAuthenticated: false,
          userEmail: null,
          account: { ...defaultAccount },
          planStatus: 'idle',
          ...idleConnection,
          currentServer: null,
          // Cleared on logout: the next account to sign in on this machine must
          // not inherit the previous user's server choice, server access or usage.
          lastServerId: null,
          servers: [],
          serversStatus: 'idle',
          serverPings: {},
          usage: null,
          usageStatus: 'idle',
          portForwards: [],
          notice: null,
          deepLinkConfirm: null,
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
        lastServerId: state.lastServerId,
        settings: state.settings,
        hasAcceptedConsent: state.hasAcceptedConsent,
        windowCorner: state.windowCorner,
      }),
      // The default merge is shallow, so a settings object saved by an older
      // build would REPLACE the defaults wholesale and leave any field added
      // since (customDnsEnabled) undefined. Merge it over the defaults instead,
      // and carry an existing Custom DNS list over as "on" — before the switch
      // existed, a non-empty list was the only way the feature could be on.
      merge: (persisted, current) => {
        const p = (persisted ?? {}) as Partial<AppState>;
        const saved = (p.settings ?? {}) as Partial<AppSettings>;
        const settings: AppSettings = {
          ...current.settings,
          ...saved,
          customDnsEnabled:
            saved.customDnsEnabled ?? (Array.isArray(saved.customDns) && saved.customDns.length > 0),
        };
        return { ...current, ...p, settings };
      },
    },
  ),
);
