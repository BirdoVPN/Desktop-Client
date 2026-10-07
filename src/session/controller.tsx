/**
 * The session controller: everything that watches or drives the VPN for the
 * lifetime of a signed-in session, mounted ONCE by App — above the biometric
 * cover and the update wall, independent of which tab is showing (W2-001).
 *
 * All of this used to live in Dashboard, which AppShell unmounts on every tab
 * switch and App unmounts under the lock and the wall. So with the window on
 * Settings, or hidden to the tray behind Hide App Contents, nothing polled:
 * the tunnel could drop, reconnect or give up with no notification, and tray
 * Quick Connect / Disconnect restored the window and then did nothing because
 * nobody was listening. Auto-connect ran again on every return to Home (W2-002).
 *
 * Rust is the source of truth (contract v2): it pushes `vpn-status-changed`
 * from its state choke point. The `get_vpn_status` read here is only a resync
 * fallback — on start, when the window comes back, and every
 * `RESYNC_INTERVAL_MS` while it is visible — and both paths go through the
 * store's seq check, so a slow read can never undo a newer event (W2-009).
 */
import { useEffect, useRef } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';
import { parseQuotaWarning, parseSessionExpired, parseVpnStats, parseVpnStatus } from '@/lib/ipc';
import { errorCopy, giveUpMessage, quotaGraceMessage } from '@/lib/errors';
import { useAppStore, type Server } from '@/store/app-store';
import { selectTunnelActive } from '@/store/selectors';
import { endSession } from '@/session/session';
import {
  loadAdminStatus,
  loadServers,
  loadSubscription,
  resetSessionData,
} from '@/session/session-data';
import { connectPreferred, findLiveServer } from '@/session/vpn-actions';
import {
  persistSettings,
  reloadSettings,
  watchKillSwitchAcrossDials,
} from '@/session/settings-persist';
import { useCustomDnsGate } from '@/session/custom-dns-gate';
import {
  connectionNotification,
  initNotifications,
  notifyConnected,
  notifyConnectionError,
  notifyConnectionLost,
  notifyDisconnected,
  notifyKillSwitchActive,
  notifyQuotaGrace,
  notifyReconnected,
} from '@/utils/notifications';

export const RESYNC_INTERVAL_MS = 10_000;
export const STATS_INTERVAL_MS = 2_000;

/** `listen` resolves asynchronously; tear down whichever way it settles. */
function unlistenLater(p: Promise<UnlistenFn>): () => void {
  return () => {
    p.then((off) => off()).catch(() => {});
  };
}

/**
 * Whether anyone can see the window. `document.hidden` alone is not enough:
 * whether WebView2 flips it on hide-to-tray is unverified (W2 §e), and Rust's
 * `app-hidden` / `app-shown` events are the certain signal for that case.
 */
let hiddenToTray = false;
const windowVisible = () => !document.hidden && !hiddenToTray;

function useStatusSync(): void {
  useEffect(() => {
    let disposed = false;
    const apply = (raw: unknown) => {
      const st = parseVpnStatus(raw);
      if (st && !disposed) useAppStore.getState().applyVpnStatus(st);
    };
    const resync = () => {
      invoke('get_vpn_status').then(apply).catch(() => {
        /* the next event or resync catches up */
      });
    };

    const offStatus = unlistenLater(listen('vpn-status-changed', (e) => apply(e.payload)));
    const offShown = unlistenLater(
      listen('app-shown', () => {
        hiddenToTray = false;
        resync();
      }),
    );
    const offHidden = unlistenLater(
      listen('app-hidden', () => {
        hiddenToTray = true;
      }),
    );
    const onVisibility = () => {
      if (windowVisible()) resync();
    };
    document.addEventListener('visibilitychange', onVisibility);
    const timer = setInterval(() => {
      if (windowVisible()) resync();
    }, RESYNC_INTERVAL_MS);
    resync();

    return () => {
      disposed = true;
      offStatus();
      offShown();
      offHidden();
      document.removeEventListener('visibilitychange', onVisibility);
      clearInterval(timer);
    };
  }, []);
}

/**
 * Counters only (the contract never pushes stats): polled while the window is
 * visible and a tunnel is up, and not at all otherwise — nobody reads a byte
 * count in the tray.
 */
function useStatsPoll(): void {
  const connected = useAppStore((s) => s.connectionState === 'connected');
  useEffect(() => {
    if (!connected) {
      useAppStore.getState().setLiveStats(null);
      return;
    }
    let disposed = false;
    const poll = () => {
      if (!windowVisible()) return;
      invoke('get_vpn_stats')
        .then((raw) => {
          const stats = parseVpnStats(raw);
          if (!disposed && stats) useAppStore.getState().setLiveStats(stats);
        })
        .catch(() => {});
    };
    poll();
    const timer = setInterval(poll, STATS_INTERVAL_MS);
    const onVisibility = () => {
      if (windowVisible()) poll();
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      disposed = true;
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [connected]);
}

/**
 * Tray Quick Connect and Disconnect run in Rust (W1-023, W2-003): they must work
 * with the window hidden, behind the biometric cover or with the webview
 * suspended, so the UI no longer acts on the `tray-*` events — acting as well
 * dialled twice. Rust cannot read this store, though, so mirror the user's
 * server into the Rust setting quick-connect does read (`preferred_server_id`):
 * the tray then dials the server the Connect button would, not merely the
 * least-loaded one. Waits for hydration because `persistSettings` writes the
 * whole settings object, and writing it before Rust's copy has loaded would
 * replace the user's settings with defaults.
 */
function usePreferredServerMirror(): void {
  const lastServerId = useAppStore((s) => s.lastServerId);
  const hydrated = useAppStore((s) => s.settingsHydrated);
  useEffect(() => {
    if (!hydrated || !lastServerId) return;
    if (useAppStore.getState().settings.preferredServerId === lastServerId) return;
    void persistSettings({ preferredServerId: lastServerId }, { quiet: true });
  }, [hydrated, lastServerId]);
}

/** Contract §3.3: Rust already tore down and cleared tokens; route to Login. */
function useSessionExpiry(): void {
  useEffect(
    () => unlistenLater(listen('session-expired', (e) => endSession(parseSessionExpired(e.payload)))),
    [],
  );
}

function useSessionData(): void {
  useEffect(() => {
    void reloadSettings();
    void loadAdminStatus();
    void loadSubscription();
    void loadServers();
    // Coming back from the tray: refresh whatever is past its TTL.
    const offShown = unlistenLater(
      listen('app-shown', () => {
        void loadSubscription();
        void loadServers();
      }),
    );
    return () => {
      offShown();
      resetSessionData();
    };
  }, []);
}

/**
 * Auto-Connect, once per signed-in session (W2-002; iOS runs it once per login
 * state change). It waits for the saved settings and the server list, so it
 * can connect to the user's own server rather than whatever sorts first, and a
 * ref — not the mount — is what makes it once: this component outlives tab
 * switches, the lock and the wall, and the ref outlives StrictMode's re-run.
 */
function useAutoConnectOnce(): void {
  const done = useRef(false);
  const hydrated = useAppStore((s) => s.settingsHydrated);
  const serversSettled = useAppStore(
    (s) => s.serversStatus === 'ready' || s.serversStatus === 'error',
  );
  // Once this run has connected or disconnected, Auto-Connect's moment has
  // passed (round 7 of the review of #222, N3): settings that count as loaded
  // only later — a save landing after a start-up that could not verify the
  // file (24dc7f2) — must not dial on their own, after a Disconnect the user
  // chose.
  useEffect(
    () =>
      useAppStore.subscribe((next, prev) => {
        if (next.connectionState !== prev.connectionState) done.current = true;
      }),
    [],
  );
  useEffect(() => {
    if (done.current || !hydrated || !serversSettled) return;
    done.current = true;
    const s = useAppStore.getState();
    if (!s.settings.autoConnect) return;
    if (selectTunnelActive(s)) return;
    void connectPreferred();
  }, [hydrated, serversSettled]);
}

function serverLabel(server: Server | null, fallback: string | null): string {
  return server?.name || fallback || '';
}

function useConnectionNotifications(): void {
  useEffect(() => {
    void initNotifications();
    return useAppStore.subscribe((next, prev) => {
      if (
        next.connectionState === prev.connectionState &&
        next.killSwitchBlocking === prev.killSwitchBlocking
      ) {
        return;
      }
      const event = connectionNotification(
        { state: prev.connectionState, blocking: prev.killSwitchBlocking },
        { state: next.connectionState, blocking: next.killSwitchBlocking },
        next.pendingAction !== null,
      );
      if (!event) return;
      switch (event.kind) {
        case 'protected': {
          // The EXIT is where traffic leaves, so it is the server and IP the
          // user is "via" — for Multi-Hop the entry node was named before
          // (W2-031).
          const route = next.liveMultiHop;
          const live = route
            ? next.servers.find((s) => s.id === route.exitId) ?? null
            : findLiveServer(next.servers, next.liveServerId, next.liveServerName);
          const name = route
            ? `${route.entryName || 'entry'} → ${route.exitName || 'exit'}`
            : serverLabel(live, next.liveServerName);
          const details = {
            ip: live?.ipAddress ?? live?.hostname ?? null,
            location: live ? [live.city, live.country].filter(Boolean).join(', ') : null,
          };
          if (event.reconnected) notifyReconnected(name, details);
          else notifyConnected(name, details);
          break;
        }
        case 'reconnecting':
          notifyConnectionLost();
          break;
        case 'not_connected':
          notifyDisconnected();
          break;
        case 'error': {
          // A give-up says that reconnecting stopped and whether traffic is
          // still blocked, as the Home banner does (REVIEW-WIN-009).
          const err = next.vpnError ?? next.commandError;
          notifyConnectionError(
            next.giveUp
              ? giveUpMessage(next.giveUp.kind, next.giveUp.attempts, next.killSwitchBlocking)
              : err
                ? errorCopy(err, 'vpn').message
                : 'The VPN connection stopped. Open BirdoVPN to reconnect.',
          );
          break;
        }
        case 'blocking':
          notifyKillSwitchActive();
          break;
      }
    });
  }, []);
}

/**
 * The card follows the tunnel: after a tray connect, auto-connect or a
 * Rust-side reconnect onto another node, show the server the tunnel is really
 * on — resolved against the loaded list, never a `{ name }` cast to a Server.
 */
function useSelectionFollowsTunnel(): void {
  const liveServerId = useAppStore((s) => s.liveServerId);
  const liveServerName = useAppStore((s) => s.liveServerName);
  const servers = useAppStore((s) => s.servers);
  const connected = useAppStore((s) => s.connectionState === 'connected');
  useEffect(() => {
    const s = useAppStore.getState();
    if (!connected || s.pendingAction !== null || s.liveMultiHop) return;
    const live = findLiveServer(servers, liveServerId, liveServerName);
    if (live && s.currentServer?.id !== live.id) {
      s.setCurrentServer(live);
      s.setLastServerId(live.id);
    }
  }, [liveServerId, liveServerName, servers, connected]);
}

/**
 * Deep links (birdo://connect/<id>). App.tsx validates and stages the id; this
 * resolves it against the server list — waiting for the list if it has not
 * loaded — and stages the target for an explicit Accept. A link is third-party
 * input: it NEVER moves the egress by itself, and it can never downgrade a live
 * Multi-Hop session to one hop.
 */
function useDeepLinkConnect(): void {
  const deepLinkAction = useAppStore((s) => s.deepLinkAction);
  const servers = useAppStore((s) => s.servers);
  useEffect(() => {
    if (!deepLinkAction) return;
    const s = useAppStore.getState();
    if (deepLinkAction.action !== 'connect' || !deepLinkAction.serverId) {
      // 'settings' is App.tsx's setTab; nothing to do here.
      s.setDeepLinkAction(null);
      return;
    }
    const target = servers.find((srv) => srv.id === deepLinkAction.serverId);
    if (!target) {
      if (servers.length > 0) {
        s.showNotice({ text: 'The server in that link is unknown for this account.', tone: 'danger' });
        s.setDeepLinkAction(null);
      }
      return;
    }
    s.setDeepLinkAction(null);
    if (!target.isOnline || !target.isAccessible) {
      s.showNotice({ text: 'That server is offline or not included in your plan.', tone: 'danger' });
      return;
    }
    if (selectTunnelActive(s) && s.liveMultiHop) {
      s.showNotice({
        text: 'That link would replace your Multi-Hop route with a single hop. Disconnect first if you meant to switch.',
        tone: 'danger',
      });
      return;
    }
    s.setDeepLinkConfirm(target);
  }, [deepLinkAction, servers]);
}

/**
 * Multi-Hop selections whose node was retired. The ids are persisted and
 * nothing removed them, so the picker sat blank and Connect refused with no
 * explanation. Pruned only against a NON-EMPTY list (an empty one is far more
 * likely a failed fetch than a fleet that ceased to exist) and never under a
 * live session's route.
 */
function useMultiHopPrune(): void {
  const servers = useAppStore((s) => s.servers);
  useEffect(() => {
    const s = useAppStore.getState();
    if (servers.length === 0 || selectTunnelActive(s)) return;
    const { multiHopEntryNodeId: entry, multiHopExitNodeId: exit } = s.settings;
    const live = new Set(servers.map((srv) => srv.id));
    const entryGone = !!entry && !live.has(entry);
    const exitGone = !!exit && !live.has(exit);
    if (!entryGone && !exitGone) return;
    void persistSettings({
      ...(entryGone ? { multiHopEntryNodeId: null } : {}),
      ...(exitGone ? { multiHopExitNodeId: null } : {}),
    });
    s.showNotice({
      text:
        entryGone && exitGone
          ? 'Both of your Multi-Hop servers were retired. Pick a new entry and exit.'
          : entryGone
            ? 'Your Multi-Hop entry server was retired. Pick a new one.'
            : 'Your Multi-Hop exit server was retired. Pick a new one.',
      tone: 'info',
    });
  }, [servers]);
}

/**
 * Rust rebuilt the session over the stealth transport because direct WireGuard
 * got no handshake (a DPI-filtered network). Said once, as information — the
 * "Stealth" chip reports it for the rest of the session. Never red.
 */
function useStealthFallbackNotice(): void {
  useEffect(
    () =>
      unlistenLater(
        listen('adaptive-transport-fallback', () => {
          useAppStore.getState().showNotice({
            text: 'This network blocks standard VPN traffic — using Stealth Mode.',
            tone: 'info',
          });
        }),
      ),
    [],
  );
}

/**
 * The Free allowance is used up and the server ends the session when its grace
 * window closes (birdo-web #590). Rust sends this once per session; the
 * session itself is untouched until the server ends it, which arrives as an
 * `error` status with `quota_exceeded`. Non-blocking: a notice in the window
 * and, since the app usually sits in the tray, a system notification.
 */
function useQuotaWarning(): void {
  useEffect(
    () =>
      unlistenLater(
        listen('quota-warning', (e) => {
          const text = quotaGraceMessage(parseQuotaWarning(e.payload).secondsRemaining);
          const s = useAppStore.getState();
          s.showNotice({
            text,
            tone: 'info',
            actionLabel: 'View plans',
            onAction: () => useAppStore.getState().pushRoute('pricing'),
          });
          notifyQuotaGrace(text);
        }),
      ),
    [],
  );
}

/**
 * The kill switch toggle across dials (round 5 of the review of #222;
 * `watchKillSwitchAcrossDials`).
 */
function useKillSwitchAcrossDials(): void {
  useEffect(() => watchKillSwitchAcrossDials(), []);
}

/** Renderless. Mounted by App for the whole signed-in session. */
export function VpnSessionController(): null {
  useStatusSync();
  useStatsPoll();
  usePreferredServerMirror();
  useCustomDnsGate();
  useSessionExpiry();
  useSessionData();
  useAutoConnectOnce();
  useConnectionNotifications();
  useSelectionFollowsTunnel();
  useDeepLinkConnect();
  useMultiHopPrune();
  useStealthFallbackNotice();
  useQuotaWarning();
  useKillSwitchAcrossDials();
  return null;
}
