/**
 * Every way the UI changes the tunnel, in one module, shared by the Connect
 * screen, the tray, auto-connect, deep links and the update wall.
 *
 * These used to be written out separately in Dashboard (connect, multi-hop,
 * live switch, deep-link accept, tray connect, tray disconnect, auto-connect),
 * each setting `connectionState` optimistically and each settling it in its
 * own way — which is how an auto-connect left the UI stuck on "Connecting…"
 * over a working tunnel, and how a failed switch blanked the server card.
 *
 * The shape now: mark the command pending, run it, report its error if it had
 * one, re-read Rust's state, clear the pending mark. The displayed state is
 * always Rust's reading with the pending mark laid over it (`selectDisplayState`);
 * nothing here writes `connectionState` itself.
 */
import { invoke } from '@tauri-apps/api/core';
import {
  parseResumeTarget,
  parseVpnStatus,
  pickBestServer,
  toIpcError,
  type ResumeTarget,
} from '@/lib/ipc';
import { isSilentError } from '@/lib/errors';
import { nextServer, type SelectionOrigin } from '@/lib/server-choice';
import { command } from '@/session/command';
import { useAppStore, type PendingAction, type Server } from '@/store/app-store';
import { selectDisplayState, selectTunnelActive } from '@/store/selectors';

/** Re-read Rust's state now. A failed read changes nothing. */
export async function resyncStatus(): Promise<void> {
  try {
    const st = parseVpnStatus(await invoke('get_vpn_status'));
    if (st) useAppStore.getState().applyVpnStatus(st);
  } catch {
    /* the event path or the next resync will catch up */
  }
}

// A Disconnect pressed during a Connect supersedes it: the connect then
// resolves `cancelled`, and its `finally` must not clear the newer mark.
let pendingToken = 0;

async function run(
  pending: PendingAction,
  cmd: string,
  args?: Record<string, unknown>,
): Promise<boolean> {
  const token = ++pendingToken;
  const s = useAppStore.getState();
  s.setPendingAction(pending);
  s.setCommandError(null);
  try {
    await command(cmd, args);
    return true;
  } catch (e) {
    const err = toIpcError(e);
    // `cancelled` is the user's own Disconnect landing on an in-flight connect.
    if (!isSilentError(err)) useAppStore.getState().setCommandError(err);
    return false;
  } finally {
    // Read Rust's state BEFORE dropping the mark, so the screen goes straight
    // from "Connecting…" to the result instead of flashing the old state.
    await resyncStatus();
    if (token === pendingToken) useAppStore.getState().setPendingAction(null);
  }
}

const usable = (s: Server | null | undefined): s is Server => !!s && s.isOnline && s.isAccessible;

/** Resolve a live server id / name to a loaded server (never a partial cast, W2-040). */
export function findLiveServer(
  servers: readonly Server[],
  id: string | null,
  name: string | null,
): Server | null {
  if (id) return servers.find((s) => s.id === id) ?? null;
  if (name) return servers.find((s) => s.name === name) ?? null;
  return null;
}

/**
 * `connect_vpn`'s arguments: the server, and who chose it, on EVERY connect
 * (MR-2390). Rust keeps the origin with the session (`ReconnectInfo.origin`):
 * if the server later leaves the pool (a drain), Rust moves an `automatic`
 * pick to the best server anywhere and a `user` pick only within its country,
 * else it says the location is unavailable. It is the origin this store
 * records with the server (`lastServerOrigin`, MR-2492), so both sides read
 * the session the same way. Rust maps exactly `'automatic'` to the client's
 * pick and anything else to the user's (`SelectionOrigin::from_ipc`).
 */
function connectArgs(serverId: string, origin: SelectionOrigin): { serverId: string; origin: SelectionOrigin } {
  return { serverId, origin };
}

/**
 * Record where a connect to `dialledId` that SUCCEEDED really landed, under
 * the dial's origin. MR-2514: a server that never answered its first
 * handshake is retried once by Rust on another one, the client's pick
 * anywhere, a user's pick only within its own country; the move keeps who
 * chose (MR-2569), so a user's pick moved within its country stays the
 * user's and nothing later takes it abroad. The live server is recorded even
 * when the UI's list does not have it yet (review L1); the card follows once
 * the list does (`useSelectionFollowsTunnel`). Never called on a failure.
 */
function recordConnected(dialledId: string, origin: SelectionOrigin): void {
  const s = useAppStore.getState();
  const landedId = s.connectionState === 'connected' && s.liveServerId ? s.liveServerId : dialledId;
  if (landedId !== dialledId) {
    const landed = findLiveServer(s.servers, landedId, null);
    if (landed) s.setCurrentServer(landed);
  }
  s.setLastServerId(landedId, origin);
}

/**
 * `origin`: who chose `server` (MR-2492), sent to Rust with the connect
 * (MR-2390) and recorded with the server once connected.
 */
export async function connectToServer(server: Server, origin: SelectionOrigin = 'user'): Promise<boolean> {
  useAppStore.getState().setCurrentServer(server);
  const ok = await run('connecting', 'connect_vpn', connectArgs(server.id, origin));
  if (ok) recordConnected(server.id, origin);
  return ok;
}

/**
 * A live switch (W2-032): Rust tears the tunnel down and brings up a fresh
 * session on the new node with the kill switch held across the gap. Shown as
 * "Switching server…", and a failure puts the card back on the node the tunnel
 * is really on instead of blanking it.
 */
export async function switchToServer(server: Server): Promise<boolean> {
  const before = useAppStore.getState().currentServer;
  useAppStore.getState().setCurrentServer(server);
  // A server picked on a live session is the user's.
  const ok = await run('switching', 'connect_vpn', connectArgs(server.id, 'user'));
  const s = useAppStore.getState();
  if (ok) {
    s.setLastServerId(server.id, 'user');
  } else {
    s.setCurrentServer(findLiveServer(s.servers, s.liveServerId, s.liveServerName) ?? before);
  }
  return ok;
}

export function connectMultiHop(entryNodeId: string, exitNodeId: string): Promise<boolean> {
  return run('connecting', 'connect_multi_hop', { entryNodeId, exitNodeId });
}

/** Valid in every state (contract §3.1): cancels a connect, stops a reconnect loop, releases the block. */
export function disconnectVpn(): Promise<boolean> {
  return run('disconnecting', 'disconnect_vpn');
}

/** The Multi-Hop pair the user armed, if it can be dialled. */
export function readyMultiHopPair(): { entry: string; exit: string } | null {
  const { settings, servers } = useAppStore.getState();
  const { multiHopEnabled, multiHopEntryNodeId: entry, multiHopExitNodeId: exit } = settings;
  if (!multiHopEnabled || !entry || !exit || entry === exit) return null;
  if (servers.length > 0 && !(servers.some((s) => s.id === entry) && servers.some((s) => s.id === exit))) {
    return null;
  }
  return { entry, exit };
}

type ConnectState = Pick<
  ReturnType<typeof useAppStore.getState>,
  'currentServer' | 'lastServerId' | 'lastServerOrigin' | 'servers'
>;

/**
 * Who chose `server` (MR-2492). The server on record keeps the origin it was
 * recorded with; any other server on the card was put there by the user.
 */
function originOf(server: Server, state: ConnectState): SelectionOrigin {
  return server.id === state.lastServerId ? state.lastServerOrigin : 'user';
}

/**
 * The server a plain "Connect" means, and who chose it: the one on the card,
 * else the one the user last connected to, else the fastest (the client's
 * own pick). The same rule for the Connect button and the tray (W2-002,
 * W2-028). A click goes where the card says, the fastest server included;
 * Auto-Connect, which nobody clicks, follows `planUnattendedConnect`.
 */
export function resolveConnectChoice(
  state: ConnectState = useAppStore.getState(),
): { server: Server; origin: SelectionOrigin } | null {
  const { currentServer, lastServerId, servers } = state;
  if (usable(currentServer)) return { server: currentServer, origin: originOf(currentServer, state) };
  const remembered = servers.find((s) => s.id === lastServerId);
  if (usable(remembered)) return { server: remembered, origin: state.lastServerOrigin };
  const best = pickBestServer(servers);
  return best ? { server: best, origin: 'automatic' } : null;
}

/** The server of `resolveConnectChoice`: what the Connect card shows. */
export function resolveConnectTarget(state: ConnectState = useAppStore.getState()): Server | null {
  return resolveConnectChoice(state)?.server ?? null;
}

/** What Auto-Connect does at launch (MR-2492, `planUnattendedConnect`). */
export type UnattendedPlan =
  | { kind: 'dial'; server: Server; origin: SelectionOrigin }
  /** No server list to check it against: dial the user's server as recorded. */
  | { kind: 'dialRecorded'; serverId: string }
  /** No server list and no server the user chose: Rust picks (`quick_connect`). */
  | { kind: 'quickConnect' }
  /** The user's server cannot be used, nor another in its country. */
  | { kind: 'held' }
  /** No server this account can use at all. */
  | { kind: 'none' };

/**
 * Where Auto-Connect goes with nobody clicking (MR-2492, the owner's rule for
 * every client; iOS `RelayRetry`, Mobile #645). The server on record is
 * dialled when it can be used. When it cannot (offline, out of the plan,
 * gone), `nextServer` decides by who chose it: a server the client chose may
 * go to the best one in any country; one the user chose stays in its country
 * (the same city first), else nothing is dialled and the user is told. It
 * used to go to the fastest server in any country either way. One move: a
 * dial that then fails shows its error, as every connect does (a server
 * whose first handshake never comes gets Rust's one retry on another server
 * first, by the same rule, MR-2514).
 *
 * With no server list (the fetch failed) nothing can say the user's server
 * is gone, so it is dialled as recorded and Rust's connect answers for it,
 * never `quick_connect`, which picks a server of its own in any country
 * (MR-1932's rule for the resume after an update).
 */
export function planUnattendedConnect(state: ConnectState = useAppStore.getState()): UnattendedPlan {
  const { currentServer, lastServerId, lastServerOrigin, servers } = state;
  const chosenId = currentServer?.id ?? lastServerId;
  const origin = currentServer ? originOf(currentServer, state) : lastServerOrigin;
  if (servers.length === 0) {
    return chosenId && origin === 'user' ? { kind: 'dialRecorded', serverId: chosenId } : { kind: 'quickConnect' };
  }
  if (chosenId) {
    const chosen = servers.find((s) => s.id === chosenId);
    if (usable(chosen)) return { kind: 'dial', server: chosen, origin };
    const next = nextServer(chosenId, servers, origin);
    if (next) return { kind: 'dial', server: next.server, origin };
    if (origin === 'user') return { kind: 'held' };
  }
  const best = pickBestServer(servers);
  return best ? { kind: 'dial', server: best, origin: 'automatic' } : { kind: 'none' };
}

/** MR-2492: Auto-Connect found the user's server unusable and stayed in its country. */
export const AUTO_CONNECT_HELD_COPY =
  "Your server isn't available now, and BirdoVPN doesn't move you to another country by itself. " +
  'Choose a server to connect.';

const NO_SERVERS_COPY = 'No accessible online servers are available for this account.';

/**
 * Connect the way the user has set things up. A Multi-Hop route that is armed
 * but incomplete is NOT silently replaced by a single hop: the user paid for,
 * and chose, the separation. `unattended`: Auto-Connect, which nobody
 * clicked (`planUnattendedConnect`).
 */
export async function connectPreferred({ unattended = false } = {}): Promise<boolean> {
  const s = useAppStore.getState();
  if (s.settings.multiHopEnabled) {
    const pair = readyMultiHopPair();
    if (!pair) {
      s.showNotice({ text: 'Choose your Multi-Hop entry and exit servers first.', tone: 'info' });
      return false;
    }
    return connectMultiHop(pair.entry, pair.exit);
  }
  if (unattended) return connectUnattended();
  const choice = resolveConnectChoice();
  if (choice) return connectToServer(choice.server, choice.origin);
  if (s.servers.length > 0) {
    s.showNotice({ text: NO_SERVERS_COPY, tone: 'danger' });
    return false;
  }
  // The list has not loaded (offline start, slow backend): Rust has its own
  // copy and applies the same best-server rule.
  return run('connecting', 'quick_connect');
}

async function connectUnattended(): Promise<boolean> {
  const s = useAppStore.getState();
  const plan = planUnattendedConnect(s);
  switch (plan.kind) {
    case 'dial':
      return connectToServer(plan.server, plan.origin);
    case 'dialRecorded': {
      // Only ever the user's server (`planUnattendedConnect`).
      const ok = await run('connecting', 'connect_vpn', connectArgs(plan.serverId, 'user'));
      if (ok) recordConnected(plan.serverId, 'user');
      return ok;
    }
    case 'quickConnect':
      return run('connecting', 'quick_connect');
    case 'held':
      s.showNotice({ text: AUTO_CONNECT_HELD_COPY, tone: 'danger' });
      return false;
    case 'none':
      s.showNotice({ text: NO_SERVERS_COPY, tone: 'danger' });
      return false;
  }
}

/** MR-1861: shown while the session an update ended comes back. */
export const RESUME_AFTER_UPDATE_COPY = 'Reconnecting after the update…';

/**
 * The session an update ended (Rust's `commands::update_resume`): only on the
 * first start of the new version, only if the user was connected when the
 * update began, and only once. Null for nothing, or a failed read.
 */
export async function takeUpdateResume(): Promise<ResumeTarget | null> {
  try {
    return parseResumeTarget(await invoke('take_update_resume'));
  } catch {
    return null;
  }
}

/** MR-1932: the server the update ended is gone, offline or out of the plan now. */
export const RESUME_SERVER_GONE_COPY =
  "The server you were connected to before the update isn't available now, so BirdoVPN didn't " +
  'reconnect. Choose a server to connect.';

/** MR-1932: the same, for a Multi-Hop route (either of its servers). */
export const RESUME_ROUTE_GONE_COPY =
  "Your Multi-Hop route from before the update isn't available now, so BirdoVPN didn't " +
  'reconnect. Choose its servers again to connect.';

/**
 * Put back the session an update ended (MR-1861): the same server, or the
 * same Multi-Hop route, through the ordinary connect commands — so with the
 * saved settings, kill switch included.
 *
 * Exactly that session or none (MR-1932). The target is checked against the
 * settled server list: one that is gone, offline or no longer in the plan —
 * for Multi-Hop, either end of the route — is NOT replaced by another server
 * (it used to fall back to the plain Connect rule, possibly another country,
 * and a Multi-Hop route was dialled unchecked). The user is told and stays
 * disconnected. An EMPTY list (the fetch failed) cannot say a server is gone,
 * so the target is dialled as recorded and Rust's connect answers for it —
 * never `quick_connect`, which picks a server of its own. Once dialled, the
 * one exception is Rust's retry when that server never answers its first
 * handshake (MR-2514): it may move by the recorded origin, a user's pick only
 * within its country, and what it lands on is recorded (`recordConnected`).
 */
export async function resumeAfterUpdate(target: ResumeTarget): Promise<boolean> {
  const s = useAppStore.getState();
  const listed = s.servers.length > 0;
  const live = (id: string) => usable(s.servers.find((srv) => srv.id === id));
  if (target.kind === 'multiHop') {
    if (listed && !(live(target.entryId) && live(target.exitId))) {
      s.showNotice({ text: RESUME_ROUTE_GONE_COPY, tone: 'danger' });
      return false;
    }
    s.showNotice({ text: RESUME_AFTER_UPDATE_COPY, tone: 'info' });
    return connectMultiHop(target.entryId, target.exitId);
  }
  const server = s.servers.find((srv) => srv.id === target.serverId);
  if (listed && !usable(server)) {
    s.showNotice({ text: RESUME_SERVER_GONE_COPY, tone: 'danger' });
    return false;
  }
  s.showNotice({ text: RESUME_AFTER_UPDATE_COPY, tone: 'info' });
  // The same server, so whoever chose it still has (MR-2492).
  const origin: SelectionOrigin = s.lastServerId === target.serverId ? s.lastServerOrigin : 'user';
  if (usable(server)) return connectToServer(server, origin);
  const ok = await run('connecting', 'connect_vpn', connectArgs(target.serverId, origin));
  if (ok) recordConnected(target.serverId, origin);
  return ok;
}

/**
 * The Accept on a staged deep link. Re-checks the session at click time — it
 * may have changed while the dialog was open — and still refuses to turn a
 * live Multi-Hop route into one hop.
 */
export async function acceptDeepLink(target: Server): Promise<void> {
  const s = useAppStore.getState();
  s.setDeepLinkConfirm(null);
  if (selectTunnelActive(s) && s.liveMultiHop) {
    s.showNotice({
      text: 'That link would replace your Multi-Hop route with a single hop. Disconnect first if you meant to switch.',
      tone: 'danger',
    });
    return;
  }
  const d = selectDisplayState(s);
  if (d === 'connected' || d === 'reconnecting') await switchToServer(target);
  else if (d === 'disconnected' || d === 'error') await connectToServer(target);
  // Mid-transition (connecting, switching, disconnecting): ignore the link.
}
