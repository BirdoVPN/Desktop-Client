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
import { parseVpnStatus, pickBestServer, toIpcError } from '@/lib/ipc';
import { isSilentError } from '@/lib/errors';
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

export async function connectToServer(server: Server): Promise<boolean> {
  useAppStore.getState().setCurrentServer(server);
  const ok = await run('connecting', 'connect_vpn', { serverId: server.id });
  if (ok) useAppStore.getState().setLastServerId(server.id);
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
  const ok = await run('switching', 'connect_vpn', { serverId: server.id });
  const s = useAppStore.getState();
  if (ok) {
    s.setLastServerId(server.id);
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

/**
 * The server a plain "Connect" means: the one on the card, else the one the
 * user last connected to, else the fastest — the same rule for the Connect
 * button, auto-connect and the tray (W2-002, W2-028).
 */
export function resolveConnectTarget(
  state: Pick<ReturnType<typeof useAppStore.getState>, 'currentServer' | 'lastServerId' | 'servers'> = useAppStore.getState(),
): Server | null {
  const { currentServer, lastServerId, servers } = state;
  if (usable(currentServer)) return currentServer;
  const remembered = servers.find((s) => s.id === lastServerId);
  if (usable(remembered)) return remembered;
  return pickBestServer(servers);
}

/**
 * Connect the way the user has set things up. A Multi-Hop route that is armed
 * but incomplete is NOT silently replaced by a single hop: the user paid for,
 * and chose, the separation.
 */
export async function connectPreferred(): Promise<boolean> {
  const s = useAppStore.getState();
  if (s.settings.multiHopEnabled) {
    const pair = readyMultiHopPair();
    if (!pair) {
      s.showNotice({ text: 'Choose your Multi-Hop entry and exit servers first.', tone: 'info' });
      return false;
    }
    return connectMultiHop(pair.entry, pair.exit);
  }
  const target = resolveConnectTarget();
  if (target) return connectToServer(target);
  if (s.servers.length > 0) {
    s.showNotice({
      text: 'No accessible online servers are available for this account.',
      tone: 'danger',
    });
    return false;
  }
  // The list has not loaded (offline start, slow backend): Rust has its own
  // copy and applies the same best-server rule.
  return run('connecting', 'quick_connect');
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
