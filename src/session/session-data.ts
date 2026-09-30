/**
 * Session data the whole app reads — settings, admin rights, plan, servers,
 * latency, usage — loaded by the session controller, not by whichever tab
 * happens to be mounted.
 *
 * Tab roots unmount on every switch, and each used to re-fetch everything on
 * mount: a Home visit re-ran get_settings, get_admin_status,
 * get_subscription_status, get_servers AND a fleet-wide ping sweep that reset
 * every latency to blank (W2-023); the Settings tab's hydrate-on-mount could
 * race a save the user had just made. Now each is fetched once per session and
 * refreshed on a TTL when the window comes back (the iOS model: servers once,
 * subscription with a short cache).
 */
import { invoke } from '@tauri-apps/api/core';
import { parseServers } from '@/lib/ipc';
import { command } from '@/session/command';
import { useAppStore, type UsageStats } from '@/store/app-store';
import { selectTunnelActive } from '@/store/selectors';
import { settingsFromRust, type RustSettings } from '@/utils/helpers';

export const SERVERS_TTL_MS = 5 * 60_000;
export const PINGS_TTL_MS = 10 * 60_000;
export const SUBSCRIPTION_TTL_MS = 60_000;
const PING_BATCH = 5;

let serversAt = 0;
let pingsAt = 0;
let subscriptionAt = 0;
let serversInFlight: Promise<void> | null = null;
let subscriptionInFlight: Promise<void> | null = null;
let usageInFlight: Promise<void> | null = null;

/** Forget the timestamps (sign-out: the next account starts cold). */
export function resetSessionData(): void {
  serversAt = 0;
  pingsAt = 0;
  subscriptionAt = 0;
}

export async function loadSettings(): Promise<void> {
  try {
    const rs = await invoke<RustSettings>('get_settings');
    useAppStore.getState().hydrateSettings(settingsFromRust(rs));
  } catch {
    /* keep the persisted preferences; Rust logs the failure */
  }
}

export async function loadAdminStatus(): Promise<void> {
  try {
    useAppStore.getState().setIsAdmin((await invoke<boolean>('get_admin_status')) === true);
  } catch {
    useAppStore.getState().setIsAdmin(false);
  }
}

interface RustSubscription {
  plan?: string | null;
  status?: string | null;
  expiresAt?: string | null;
  devicesUsed?: number;
  devicesLimit?: number;
  bandwidthLimit?: number | null;
  expires_at?: string | null;
  devices_used?: number;
  devices_limit?: number;
  bandwidth_limit?: number | null;
}

/**
 * The plan and subscription summary. A failure leaves the plan UNKNOWN (null)
 * and says so (`planStatus: 'error'`), which every consumer renders as
 * "checking" with a Retry — never as Free (W2-011).
 */
export function loadSubscription(force = false): Promise<void> {
  if (subscriptionInFlight) return subscriptionInFlight;
  const s = useAppStore.getState();
  if (!force && s.planStatus === 'ready' && Date.now() - subscriptionAt < SUBSCRIPTION_TTL_MS) {
    return Promise.resolve();
  }
  if (s.account.plan === null) s.setPlanStatus('loading');
  subscriptionInFlight = (async () => {
    try {
      const sub = await command<RustSubscription>('get_subscription_status');
      const status = sub?.status;
      useAppStore.getState().setAccount({
        plan: sub?.plan ? sub.plan.toUpperCase() : 'RECON',
        status:
          status === 'active' || status === 'expired' || status === 'cancelled' ? status : 'unknown',
        expiresAt: sub?.expiresAt ?? sub?.expires_at ?? null,
        activeDevices: sub?.devicesUsed ?? sub?.devices_used ?? 0,
        maxDevices: sub?.devicesLimit ?? sub?.devices_limit ?? 1,
        // The backend no longer reports usage here; the Limit tab reads it
        // from get_usage_stats.
        bandwidthUsed: 0,
        bandwidthLimit: sub?.bandwidthLimit ?? sub?.bandwidth_limit ?? 0,
      });
      subscriptionAt = Date.now();
      useAppStore.getState().setPlanStatus('ready');
    } catch {
      useAppStore.getState().setPlanStatus('error');
    } finally {
      subscriptionInFlight = null;
    }
  })();
  return subscriptionInFlight;
}

/**
 * Latency sweep, in batches of five, ONE store write per batch (it was one
 * per server, each re-rendering the whole Connect screen). Skipped while a
 * tunnel is up: the probe would then measure the path through the tunnel,
 * which says nothing about the server being picked (W2-046).
 */
async function sweepPings(): Promise<void> {
  const s = useAppStore.getState();
  if (selectTunnelActive(s)) return;
  pingsAt = Date.now();
  const pingable = s.servers.filter((srv) => srv.hostname || srv.ipAddress);
  for (let i = 0; i < pingable.length; i += PING_BATCH) {
    if (!useAppStore.getState().isAuthenticated) return;
    const batch = pingable.slice(i, i + PING_BATCH);
    const results = await Promise.allSettled(
      batch.map((srv) =>
        invoke<number | null>('ping_server', {
          hostname: srv.hostname || srv.ipAddress,
          port: srv.port ?? 51820,
        }),
      ),
    );
    const pings: Record<string, number> = {};
    results.forEach((r, j) => {
      if (r.status === 'fulfilled' && typeof r.value === 'number' && Number.isFinite(r.value)) {
        pings[batch[j].id] = r.value;
      }
    });
    if (Object.keys(pings).length > 0) useAppStore.getState().mergeServerPings(pings);
  }
}

export function loadServers(force = false): Promise<void> {
  if (serversInFlight) return serversInFlight;
  const s = useAppStore.getState();
  if (!force && s.serversStatus === 'ready' && Date.now() - serversAt < SERVERS_TTL_MS) {
    if (Date.now() - pingsAt > PINGS_TTL_MS) void sweepPings();
    return Promise.resolve();
  }
  // Keep a list that is already on screen while it refreshes.
  if (s.servers.length === 0) s.setServersStatus('loading');
  serversInFlight = (async () => {
    try {
      const servers = parseServers(await command('get_servers'));
      const st = useAppStore.getState();
      st.setServers(servers);
      st.setServersStatus('ready');
      serversAt = Date.now();
      // Restore the server the user last connected to, so a cold start shows
      // the node they always use instead of "Choose a server".
      if (!st.currentServer && st.lastServerId) {
        const remembered = servers.find((srv) => srv.id === st.lastServerId);
        if (remembered) st.setCurrentServer(remembered);
      }
      if (force || Date.now() - pingsAt > PINGS_TTL_MS) void sweepPings();
    } catch {
      useAppStore.getState().setServersStatus('error');
    } finally {
      serversInFlight = null;
    }
  })();
  return serversInFlight;
}

type RawUsage = Partial<Record<keyof UsageStats, unknown>>;

export function loadUsage(): Promise<void> {
  if (usageInFlight) return usageInFlight;
  const s = useAppStore.getState();
  s.setUsage(s.usage, s.usage ? 'ready' : 'loading');
  usageInFlight = (async () => {
    try {
      const raw = (await command<RawUsage | null>('get_usage_stats')) ?? {};
      const num = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
      const str = (v: unknown) => (typeof v === 'string' ? v : null);
      useAppStore.getState().setUsage(
        {
          plan: str(raw.plan),
          bandwidthLimitGb: num(raw.bandwidthLimitGb),
          bandwidthUsedGb: num(raw.bandwidthUsedGb),
          bandwidthPeriodEnd: str(raw.bandwidthPeriodEnd),
          bandwidthLastSyncAt: str(raw.bandwidthLastSyncAt),
          bandwidthIsFresh: typeof raw.bandwidthIsFresh === 'boolean' ? raw.bandwidthIsFresh : null,
        },
        'ready',
      );
    } catch {
      const cur = useAppStore.getState();
      cur.setUsage(cur.usage, 'error');
    } finally {
      usageInFlight = null;
    }
  })();
  return usageInFlight;
}
