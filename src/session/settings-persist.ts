/**
 * The one settings write path (W2-013, W2-038).
 *
 * Settings, VPN Settings, Kill Switch Exceptions and the Connect screen each
 * had their own copy of "patch the store, send the full object to
 * `save_settings`"; all but one swallowed a failed save and kept the
 * optimistic value, so a toggle could show a state Rust never stored. The one
 * that got it right was Kill Switch Exceptions (optimistic update, rollback on
 * failure, say so). This is that pattern, once.
 *
 * `save_settings` REPLACES the whole Rust struct, so the payload is always the
 * full object through `settingsToRust` — never a partial — or every field left
 * out is silently reset to its serde default.
 */
import { invoke } from '@tauri-apps/api/core';
import { settingsToRust } from '@/utils/helpers';
import { useAppStore, type AppSettings, type ConnectionState } from '@/store/app-store';
import { loadSettings } from '@/session/session-data';
import { isSilentError } from '@/lib/errors';
import { toIpcError } from '@/lib/ipc';

const REAPPLY_DEBOUNCE_MS = 900;
let reapplyTimer: ReturnType<typeof setTimeout> | null = null;

/** What `reapply_vpn_settings` came to (contract §3, WIN-FIX-3). */
export type ReapplyOutcome = 'not_connected' | 'applied' | 'reverted';

export const REAPPLY_REVERTED_COPY = "Couldn't apply that change — your previous setting was restored.";

/** The live reapply in flight, if any (see `persistSettings`). */
let reapplyInFlight: Promise<void> | null = null;

/**
 * How long a save waits for a reapply in flight (REVIEW-WIN4-003). A reapply
 * that wedged must not hold every later save, Kill Switch OFF included; past
 * this the save re-reads what is on disk and goes on top of it.
 */
export const REAPPLY_WAIT_MS = 45_000;

/** Whether the reapply's error says Rust saved the previous settings back. */
function settingsRestored(e: unknown): boolean {
  if (typeof e !== 'object' || e === null) return false;
  const o = e as Record<string, unknown>;
  return o.settingsRestored === true || o.settings_restored === true;
}

/** `p` settled within `ms` (true), or the time ran out first (false). */
async function settledWithin(p: Promise<void>, ms: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<boolean>((resolve) => {
    timer = setTimeout(() => resolve(false), ms);
  });
  try {
    return await Promise.race([p.then(() => true), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function runReapply(): Promise<void> {
  const run = reapply().finally(() => {
    if (reapplyInFlight === run) reapplyInFlight = null;
  });
  reapplyInFlight = run;
  return run;
}

async function reapply(): Promise<void> {
  const s = useAppStore.getState();
  if (s.connectionState !== 'connected') return;
  s.setReapplying(true);
  try {
    const outcome = await invoke<ReapplyOutcome>('reapply_vpn_settings');
    if (outcome === 'reverted') {
      // Rust could not apply the change, saved the previous settings back
      // and reconnected on them: show what is really in force, and say so.
      await loadSettings();
      useAppStore.getState().showNotice({ text: REAPPLY_REVERTED_COPY, tone: 'danger' });
    }
  } catch (e) {
    // Rust saved the previous settings back before this failed (a revert
    // whose reconnect failed, or that a Disconnect came before): show what is
    // saved, or the next save writes the failed value back. Only then: a
    // restore Rust refused saved nothing, and re-reading an unverifiable file
    // hydrates the defaults the next save would write over it (REVIEW-WIN4-004).
    if (settingsRestored(e)) await loadSettings();
    // The user's own Disconnect (or a newer connect) superseded the rebuild:
    // nothing went wrong that they did not ask for (WIN3-002).
    if (isSilentError(toIpcError(e))) return;
    // The rebuild is fail-closed: Rust keeps traffic blocked rather than
    // leaving the old settings silently in force, and the status (blocking
    // banner, Disconnect) shows that. This says why it happened.
    useAppStore.getState().showNotice({
      text: "Couldn't apply that change to your live connection.",
      tone: 'danger',
      actionLabel: 'Retry',
      onAction: () => void runReapply(),
    });
  } finally {
    useAppStore.getState().setReapplying(false);
  }
}

/**
 * Rebuild the live tunnel with the saved settings, debounced so a burst of
 * changes costs one reconnect blip. No-op unless connected: the saved value
 * applies at the next connect anyway.
 */
export function scheduleReapply(): void {
  if (useAppStore.getState().connectionState !== 'connected') return;
  if (reapplyTimer) clearTimeout(reapplyTimer);
  reapplyTimer = setTimeout(() => {
    reapplyTimer = null;
    void runReapply();
  }, REAPPLY_DEBOUNCE_MS);
}

/** For tests: drop a pending debounced reapply, and forget one in flight. */
export function cancelScheduledReapply(): void {
  if (reapplyTimer) clearTimeout(reapplyTimer);
  reapplyTimer = null;
  reapplyInFlight = null;
}

/**
 * Patch the store, save the full object, and on failure put back exactly the
 * keys this call changed (unless something newer has changed them since) and
 * tell the user. `reapply` is for tunnel-shaping settings only: routing a
 * notification toggle through it would rebuild the tunnel for nothing.
 *
 * WIN3-009: while a live reapply is in flight the save waits for it. A
 * reapply that fails saves the PREVIOUS settings back, and until it is done
 * this store still holds the value that failed: a full-object save in that
 * window wrote it back over them — before the revert's reconnect read the
 * file (which then failed again), or after (the screen showing it beside
 * "your previous setting was restored"). The change then goes on top of
 * what the reapply left saved.
 */
export async function persistSettings(
  patch: Partial<AppSettings>,
  opts: { reapply?: boolean; quiet?: boolean } = {},
): Promise<boolean> {
  const keys = Object.keys(patch) as (keyof AppSettings)[];
  let before = useAppStore.getState().settings;
  useAppStore.getState().updateSettings(patch);
  if (reapplyInFlight) {
    const original = before;
    if (!(await settledWithin(reapplyInFlight, REAPPLY_WAIT_MS))) await loadSettings();
    // What a failed save puts back: what the reapply re-read from disk, or,
    // for a key it did not touch, what the key was.
    const settled = useAppStore.getState().settings;
    const untouched: Partial<AppSettings> = {};
    for (const key of keys) {
      if (settled[key] === patch[key]) (untouched as Record<string, unknown>)[key] = original[key];
    }
    before = { ...settled, ...untouched };
    useAppStore.getState().updateSettings(patch);
  }
  const next = { ...before, ...patch };
  try {
    await invoke('save_settings', { settings: settingsToRust(next) });
  } catch {
    const current = useAppStore.getState().settings;
    const revert: Partial<AppSettings> = {};
    for (const key of keys) {
      if (current[key] === patch[key]) {
        (revert as Record<string, unknown>)[key] = before[key];
      }
    }
    useAppStore.getState().updateSettings(revert);
    // A background mirror the user never touched must not raise a notice
    // about "that setting"; it rolls back the same way and retries next time.
    if (!opts.quiet) {
      useAppStore.getState().showNotice({
        text: "Couldn't save that setting. It has been put back — please try again.",
        tone: 'danger',
      });
    }
    return false;
  }
  if (opts.reapply) scheduleReapply();
  return true;
}

/**
 * Whether a kill-switch toggle must be pushed to Rust (`set_killswitch_live`)
 * right now, or only persisted for the next connect to read.
 *
 * OPEN-WORK F3: this used to be `connectionState === 'connected'` for both
 * directions, which is exactly the state in which the toggle matters LEAST —
 * the reactive block is engaged while reconnecting / switching / in error, and
 * turning the kill switch OFF in those states never reached Rust, so the block
 * stayed up until the tunnel recovered or the user hit Disconnect.
 *
 * The two directions have different safe sets:
 * - OFF is safe in every state (clear the intent + lift any block). The only
 *   states worth skipping are the two with no session — unless the block is up
 *   anyway (always-on with no tunnel), which is precisely when OFF must land.
 * - ON must ALSO skip `connecting` and `switching`: Rust would run `arm()`
 *   before the dial publishes VPN_SERVER_IP / the tunnel LUID — a block-all
 *   with no (or the PREVIOUS server's) relay permit ahead of the handshake, or
 *   on Windows lockdown the activate_blocking refusal that silently drops
 *   lockdown for the session. The dial's own `arm()` reads the persisted
 *   preference at the right moment, so ON is persisted-only there.
 */
export function killSwitchLiveApplies(
  state: ConnectionState,
  enabled: boolean,
  blocking = false,
): boolean {
  if (state === 'disconnected' || state === 'disconnecting') return !enabled && blocking;
  if (!enabled) return true;
  return state !== 'connecting' && state !== 'switching';
}

/**
 * The kill switch: persist FIRST (`set_killswitch_live` → `arm()` re-reads the
 * file, so arming must not race the write), then push it to a live session.
 */
export async function setKillSwitch(enabled: boolean): Promise<void> {
  if (!(await persistSettings({ killSwitchEnabled: enabled }))) return;
  const s = useAppStore.getState();
  if (!killSwitchLiveApplies(s.connectionState, enabled, s.killSwitchBlocking)) return;
  try {
    await invoke('set_killswitch_live', { enabled });
  } catch {
    s.showNotice({
      text: 'Saved, but the change could not be applied to your live connection. It applies from your next connection.',
      tone: 'danger',
    });
  }
}
