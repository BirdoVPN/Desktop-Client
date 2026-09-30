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

const REAPPLY_DEBOUNCE_MS = 900;
let reapplyTimer: ReturnType<typeof setTimeout> | null = null;

async function runReapply(): Promise<void> {
  const s = useAppStore.getState();
  if (s.connectionState !== 'connected') return;
  s.setReapplying(true);
  try {
    await invoke('reapply_vpn_settings');
  } catch {
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

/** For tests: drop a pending debounced reapply. */
export function cancelScheduledReapply(): void {
  if (reapplyTimer) clearTimeout(reapplyTimer);
  reapplyTimer = null;
}

/**
 * Patch the store, save the full object, and on failure put back exactly the
 * keys this call changed (unless something newer has changed them since) and
 * tell the user. `reapply` is for tunnel-shaping settings only: routing a
 * notification toggle through it would rebuild the tunnel for nothing.
 */
export async function persistSettings(
  patch: Partial<AppSettings>,
  opts: { reapply?: boolean; quiet?: boolean } = {},
): Promise<boolean> {
  const store = useAppStore.getState();
  const before = store.settings;
  const next = { ...before, ...patch };
  store.updateSettings(patch);
  try {
    await invoke('save_settings', { settings: settingsToRust(next) });
  } catch {
    const current = useAppStore.getState().settings;
    const revert: Partial<AppSettings> = {};
    for (const key of Object.keys(patch) as (keyof AppSettings)[]) {
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
