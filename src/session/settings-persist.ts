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
import { create } from 'zustand';
import { settingsToRust } from '@/utils/helpers';
import { useAppStore, type AppSettings, type ConnectionState } from '@/store/app-store';
import { loadSettings } from '@/session/session-data';
import { errorCopy, isSilentError } from '@/lib/errors';
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
  const refused = await trySave(patch, opts);
  // A background mirror the user never touched must not raise a notice
  // about "that setting"; it rolls back the same way and retries next time.
  if (refused && !opts.quiet) {
    showSaveFailure(refused.error, SAVE_FAILED_COPY);
  }
  return refused === null;
}

const SAVE_FAILED_COPY = "Couldn't save that setting. It has been put back — please try again.";

/**
 * `persistSettings` without its notice: `null` once saved, or what the
 * refused save threw, with the keys this call changed already put back. For
 * a caller whose notice depends on more than the save (the kill switch OFF).
 */
async function trySave(
  patch: Partial<AppSettings>,
  opts: { reapply?: boolean },
): Promise<{ error: unknown } | null> {
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
  } catch (e) {
    const current = useAppStore.getState().settings;
    const revert: Partial<AppSettings> = {};
    for (const key of keys) {
      if (current[key] === patch[key]) {
        (revert as Record<string, unknown>)[key] = before[key];
      }
    }
    useAppStore.getState().updateSettings(revert);
    return { error: e };
  }
  if (opts.reapply) scheduleReapply();
  return null;
}

/**
 * The notice for a settings write Rust refused. `settings_unverified` (review
 * of #222) says what happened and offers the reset; anything else shows
 * `fallback`. Shared by every screen that writes settings.
 */
export function showSaveFailure(e: unknown, fallback: string): void {
  const err = toIpcError(e);
  useAppStore.getState().showNotice(
    err.code === 'settings_unverified'
      ? {
          text: errorCopy(err).message,
          tone: 'danger',
          actionLabel: 'Reset settings',
          onAction: askToResetSettings,
        }
      : { text: fallback, tone: 'danger' },
  );
}

/** Whether the reset confirmation is open (`ResetSettingsDialog`). */
export const useResetPrompt = create<{ open: boolean }>(() => ({ open: false }));

/**
 * Ask before resetting (round 3 of the review of #222): the reset replaces
 * every setting with its default, so a click on an 8-second toast must not do
 * it on its own.
 */
export function askToResetSettings(): void {
  useResetPrompt.setState({ open: true });
}

/**
 * The way out of `settings_unverified`, run only after the user confirmed it.
 * Rust re-checks first and resets only a file that still cannot be verified
 * (it answers `false` when the key came back, and nothing was touched); it
 * sets the file aside and saves the defaults. The screen then shows what is
 * saved, and a live session is rebuilt on it.
 */
export async function resetSettings(): Promise<void> {
  try {
    const reset = await invoke<boolean>('reset_settings');
    await loadSettings();
    if (reset) scheduleReapply();
    useAppStore.getState().showNotice({
      text: reset
        ? 'Your settings were reset to their defaults.'
        : 'Your saved settings can be read again, so nothing was reset.',
      tone: 'info',
    });
  } catch {
    useAppStore.getState().showNotice({
      text: "Couldn't reset your settings. Please try again.",
      tone: 'danger',
    });
  }
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

export const KILL_SWITCH_OFF_FAILED_COPY =
  "The kill switch couldn't be turned off on your live connection. Disconnect to lift it.";

/** Bumped by every kill-switch choice, so an older one's late steps stand down. */
let killSwitchChoice = 0;

/**
 * The kill switch toggle.
 *
 * An ON is persisted FIRST: `set_killswitch_live` → `arm()` re-reads the
 * file, so arming must not race the write. A refused ON is not pushed.
 *
 * An OFF reads no file, so it goes out first (round 4 of the review of #222,
 * P3-4): behind its save it waited for a reapply in flight, up to
 * `REAPPLY_WAIT_MS`, with the block still up. Then:
 * - once the save lands it is pushed once more: a dial that finished in the
 *   meantime (a connect, a switch, a reapply's rebuild — the very reapply the
 *   save waited for) armed from the file as it was before the save, still
 *   ON. Not when a newer choice came since.
 * - a refused save (`settings_unverified`, an unreadable file) still lets it
 *   lift the block (round 3): the block must be liftable whatever the file
 *   says. The refusal's own notice stays; the saved preference is
 *   unchanged, and the next connect follows it.
 * - one that could not be applied says to disconnect (round 3): the block is
 *   still up, and "it applies from your next connection" told the user to
 *   wait behind it.
 */
export async function setKillSwitch(enabled: boolean): Promise<void> {
  const choice = ++killSwitchChoice;
  if (enabled) await turnKillSwitchOn();
  else await turnKillSwitchOff(choice);
}

async function turnKillSwitchOn(): Promise<void> {
  if (!(await persistSettings({ killSwitchEnabled: true }))) return;
  const s = useAppStore.getState();
  if (!killSwitchLiveApplies(s.connectionState, true, s.killSwitchBlocking)) return;
  try {
    await invoke('set_killswitch_live', { enabled: true });
  } catch {
    s.showNotice({
      text: 'Saved, but the change could not be applied to your live connection. It applies from your next connection.',
      tone: 'danger',
    });
  }
}

async function turnKillSwitchOff(choice: number): Promise<void> {
  const latest = () => choice === killSwitchChoice;
  const live = () => {
    const s = useAppStore.getState();
    return killSwitchLiveApplies(s.connectionState, false, s.killSwitchBlocking);
  };
  const pushOff = () =>
    invoke('set_killswitch_live', { enabled: false }).then(
      () => true,
      () => false,
    );

  const first = live() ? pushOff() : null;
  const refused = await trySave({ killSwitchEnabled: false }, {});
  // Whether the block is lifted: the LAST push says (`null`: none was due).
  let lifted = first === null ? null : await first;
  if (refused === null && latest() && live()) lifted = await pushOff();

  const { showNotice } = useAppStore.getState();
  if (lifted === false) {
    showNotice({ text: KILL_SWITCH_OFF_FAILED_COPY, tone: 'danger' });
  } else if (refused) {
    showSaveFailure(refused.error, SAVE_FAILED_COPY);
  }
}
