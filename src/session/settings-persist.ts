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
import {
  useAppStore,
  type AppSettings,
  type AppStateSnapshot,
  type ConnectionState,
} from '@/store/app-store';
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
      await reloadSettings();
      useAppStore.getState().showNotice({ text: REAPPLY_REVERTED_COPY, tone: 'danger' });
    }
  } catch (e) {
    // Rust saved the previous settings back before this failed (a revert
    // whose reconnect failed, or that a Disconnect came before): show what is
    // saved, or the next save writes the failed value back. Only then: a
    // restore Rust refused saved nothing, and re-reading an unverifiable file
    // hydrates the defaults the next save would write over it (REVIEW-WIN4-004).
    if (settingsRestored(e)) await reloadSettings();
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
    if (!(await settledWithin(reapplyInFlight, REAPPLY_WAIT_MS))) await reloadSettings();
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
  // While a refused OFF holds for this connection only, a save of anything
  // else writes the kill switch the OFF was refused over (round 7 of the
  // review of #222, N4): the toggle shows the live OFF, but the notice said
  // the saved ON comes back at the next connection, and the next unrelated
  // save — the quiet preferred-server mirror included — wrote the OFF.
  const held = heldKillSwitch();
  if (held !== undefined && !('killSwitchEnabled' in patch)) next.killSwitchEnabled = held;
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
  savedKillSwitch(next.killSwitchEnabled);
  // The file holds this store's settings now (round 6 of the review of #222,
  // P3-4): after a start-up that could not verify the file (get_settings
  // answered settings_unverified), the store is what is saved from here on,
  // and what waits for that (the preferred-server mirror, the Custom DNS
  // gate, Auto-Connect) may go. It stayed false for the rest of the run.
  if (!useAppStore.getState().settingsHydrated) useAppStore.setState({ settingsHydrated: true });
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
  const since = killSwitchChoice;
  let reset: boolean;
  try {
    reset = await invoke<boolean>('reset_settings');
  } catch {
    useAppStore.getState().showNotice({
      text: "Couldn't reset your settings. Please try again.",
      tone: 'danger',
    });
    return;
  }
  // A kill switch choice made while the reset ran, or one still being made,
  // is newer than the defaults (follow-up 2 to the review of #222): the
  // reset neither forgets it nor pushes ON over it. Forgotten, an OFF whose
  // refused save answered after the reset put the toggle back to OFF, and
  // the push below had turned the intent ON under it.
  const chosen = choiceOwnsKillSwitch(since);
  // The defaults are the choice now (round 6 of the review of #222): a kill
  // switch choice made before the reset must not be pushed back over them
  // after the next dial — so it goes at once, before anything below reads
  // it (round 8).
  if (reset && !chosen) {
    forgetKillSwitchChoices();
  } else if (reset && choicesInFlight.size > 0) {
    // Left to a choice still in flight, which may yet not take: the reset
    // then finishes once it has ended (`finishWaitingReset`, review of #255, L1).
    resetWaiting = { since };
  }
  await reloadSettings();
  if (!reset) {
    useAppStore.getState().showNotice({
      text: 'Your saved settings can be read again, so nothing was reset.',
      tone: 'info',
    });
    return;
  }
  scheduleReapply();
  useAppStore.getState().showNotice({
    text: 'Your settings were reset to their defaults.',
    tone: 'info',
  });
  if (!chosen) await armTheResetDefaults(since);
}

/**
 * After a reset, a live session gets the defaults' kill switch now (round 8
 * of the review of #222, E2): connected, reconnecting or in error. The
 * reapply that rebuilds on the defaults runs only while connected, and the
 * auto-reconnect never arms, so a kill switch turned off for this connection
 * stayed off under a toggle reading ON until the user's next dial. A push
 * that fails says so.
 *
 * Only an intent that is OFF is pushed (follow-up 1 to the review of #222).
 * The push re-arms, and an intent already ON loses by it: while reconnecting
 * in Windows lockdown no tunnel LUID is published, `activate_blocking`
 * refuses, and `arm` falls back to the reactive kill switch for the rest of
 * the session. An intent that cannot be read is pushed, as before: OFF under
 * a toggle reading ON is the worse of the two. A choice made since the reset
 * began decides instead (follow-up 2), up to the push itself.
 */
async function armTheResetDefaults(since: number): Promise<void> {
  const applies = () => {
    const s = useAppStore.getState();
    return (
      s.settings.killSwitchEnabled &&
      killSwitchLiveApplies(s.connectionState, true, s.killSwitchBlocking) &&
      !choiceOwnsKillSwitch(since)
    );
  };
  if (!applies()) return;
  try {
    const { enabled } = await invoke<{ enabled: boolean }>('get_killswitch_status');
    if (enabled === true) return;
  } catch {
    /* not known: pushed */
  }
  if (!applies()) return;
  try {
    await invoke('set_killswitch_live', { enabled: true });
  } catch {
    useAppStore.getState().showNotice({ text: KILL_SWITCH_ON_FAILED_COPY, tone: 'danger' });
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

export const KILL_SWITCH_OFF_THIS_CONNECTION_COPY =
  "The kill switch is off for this connection only. It couldn't be saved, so it comes back on at your next connection.";

export const KILL_SWITCH_ON_FAILED_COPY =
  "The kill switch couldn't be turned on for this connection. Disconnect and connect again to turn it on.";

/** Bumped by every kill-switch choice, so an older one's late steps stand down. */
let killSwitchChoice = 0;

/**
 * The user's kill-switch choice in this run of the app, which every dial is
 * checked against when it ends (round 5 of the review of #222). A refused
 * OFF holds for this connection only (`thisConnectionOnly`): it gives way,
 * to the value it was refused over, when the next dial starts.
 */
interface StandingChoice {
  enabled: boolean;
  thisConnectionOnly?: { saved: boolean };
  /**
   * The choice (`killSwitchChoice`) that made it. None for the file's value
   * that a dial puts back over a this-connection OFF (`dialStarted`).
   */
  made?: number;
}
let standingChoice: StandingChoice | null = null;

/** The kill-switch choices whose steps have not all run yet. */
const choicesInFlight = new Set<number>();

/**
 * A reset that left the kill switch to a choice still in flight (follow-up 2),
 * kept so it can finish if that choice does not take (review of #255, L1):
 * `since` as the reset took it.
 */
let resetWaiting: { since: number } | null = null;

/**
 * Whether the kill switch is a choice's to settle rather than the caller's:
 * one is still being made, or one made after choice number `since` stands
 * (follow-ups 2 and 4 to the review of #222). A re-read or a reset that
 * began before it is older than it. A choice that did not take hands the
 * kill switch back: the toggle went back to what was there before it.
 */
function choiceOwnsKillSwitch(since: number): boolean {
  return choicesInFlight.size > 0 || (standingChoice?.made ?? 0) > since;
}

/**
 * Re-read the settings from Rust: every re-read goes through here (round 8
 * of the review of #222, E1). While a refused OFF holds for this connection
 * only, the toggle keeps showing that OFF — it is what is live — and the
 * file's kill switch becomes the value it gives way to at the next dial.
 * Hydrated over it, the toggle (and the status chip) read ON while the
 * intent was OFF: reproduced through Reset when the file verified again
 * (`reset_settings` answering false).
 *
 * A kill switch choice made while the read was in flight, or still being
 * made when it lands, keeps the toggle (follow-up 4): the file may predate
 * its save, and hydrated over it the toggle read ON beside an OFF that was
 * pushed and then saved. The choice's own steps settle it — and the value a
 * this-connection OFF gives way to — and every other field is hydrated.
 */
export async function reloadSettings(): Promise<void> {
  const since = killSwitchChoice;
  let kept = false;
  const loaded = await loadSettings((read) => {
    kept = choiceOwnsKillSwitch(since);
    return kept
      ? { ...read, killSwitchEnabled: useAppStore.getState().settings.killSwitchEnabled }
      : read;
  });
  if (!loaded || kept) return;
  const held = standingChoice?.thisConnectionOnly;
  if (!held) return;
  const s = useAppStore.getState();
  held.saved = s.settings.killSwitchEnabled;
  s.updateSettings({ killSwitchEnabled: false });
}

/**
 * The kill switch a save writes while a refused OFF holds for this
 * connection only: the value it was refused over (round 7, N4).
 */
function heldKillSwitch(): boolean | undefined {
  return standingChoice?.thisConnectionOnly?.saved;
}

/**
 * A save landed, and it wrote the whole store — the kill switch as the toggle
 * showed it included (round 6 of the review of #222, P2-2). A refused OFF
 * the toggle showed is saved now: it no longer gives way at the next dial,
 * which would have put the toggle back to ON while the dial armed OFF from
 * the file. (Since round 7 a held OFF is written only by a save of the kill
 * switch itself: other saves write the value it was refused over.)
 */
function savedKillSwitch(enabled: boolean): void {
  if (standingChoice?.thisConnectionOnly && standingChoice.enabled === enabled) {
    standingChoice.thisConnectionOnly = undefined;
  }
}

/**
 * Forget the kill switch choices made so far: after a reset, at sign-out
 * (follow-up 3 to the review of #222: the session controller's teardown, so
 * a same-run sign-in does not show the last session's this-connection OFF),
 * and for tests. One still in flight no longer holds up the next re-read.
 *
 * Nor is it the latest choice any more (review of #255, L2): a refused OFF
 * still in flight at sign-out answered in the next session, and put its
 * toggle OFF over that session's saved ON. A reset forgets only when no
 * choice is in flight, so there this changes nothing.
 */
export function forgetKillSwitchChoices(): void {
  standingChoice = null;
  choicesInFlight.clear();
  killSwitchChoice++;
  resetWaiting = null;
}

/**
 * A kill switch choice ended. If a reset left the kill switch to it and it did
 * not take, the reset's kill switch would be lost: an ON refused while the
 * reset ran went back to OFF, the intent stayed OFF, and the file held the
 * defaults' ON. Once the last choice in flight has ended without one taking,
 * the reset finishes what it left: forget, re-read, and arm the defaults.
 * A choice that took settles the kill switch, as before. One forgotten at
 * sign-out never gets here (`setKillSwitch`).
 */
async function finishWaitingReset(took: boolean): Promise<void> {
  const waiting = resetWaiting;
  if (!waiting) return;
  if (took) {
    resetWaiting = null;
    return;
  }
  if (choicesInFlight.size > 0) return;
  resetWaiting = null;
  if (choiceOwnsKillSwitch(waiting.since)) return;
  forgetKillSwitchChoices();
  await reloadSettings();
  await armTheResetDefaults(waiting.since);
}

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
 *   says. The toggle then shows what is live — OFF, for this connection
 *   only — and says the saved ON comes back at the next connection (round 4,
 *   P3-1: it went back to ON over a kill switch that was off).
 * - one that could not be applied says to disconnect (round 3): the block is
 *   still up, and "it applies from your next connection" told the user to
 *   wait behind it.
 *
 * A dial in progress arms from the file when it ends, which a choice made
 * during it may not have reached; `watchKillSwitchAcrossDials` checks the
 * choice against Rust once it has (round 5).
 */
export async function setKillSwitch(enabled: boolean): Promise<void> {
  const choice = ++killSwitchChoice;
  const previous = standingChoice;
  const mine: StandingChoice = { enabled, made: choice };
  standingChoice = mine;
  choicesInFlight.add(choice);
  let stands = false;
  try {
    stands = enabled ? await turnKillSwitchOn() : await turnKillSwitchOff(choice, mine);
    // A choice that did not take leaves the one before it standing, as the
    // toggle went back to it.
    if (!stands && standingChoice === mine) standingChoice = previous;
  } finally {
    // Not there: forgotten meanwhile (sign-out), so its end settles nothing.
    if (choicesInFlight.delete(choice)) await finishWaitingReset(stands);
  }
}

/** Whether the ON was saved. */
async function turnKillSwitchOn(): Promise<boolean> {
  if (!(await persistSettings({ killSwitchEnabled: true }))) return false;
  const s = useAppStore.getState();
  if (!killSwitchLiveApplies(s.connectionState, true, s.killSwitchBlocking)) return true;
  try {
    await invoke('set_killswitch_live', { enabled: true });
  } catch {
    s.showNotice({
      text: 'Saved, but the change could not be applied to your live connection. It applies from your next connection.',
      tone: 'danger',
    });
  }
  return true;
}

/** Whether the OFF stands: saved, or refused but in force for this connection. */
async function turnKillSwitchOff(choice: number, mine: StandingChoice): Promise<boolean> {
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

  const { showNotice, updateSettings, settings } = useAppStore.getState();
  if (lifted === false) {
    showNotice({ text: KILL_SWITCH_OFF_FAILED_COPY, tone: 'danger' });
    return refused === null;
  }
  if (refused === null) return true;
  if (lifted && latest()) {
    // The save put the toggle back; it shows what is live instead.
    mine.thisConnectionOnly = { saved: settings.killSwitchEnabled };
    updateSettings({ killSwitchEnabled: false });
    showNotice({
      text: KILL_SWITCH_OFF_THIS_CONNECTION_COPY,
      tone: 'danger',
      ...(toIpcError(refused.error).code === 'settings_unverified'
        ? { actionLabel: 'Reset settings', onAction: askToResetSettings }
        : {}),
    });
    return true;
  }
  showSaveFailure(refused.error, SAVE_FAILED_COPY);
  return false;
}

/** A dial: a connect, a switch, or a reapply's rebuild — each arms from the file. */
const dialing = (s: AppStateSnapshot) =>
  s.connectionState === 'connecting' || s.connectionState === 'switching' || s.reapplying;

/**
 * Keep the kill switch toggle and Rust's intent in step across dials
 * (round 5 of the review of #222). The session controller runs it.
 *
 * - When a dial starts, a refused OFF's "this connection" is over: the
 *   toggle goes back to the value it was refused over — that one field, not
 *   a re-read of the screen (N2: a re-read of an unverifiable file loaded its
 *   stand-in defaults over every field, and the next whole-object save wrote
 *   them over the user's file).
 * - When a dial ends, Rust's intent (`get_killswitch_status`) is checked
 *   against the user's standing choice, and the choice is pushed if the dial
 *   armed otherwise: a refused OFF that landed during the dial, which then
 *   armed ON from the file (N1); an ON saved during `connecting`, where it is
 *   not pushed, after the dial had read the file (it ran with the intent
 *   OFF beside a toggle reading ON).
 * - With no choice made there is nothing to check. Round 5 copied Rust's
 *   intent into the toggle when the settings had not come from Rust; that
 *   read could precede the dial's arm, and a later save wrote it over the
 *   file (round 6).
 *
 * The auto-reconnect is not a dial here: it keeps the session's intent and
 * does not read the file.
 */
export function watchKillSwitchAcrossDials(): () => void {
  return useAppStore.subscribe((next, prev) => {
    if (dialing(next) === dialing(prev)) return;
    if (dialing(next)) dialStarted();
    else void dialEnded();
  });
}

function dialStarted(): void {
  const standing = standingChoice;
  if (!standing?.thisConnectionOnly) return;
  // What the file says stands now, and is checked when this dial ends (round
  // 7 of the review of #222, N2): a dial Rust started itself (the tray's
  // Quick Connect) can take this OFF's push before the UI sees it begin. Its
  // arm then stands aside, as for any OFF during a dial, and the check puts
  // the intent back to what the toggle shows again.
  standingChoice = { enabled: standing.thisConnectionOnly.saved };
  const s = useAppStore.getState();
  if (s.settings.killSwitchEnabled === standing.enabled) {
    s.updateSettings({ killSwitchEnabled: standing.thisConnectionOnly.saved });
  }
}

async function dialEnded(): Promise<void> {
  const standing = standingChoice;
  if (!standing) return;
  let enabled: boolean;
  try {
    ({ enabled } = await invoke<{ enabled: boolean }>('get_killswitch_status'));
  } catch {
    return;
  }
  const s = useAppStore.getState();
  // Another dial started meanwhile: its end checks again.
  if (dialing(s)) return;
  if (standing !== standingChoice || enabled === standing.enabled) return;
  // An OFF wherever it can lift a block; an ON only on a dial that came up
  // (it is the dial's own arm that missed it), never on one that failed.
  const applies = standing.enabled
    ? s.connectionState === 'connected'
    : killSwitchLiveApplies(s.connectionState, false, s.killSwitchBlocking);
  if (!applies) return;
  try {
    await invoke('set_killswitch_live', { enabled: standing.enabled });
  } catch {
    // Either way the connection now runs other than the toggle shows, so it
    // is said (round 7: a failed ON was silent).
    s.showNotice({
      text: standing.enabled ? KILL_SWITCH_ON_FAILED_COPY : KILL_SWITCH_OFF_FAILED_COPY,
      tone: 'danger',
    });
  }
}

/**
 * The crash-report choice made on the consent screen. It goes straight to
 * Rust through the dedicated command (it reads settings.json, flips the one
 * field and applies the opt-in live), never through a full save of a store
 * that has not been hydrated from Rust yet. Default OFF; a failed write
 * leaves it OFF, the safe direction, and says so (round 4 of the review of
 * #222: it was only logged, so a `settings_unverified` refusal offered no
 * reset and a choice that did not stick went unmentioned).
 */
export async function saveConsentCrashChoice(enabled: boolean): Promise<void> {
  useAppStore.getState().updateSettings({ crashReportsEnabled: enabled });
  try {
    await invoke('set_crash_reports_enabled', { enabled });
  } catch (err) {
    console.error('Failed to save the crash-report choice', err);
    useAppStore.getState().updateSettings({ crashReportsEnabled: false });
    showSaveFailure(err, CONSENT_CRASH_CHOICE_FAILED_COPY);
  }
}

export const CONSENT_CRASH_CHOICE_FAILED_COPY =
  "Your crash-report choice couldn't be saved. Please check it in Settings.";
