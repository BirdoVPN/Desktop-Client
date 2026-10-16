/**
 * Rust's record of the consent text accepted (MR-1607).
 *
 * The consent screen and the version the user accepted live here, in the
 * webview (`acceptedConsentVersion`, D7). Rust could not see either, so the
 * tray's Quick Connect — which runs in Rust with no window — dialled while
 * the screen asking for a newer text was showing. Rust now keeps its own
 * record (`commands::consent`) and refuses that connect until it holds the
 * current version.
 *
 * This module keeps the record in step with the store:
 *
 *  - whenever the store holds the current version — every start, and the
 *    moment the user accepts — it is written to Rust. The start-up write is
 *    the MIGRATION: an install that accepted version 2 in an earlier build has
 *    no Rust record yet, and gets one from what the store already holds, with
 *    no second consent screen;
 *  - MR-2016: and when it does not — the consent screen is up, because the
 *    text is newer or this webview lost its storage — the start-up write says
 *    so, and Rust takes its record down to match (`withdrawConsentInRust`).
 *    The record used to only rise, so a webview that lost its storage showed
 *    the consent screen while the tray's Quick Connect still dialled;
 *  - Auto-Connect and the resume after an update dial only once Rust's record
 *    holds the current version (`recordConsentInRust` again, so they never
 *    race the start-up write);
 *  - a refused tray Quick Connect (`consent-required`) brings the window up.
 *    If the store lacks the current version, that window shows the consent
 *    screen and nothing else is needed. If it holds it, Rust's record fell
 *    behind (its write failed): it is written again, and the user is told.
 */
import { invoke } from '@tauri-apps/api/core';
import { hasCurrentConsent } from '@/lib/consent';
import { useAppStore } from '@/store/app-store';

/** Rust's event for a connect refused for want of consent (`commands::consent`). */
export const CONSENT_REQUIRED_EVENT = 'consent-required';

export const CONSENT_RESAVED_COPY =
  "Quick Connect didn't start because your privacy consent wasn't saved. It's saved now — try again.";

export const CONSENT_NOT_SAVED_COPY =
  "Couldn't save your privacy consent, so Quick Connect from the tray can't start. Connect from " +
  'this window, or restart BirdoVPN.';

/** Auto-Connect, or the resume after an update, held back (MR-1607). */
export const UNATTENDED_CONNECT_HELD_COPY =
  "Couldn't save your privacy consent, so BirdoVPN didn't connect by itself. Connect from this window.";

/**
 * Write the version the store holds into Rust's record, if it is the current
 * one. Resolves whether Rust's record holds the current version now. Never
 * throws: a failed write is `false`.
 */
export async function recordConsentInRust(): Promise<boolean> {
  const accepted = useAppStore.getState().acceptedConsentVersion;
  if (!hasCurrentConsent(accepted)) return false;
  try {
    const recorded = await invoke<unknown>('record_consent', { version: accepted });
    return typeof recorded === 'number' && hasCurrentConsent(recorded);
  } catch {
    return false;
  }
}

/**
 * MR-2016: the store holds no current consent, so the consent screen is what
 * the window shows: Rust's record is set to what the store holds, and the
 * tray waits for the screen as the window does. Never throws: a failed write
 * leaves Rust's record as it was (the start-up write repeats at every start).
 *
 * Should it land after the accept's own write (it is sent at start, the accept
 * seconds later, so only in theory), the next tray Quick Connect is refused
 * and `onConsentRequired` writes the record again.
 */
export async function withdrawConsentInRust(): Promise<void> {
  const held = useAppStore.getState().acceptedConsentVersion;
  if (hasCurrentConsent(held)) return;
  try {
    await invoke('record_consent', { version: held });
  } catch {
    /* as it was: retried at the next start */
  }
}

/**
 * Rust refused a connect for want of consent (the tray's Quick Connect). It
 * has brought the window up already.
 */
export async function onConsentRequired(): Promise<void> {
  // The consent screen is what the window shows: nothing else to say.
  if (!hasCurrentConsent(useAppStore.getState().acceptedConsentVersion)) return;
  const recorded = await recordConsentInRust();
  useAppStore
    .getState()
    .showNotice(
      recorded
        ? { text: CONSENT_RESAVED_COPY, tone: 'info' }
        : { text: CONSENT_NOT_SAVED_COPY, tone: 'danger' },
    );
}
