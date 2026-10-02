/**
 * Which consent text the user has accepted (owner decision D7: versioned
 * re-consent; Android's `CONSENT_VERSION` / `ConsentCopyTest` parity).
 *
 * The app used to store a BOOLEAN, so a user who accepted one text never saw
 * a later one. It now stores the version of the text accepted, and the
 * consent screen shows again whenever that is older than this:
 *
 *  - 1: the text accepted before versioning (stored as `hasAcceptedConsent`);
 *  - 2: the text rewritten by the 29 Sep 2026 audit remediation
 *    (REMEDIATION-DECISIONS §1.5: the live session record, the backups, the
 *    opt-in crash and error reports).
 *
 * Bump it with ANY change to `CONSENT_COPY` (`components/ConsentScreen.tsx`);
 * `ConsentScreen.test.tsx` pins the copy to this number and fails until both
 * move together.
 */
export const CONSENT_VERSION = 2;

/** Whether the version a user accepted is the current one. */
export function hasCurrentConsent(acceptedVersion: number): boolean {
  return acceptedVersion >= CONSENT_VERSION;
}
