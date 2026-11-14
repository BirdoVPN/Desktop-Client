/**
 * MR-2335 (MR-179 hold fallback, birdo-web #883): an account deletion on its
 * 24-hour hold, shown on Profile with a way to cancel it.
 *
 * Read from `list_pending_changes` (GET /auth/pending-changes) when Profile
 * opens and whenever the window regains focus. A hold can vanish between two
 * reads: the server cancels it on a sign-out elsewhere, a number rotation, a
 * password or 2FA change, and drops it when this app's session ends. So a
 * hold that is gone is simply not shown; it is never an error. A read that
 * FAILS keeps what was shown: an outage is not "no hold".
 *
 * Nothing here ever concludes that the account WAS deleted. The hold is not
 * remembered anywhere but this screen's state, and a session that has ended
 * (a read answered `session_expired`) takes the ordinary session-expired path
 * (`command()` → `expireSession`): the sign-in screen, never "account deleted".
 *
 * Signing out of this app, or signing out everywhere, CANCELS the hold on the
 * server. The dialog, this banner and the sign-out confirmation all say so.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { CalendarClock } from 'lucide-react';
import { BirdoButton } from '@/components/birdo';
import { status as statusTokens, white } from '@/lib/birdo-theme';
import { errorCopy } from '@/lib/errors';
import { toIpcError } from '@/lib/ipc';
import { command } from '@/session/command';

/** A held account deletion: the id to cancel it by, and when it applies. */
export interface HeldDeletion {
  id: string;
  applyAfter: string;
}

/** `applyAfter` in the viewer's local time, or null if it is not a date. */
export function holdTimeText(applyAfter: string): string | null {
  const at = new Date(applyAfter);
  return Number.isNaN(at.getTime()) ? null : at.toLocaleString();
}

/** "on <local time>", or "within 24 hours" when the time cannot be read. */
export function holdWhen(applyAfter: string): string {
  const at = holdTimeText(applyAfter);
  return at ? `on ${at}` : 'within 24 hours';
}

/** The account's held deletion in what `list_pending_changes` returned, if any. */
export function heldDeletionOf(items: unknown): HeldDeletion | null {
  if (!Array.isArray(items)) return null;
  for (const item of items) {
    if (typeof item !== 'object' || item === null) continue;
    const row = item as Record<string, unknown>;
    if (row.action !== 'account_delete') continue;
    if (typeof row.id !== 'string' || !row.id) continue;
    if (typeof row.applyAfter !== 'string' || !row.applyAfter) continue;
    return { id: row.id, applyAfter: row.applyAfter };
  }
  return null;
}

/** What ends a hold besides Cancel: said wherever a hold is shown. */
export const SIGN_OUT_CANCELS_HOLD =
  'Signing out of this app, or signing out everywhere, also cancels it.';

/** The sign-out confirmation while a hold is listed. */
export const SIGN_OUT_WITH_HOLD =
  'Your account is waiting to be deleted. Signing out cancels that deletion, so your account ' +
  'will NOT be deleted. To delete it, stay signed in until the time shown.';

/** A failed cancel, in words. */
export function cancelErrorText(e: unknown): string {
  const err = toIpcError(e);
  return err.code === 'unknown'
    ? "Couldn't cancel the deletion. Please try again."
    : errorCopy(err).message;
}

/**
 * The held deletion, read on mount and on every window focus. `refresh` reads
 * it again now (after the dialog filed or cancelled one).
 */
export function usePendingDeletion(): { hold: HeldDeletion | null; refresh: () => void } {
  const [hold, setHold] = useState<HeldDeletion | null>(null);
  const latest = useRef(0);
  const mounted = useRef(true);

  const refresh = useCallback(() => {
    const mine = ++latest.current;
    // `command`, not `invoke`: a session that has ended goes the ordinary
    // session-expired way. It is never read as "the deletion went through".
    command<unknown>('list_pending_changes')
      .then((items) => {
        // Only the newest read may answer: a slow one must not undo a cancel.
        if (mounted.current && mine === latest.current) setHold(heldDeletionOf(items));
      })
      .catch(() => {
        /* keep what is shown: a failed read is not "no hold" */
      });
  }, []);

  useEffect(() => {
    mounted.current = true;
    refresh();
    window.addEventListener('focus', refresh);
    return () => {
      mounted.current = false;
      window.removeEventListener('focus', refresh);
    };
  }, [refresh]);

  return { hold, refresh };
}

/** The Profile banner: when the deletion applies, and Cancel. */
export function PendingDeletionBanner({ hold, onChanged }: { hold: HeldDeletion; onChanged: () => void }) {
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const cancel = async () => {
    if (cancelling) return;
    setCancelling(true);
    setError(null);
    try {
      // Cancelled now, or gone already (404 pending_change_not_found): either
      // way the list is read again and says what is left.
      await command('cancel_pending_change', { id: hold.id });
      onChanged();
    } catch (e: unknown) {
      setError(cancelErrorText(e));
    } finally {
      setCancelling(false);
    }
  };

  return (
    <div
      role="status"
      className="flex flex-col gap-2.5 rounded-birdo-lg px-4 py-3.5"
      style={{ backgroundColor: statusTokens.redBg, border: `1px solid ${statusTokens.redBorder}` }}
    >
      <div className="flex items-start gap-2.5">
        <CalendarClock size={18} className="mt-0.5 shrink-0" style={{ color: statusTokens.red }} aria-hidden />
        <div className="min-w-0">
          <p className="text-[13px] font-semibold" style={{ color: white.w100 }}>
            {`Your account will be deleted ${holdWhen(hold.applyAfter)}.`}
          </p>
          <p className="mt-1 text-[12px]" style={{ color: white.w80 }}>
            Cancel it to keep your account. {SIGN_OUT_CANCELS_HOLD}
          </p>
        </div>
      </div>
      <BirdoButton
        text="Cancel deletion"
        variant="secondary"
        size="small"
        fullWidth
        isLoading={cancelling}
        disabled={cancelling}
        onClick={() => void cancel()}
      />
      {error && (
        <p className="text-[12px]" style={{ color: statusTokens.red }}>
          {error}
        </p>
      )}
    </div>
  );
}
