/**
 * MR-2335 (MR-179 hold fallback, birdo-web #883): an account deletion on its
 * 24-hour hold, shown on Profile with a way to cancel it.
 *
 * The hold itself is shared state (`@/lib/held-deletion`): Profile reads the
 * list when it opens and whenever the window regains focus
 * (`usePendingDeletion`) and again after the dialog or this banner files or
 * cancels one, and the Home sign-out dialog reads the same state. A
 * hold can vanish between two reads: the server cancels it on a sign-out
 * elsewhere, a number rotation, a password or 2FA change, and drops it when
 * this app's session ends. So a hold that is gone is simply not shown; it is
 * never an error. A read that FAILS keeps what was shown: an outage is not
 * "no hold".
 *
 * Nothing here ever concludes that the account WAS deleted. The hold is not
 * persisted, and a session that has ended (a read answered `session_expired`)
 * takes the ordinary session-expired path (`command()` → `expireSession`):
 * the sign-in screen, never "account deleted".
 *
 * Signing out of this app, or signing out everywhere, CANCELS the hold on the
 * server. The dialog, this banner and both sign-out confirmations say so.
 */
import { useState } from 'react';
import { CalendarClock } from 'lucide-react';
import { BirdoButton } from '@/components/birdo';
import { status as statusTokens, white } from '@/lib/birdo-theme';
import { errorCopy } from '@/lib/errors';
import { holdWhen, SIGN_OUT_CANCELS_HOLD, type HeldDeletion } from '@/lib/held-deletion';
import { toIpcError } from '@/lib/ipc';
import { command } from '@/session/command';
import { refreshHeldDeletion } from '@/session/held-deletion';

/** A failed cancel, in words. */
export function cancelErrorText(e: unknown): string {
  const err = toIpcError(e);
  return err.code === 'unknown'
    ? "Couldn't cancel the deletion. Please try again."
    : errorCopy(err).message;
}

/** The Profile banner: when the deletion applies, and Cancel. */
export function PendingDeletionBanner({ hold }: { hold: HeldDeletion }) {
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
      void refreshHeldDeletion();
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
