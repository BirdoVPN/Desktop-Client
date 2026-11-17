/**
 * MR-2335 (MR-179 hold fallback, birdo-web #883): an account deletion on its
 * 24-hour hold, shown on Profile with a way to cancel it.
 *
 * The hold itself is shared state (`@/lib/held-deletion`): the dialog writes
 * it the moment the server names it, Profile reads the list when it opens and
 * whenever the window regains focus (`usePendingDeletion`), and the Home
 * sign-out dialog and the number-replacement dialog read the same state. A
 * hold can vanish between two reads: the server cancels it on a sign-out
 * everywhere, a number rotation, a password or 2FA change, and voids one this
 * app's session filed when that session ends. So a hold that is gone is
 * simply not shown; it is never an error. A read that FAILS keeps what was
 * shown: an outage is not "no hold".
 *
 * Nothing here ever concludes that the account WAS deleted. The hold is not
 * persisted, and a session that has ended (a read answered `session_expired`)
 * takes the ordinary session-expired path (`command()` → `expireSession`):
 * the sign-in screen, never "account deleted".
 *
 * Signing out of this app voids only a hold THIS session filed (birdo-web
 * #883); one filed on the website or by another device stays. The dialog,
 * this banner and both sign-out confirmations say which (`filedHere`).
 */
import { useState } from 'react';
import { CalendarClock } from 'lucide-react';
import { BirdoButton } from '@/components/birdo';
import { status as statusTokens, white } from '@/lib/birdo-theme';
import { holdWhen, signOutHoldNote, type HeldDeletion } from '@/lib/held-deletion';
import { cancelErrorText, cancelHeldDeletion } from '@/session/held-deletion';

/** The Profile banner: when the deletion applies, and Cancel. */
export function PendingDeletionBanner({ hold }: { hold: HeldDeletion }) {
  const [cancelling, setCancelling] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const cancel = async () => {
    if (cancelling) return;
    setCancelling(true);
    setError(null);
    try {
      await cancelHeldDeletion(hold.id);
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
            Cancel it to keep your account. {signOutHoldNote(hold)}
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
