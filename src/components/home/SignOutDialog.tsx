/**
 * "Sign out?" — the sign-out confirmation (canonical: iOS's Home confirm,
 * reworded from "Log Out?" to the account vocabulary). The Connect screen
 * opens it; Profile opens it while a deletion is on hold.
 *
 * MR-2335: while an account deletion waits out its 24-hour hold, this dialog
 * says what signing out does to it, with its date, and offers Cancel
 * deletion. What it does depends on where the hold came from (birdo-web #883):
 * one THIS app session filed is voided when this session signs out; one filed
 * on the website or by another device stays, whatever this app does
 * (`filedHere`, `@/lib/held-deletion`). The hold is shared state: one filed in
 * Profile is known here at once, and the list is read again each time the
 * dialog opens (a hold filed before the app was restarted). Sign out waits for
 * that one read, so the warning cannot be skipped by a fast click, but for at
 * most `HOLD_READ_WAIT_MS`: a read that fails or is slower leaves no hold
 * known, so the dialog says it could not check, and Sign out works.
 *
 * The server's sign-out is best effort (Rust's `logout` ignores a failed
 * `/auth/logout`), so offline it may never void a hold filed here. Confirming
 * Sign out while one is known therefore cancels it FIRST; if that cancel
 * fails, nobody is signed out: the dialog says the deletion is still
 * scheduled and offers Try again, or Sign out anyway.
 */
import { useEffect, useState } from 'react';
import { TriangleAlert } from 'lucide-react';
import { BirdoButton, BirdoDialog } from '@/components/birdo';
import { status, white } from '@/lib/birdo-theme';
import {
  HOLD_UNCHECKED_CAUTION,
  signOutCancelFailedText,
  signOutWithHoldText,
  useHeldDeletion,
} from '@/lib/held-deletion';
import {
  cancelErrorText,
  cancelHeldDeletion,
  HOLD_READ_WAIT_MS,
  refreshHeldDeletion,
} from '@/session/held-deletion';
import { signOut } from '@/session/session';

export function SignOutDialog({
  open,
  stillConnected,
  onClose,
}: {
  open: boolean;
  stillConnected: boolean;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  return (
    <BirdoDialog
      open={open}
      onClose={onClose}
      busy={busy}
      title="Sign out?"
      icon={TriangleAlert}
      iconColor={status.yellowLight}
    >
      {/* Mounted only while the dialog is open: each opening reads the list once. */}
      <SignOutConfirm stillConnected={stillConnected} busy={busy} setBusy={setBusy} onClose={onClose} />
    </BirdoDialog>
  );
}

function SignOutConfirm({
  stillConnected,
  busy,
  setBusy,
  onClose,
}: {
  stillConnected: boolean;
  busy: boolean;
  setBusy: (busy: boolean) => void;
  onClose: () => void;
}) {
  const hold = useHeldDeletion();
  // The read this opening started: still out, answered, or failed / not
  // answered within HOLD_READ_WAIT_MS ("unchecked": the caution, and Sign out
  // goes ahead). A late answer still counts.
  const [read, setRead] = useState<'pending' | 'answered' | 'unchecked'>('pending');
  // Cancel deletion, from this dialog.
  const [cancelling, setCancelling] = useState(false);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const [cancelled, setCancelled] = useState(false);
  // Sign out tried to cancel a hold filed here first, and that failed.
  const [signOutBlocked, setSignOutBlocked] = useState<{ reason: string; applyAfter: string } | null>(null);
  useEffect(() => {
    let current = true;
    const timer = setTimeout(() => {
      if (current) setRead((now) => (now === 'pending' ? 'unchecked' : now));
    }, HOLD_READ_WAIT_MS);
    void refreshHeldDeletion().then((answered) => {
      if (current) setRead(answered ? 'answered' : 'unchecked');
    });
    return () => {
      current = false;
      clearTimeout(timer);
    };
  }, []);

  const cancelDeletion = async () => {
    if (!hold || cancelling) return;
    setCancelling(true);
    setCancelError(null);
    try {
      await cancelHeldDeletion(hold.id);
      setCancelled(true);
    } catch (e: unknown) {
      setCancelError(cancelErrorText(e));
    } finally {
      setCancelling(false);
    }
  };

  const signOutNow = async () => {
    setBusy(true);
    try {
      await signOut();
    } finally {
      setBusy(false);
    }
  };

  // Sign out. A hold this session filed is cancelled first: the server's
  // sign-out may never arrive, and the user was told signing out cancels it.
  const confirmSignOut = async () => {
    if (busy) return;
    setSignOutBlocked(null);
    if (hold?.filedHere) {
      setBusy(true);
      try {
        // No list read after it: the session ends next (a read could race the
        // sign-out and end it as "session expired").
        await cancelHeldDeletion(hold.id, { reread: false });
      } catch (e: unknown) {
        setSignOutBlocked({ reason: cancelErrorText(e), applyAfter: hold.applyAfter });
        return;
      } finally {
        setBusy(false);
      }
    }
    await signOutNow();
  };

  return (
    <>
      <p className="text-[13px]" style={{ color: white.w60 }}>
        {stillConnected
          ? 'You are still connected. Signing out will disconnect.'
          : 'Are you sure you want to sign out?'}
      </p>
      {hold && (
        <p
          role="alert"
          className="rounded-birdo-sm px-3 py-2 text-[12px]"
          style={{ backgroundColor: status.redBg, color: white.w100 }}
        >
          {signOutWithHoldText(hold)}
        </p>
      )}
      {!hold && !cancelled && read === 'unchecked' && (
        <p role="note" className="text-[12px]" style={{ color: white.w80 }}>
          {HOLD_UNCHECKED_CAUTION}
        </p>
      )}
      {cancelled && !hold && (
        <p role="status" className="text-[12px]" style={{ color: white.w80 }}>
          The deletion is cancelled. Your account stays as it is.
        </p>
      )}
      {hold && !signOutBlocked && (
        <BirdoButton
          text="Cancel deletion"
          variant="secondary"
          size="small"
          fullWidth
          isLoading={cancelling}
          disabled={cancelling || busy}
          onClick={() => void cancelDeletion()}
        />
      )}
      {cancelError && (
        <p className="text-[12px]" style={{ color: status.red }}>
          {cancelError}
        </p>
      )}
      {signOutBlocked && (
        <>
          <p role="alert" className="text-[12px]" style={{ color: status.red }}>
            {signOutCancelFailedText(signOutBlocked.reason, signOutBlocked)}
          </p>
          <div className="flex gap-2.5">
            <BirdoButton
              text="Retry"
              variant="secondary"
              fullWidth
              isLoading={busy}
              disabled={busy}
              onClick={() => void confirmSignOut()}
            />
            <BirdoButton
              text="Sign out anyway"
              variant="danger"
              fullWidth
              disabled={busy}
              onClick={() => void signOutNow()}
            />
          </div>
        </>
      )}
      <div className="flex gap-2.5">
        <BirdoButton
          text={hold ? 'Stay signed in' : 'Cancel'}
          variant="secondary"
          fullWidth
          disabled={busy}
          onClick={onClose}
        />
        {!signOutBlocked && (
          <BirdoButton
            text="Sign out"
            variant="danger"
            fullWidth
            isLoading={busy}
            disabled={(read === 'pending' && !hold) || cancelling}
            onClick={() => void confirmSignOut()}
          />
        )}
      </div>
    </>
  );
}
