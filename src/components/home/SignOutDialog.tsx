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
 * that one read, so the warning cannot be skipped by a fast click.
 */
import { useEffect, useState } from 'react';
import { TriangleAlert } from 'lucide-react';
import { BirdoButton, BirdoDialog } from '@/components/birdo';
import { status, white } from '@/lib/birdo-theme';
import { signOutWithHoldText, useHeldDeletion } from '@/lib/held-deletion';
import { cancelErrorText, cancelHeldDeletion, refreshHeldDeletion } from '@/session/held-deletion';
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
  // The read this opening started is still out.
  const [checking, setChecking] = useState(true);
  // Cancel deletion, from this dialog.
  const [cancelling, setCancelling] = useState(false);
  const [cancelError, setCancelError] = useState<string | null>(null);
  const [cancelled, setCancelled] = useState(false);
  useEffect(() => {
    let current = true;
    void refreshHeldDeletion().finally(() => {
      if (current) setChecking(false);
    });
    return () => {
      current = false;
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
      {cancelled && !hold && (
        <p role="status" className="text-[12px]" style={{ color: white.w80 }}>
          The deletion is cancelled. Your account stays as it is.
        </p>
      )}
      {hold && (
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
      <div className="flex gap-2.5">
        <BirdoButton
          text={hold ? 'Stay signed in' : 'Cancel'}
          variant="secondary"
          fullWidth
          disabled={busy}
          onClick={onClose}
        />
        <BirdoButton
          text="Sign out"
          variant="danger"
          fullWidth
          isLoading={busy}
          disabled={(checking && !hold) || cancelling}
          onClick={async () => {
            setBusy(true);
            try {
              await signOut();
            } finally {
              setBusy(false);
            }
          }}
        />
      </div>
    </>
  );
}
