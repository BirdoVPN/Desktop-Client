/**
 * "Sign out?" — the Connect screen's confirmation (canonical: iOS's Home
 * confirm, reworded from "Log Out?" to the account vocabulary).
 *
 * MR-2335: signing out cancels an account deletion on its 24-hour hold, so
 * while one is known this dialog says so, with its date, exactly as Profile's
 * confirmation does. The hold is shared state (`@/lib/held-deletion`): one
 * filed in Profile is known here at once, and the list is read again each
 * time the dialog opens (a hold filed before the app was restarted). Sign out
 * waits for that one read, so the warning cannot be skipped by a fast click.
 */
import { useEffect, useState } from 'react';
import { TriangleAlert } from 'lucide-react';
import { BirdoButton, BirdoDialog } from '@/components/birdo';
import { status, white } from '@/lib/birdo-theme';
import { signOutWithHoldText, useHeldDeletion } from '@/lib/held-deletion';
import { refreshHeldDeletion } from '@/session/held-deletion';
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
  useEffect(() => {
    let current = true;
    void refreshHeldDeletion().finally(() => {
      if (current) setChecking(false);
    });
    return () => {
      current = false;
    };
  }, []);
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
          {signOutWithHoldText(hold.applyAfter)}
        </p>
      )}
      <div className="flex gap-2.5">
        <BirdoButton text="Cancel" variant="secondary" fullWidth disabled={busy} onClick={onClose} />
        <BirdoButton
          text="Sign out"
          variant="danger"
          fullWidth
          isLoading={busy}
          disabled={checking && !hold}
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
