/**
 * "Sign out?" — the Connect screen's confirmation (canonical: iOS's Home
 * confirm, reworded from "Log Out?" to the account vocabulary).
 */
import { useState } from 'react';
import { AlertTriangle } from 'lucide-react';
import { BirdoButton, BirdoDialog } from '@/components/birdo';
import { status, white } from '@/lib/birdo-theme';
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
      icon={AlertTriangle}
      iconColor={status.yellowLight}
    >
      <p className="text-[13px]" style={{ color: white.w60 }}>
        {stillConnected
          ? 'You are still connected. Signing out will disconnect.'
          : 'Are you sure you want to sign out?'}
      </p>
      <div className="flex gap-2.5">
        <BirdoButton text="Cancel" variant="secondary" fullWidth disabled={busy} onClick={onClose} />
        <BirdoButton
          text="Sign out"
          variant="danger"
          fullWidth
          isLoading={busy}
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
    </BirdoDialog>
  );
}
