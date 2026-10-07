/**
 * Redeem a voucher — in-app parity with mobile's VoucherRedeemDialog. Calls the
 * Rust `redeem_voucher` command (→ POST /vouchers/redeem) and refreshes the
 * plan on success.
 */
import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { CircleCheck, Gift } from 'lucide-react';
import { BirdoButton, BirdoDialog, BirdoTextField } from '@/components/birdo';
import { brand, white } from '@/lib/birdo-theme';
import { errorCopy } from '@/lib/errors';
import { toIpcError } from '@/lib/ipc';
import { planName } from '@/lib/plan';

/** The contract has no voucher codes: an unclassified refusal is about the code itself. */
function voucherErrorText(e: unknown): string {
  const err = toIpcError(e);
  return err.code === 'unknown'
    ? "Couldn't redeem that voucher. Check the code and try again."
    : errorCopy(err).message;
}

export function VoucherRedeemDialog({
  open,
  onDismiss,
  onRedeemed,
}: {
  open: boolean;
  onDismiss: () => void;
  onRedeemed: () => void;
}) {
  const [code, setCode] = useState('');
  const [redeeming, setRedeeming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<{ plan: string; days: number } | null>(null);

  const close = () => {
    onDismiss();
    // Fresh next time it opens.
    setCode('');
    setError(null);
    setSuccess(null);
  };

  const canSubmit = code.trim().length > 0 && !redeeming && !success;

  const handleConfirm = async () => {
    if (!canSubmit) return;
    setRedeeming(true);
    setError(null);
    try {
      const res = await invoke<{ ok: boolean; plan: string; durationDays: number; extended: boolean }>(
        'redeem_voucher',
        { code: code.trim() },
      );
      setSuccess({ plan: res.plan, days: res.durationDays });
      onRedeemed();
    } catch (e: unknown) {
      setError(voucherErrorText(e));
    } finally {
      setRedeeming(false);
    }
  };

  return (
    <BirdoDialog
      open={open}
      onClose={close}
      busy={redeeming}
      title={success ? 'Voucher redeemed' : 'Redeem voucher'}
      icon={success ? CircleCheck : Gift}
      iconColor={success ? brand.accentLight : brand.accent}
    >
      {success ? (
        <p className="text-[13px]" style={{ color: white.w60 }}>
          {success.days > 0
            ? `${success.days} days added to your ${planName(success.plan)} plan.`
            : `Your ${planName(success.plan)} plan has been updated.`}
        </p>
      ) : (
        <>
          <p className="text-[13px]" style={{ color: white.w60 }}>
            Enter a 30 or 90-day voucher code to extend your subscription. Payments are handled on
            the web — vouchers add time to your plan.
          </p>
          <BirdoTextField
            value={code}
            onChange={(v) => {
              // Codes are case-insensitive; uppercase for display + matching.
              setCode(v.toUpperCase());
              if (error) setError(null);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') void handleConfirm();
            }}
            label="Voucher code"
            type="text"
            placeholder="BIRD-XXXX-XXXX-XXXX"
            errorText={error}
            disabled={redeeming}
            autoComplete="off"
          />
        </>
      )}
      <div className="flex gap-2.5">
        {success ? (
          <BirdoButton text="Done" variant="primary" fullWidth onClick={close} />
        ) : (
          <>
            <BirdoButton text="Cancel" variant="secondary" fullWidth disabled={redeeming} onClick={close} />
            <BirdoButton
              text={redeeming ? 'Redeeming…' : 'Redeem'}
              variant="primary"
              fullWidth
              isLoading={redeeming}
              disabled={!canSubmit}
              onClick={handleConfirm}
            />
          </>
        )}
      </div>
    </BirdoDialog>
  );
}
