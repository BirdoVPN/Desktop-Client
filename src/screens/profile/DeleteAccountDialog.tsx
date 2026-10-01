/**
 * Delete Account (GDPR Art.17).
 *
 * Accounts WITH a password re-confirm with it (defense-in-depth against a
 * compromised webview). Accounts without one — anonymous, and SSO accounts —
 * type "DELETE" instead; grouping SSO with email once trapped SSO users behind
 * a password they had never set. Backend: delete_account -> DELETE
 * /api/v1/gdpr/delete.
 *
 * Audit 2026-09-29, kept intact:
 *  - A-8 / C-9: deleting the account cancels a WEB (Polar) subscription but
 *    cannot cancel an App Store or Google Play one, which keeps billing. The
 *    dialog says so BEFORE the user confirms, and lists any store subscription
 *    the server reports as still billing afterwards.
 *  - Second-pass #15: the VPN is disconnected only AFTER the server confirms
 *    the deletion (the Rust `delete_account` does it between the 2xx and
 *    clearing local state). Disconnecting first left a user who typed a wrong
 *    password, or was offline, disconnected from an account that still exists.
 *  - Local state is only cleared once the server confirms (Rust side).
 *
 * Accounts with 2FA (Account API contract 2026-10-01, item 85): the server
 * answers the first attempt `two_factor_required`, and the dialog stays open
 * and asks for the code — the sign-in screen's field, TOTP or backup code —
 * then sends it with the retry. `two_factor_invalid` says the code was wrong
 * and lets the user try again; a 429 gets the rate-limit copy. A server that
 * predates the contract never asks, and never sees a code.
 */
import { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { ShieldAlert } from 'lucide-react';
import { BirdoButton, BirdoDialog, BirdoTextField } from '@/components/birdo';
import { status as statusTokens, white } from '@/lib/birdo-theme';
import { errorCopy } from '@/lib/errors';
import { toIpcError } from '@/lib/ipc';
import {
  isTwoFactorCode,
  sanitizeTwoFactorInput,
  TWO_FACTOR_HINT,
  TWO_FACTOR_PLACEHOLDER,
} from '@/lib/two-factor';
import { useAppStore } from '@/store/app-store';

/** Shape returned by the Rust `delete_account` command. */
export interface DeleteAccountResult {
  /** Store names ("Apple App Store", "Google Play"); empty if none/unknown. */
  storeSubscriptionsStillBilling: string[];
}

export const STORE_BILLING_WARNING =
  'Deleting your account does not cancel an App Store or Google Play subscription. ' +
  'Cancel it first in your Apple or Google account settings, or it will keep billing. ' +
  'A web subscription bought on birdo.app is cancelled automatically.';

/** Shape returned by the Rust `deletion_preflight` command (second-pass #9). */
export interface DeletionPreflight {
  /** Store names whose subscriptions will keep billing; empty if none. */
  storeSubscriptionsStillBilling: string[];
  /** A web (Polar) subscription is billing and the deletion will cancel it. */
  webSubscriptionWillBeCancelled: boolean;
}

/** Shown in place of STORE_BILLING_WARNING when the preflight names stores. */
export function preflightStoreWarning(stores: string[]): string {
  return (
    `This account has a subscription that deleting it will not cancel: ${stores.join(', ')}. ` +
    'Cancel it first in your Apple or Google account settings, or it will keep billing.'
  );
}

export const PREFLIGHT_WEB_CANCELLED =
  'Your web subscription bought on birdo.app will be cancelled automatically.';

/**
 * A refusal, in words (W2-012). A wrong password is `invalid_credentials`;
 * anything the contract has no code for gets a sentence about THIS action
 * rather than Rust's raw text.
 */
function deletionErrorText(e: unknown): string {
  const err = toIpcError(e);
  return err.code === 'unknown'
    ? "Couldn't delete your account. Please try again."
    : errorCopy(err, 'password_confirm').message;
}

export function DeleteAccountDialog({
  open,
  hasPassword,
  onDismiss,
  onDeleted,
}: {
  open: boolean;
  hasPassword: boolean;
  onDismiss: () => void;
  onDeleted: () => void;
}) {
  const [password, setPassword] = useState('');
  const [confirmText, setConfirmText] = useState('');
  // Set once the server answered `two_factor_required`.
  const [askingTwoFactor, setAskingTwoFactor] = useState(false);
  const [twoFactorCode, setTwoFactorCode] = useState('');
  const [deleting, setDeleting] = useState(false);
  // A refusal of the password / DELETE confirmation, under that field.
  const [error, setError] = useState<string | null>(null);
  // A refusal of the code (wrong, or too many tries), under the code field:
  // a wrong password at the code step must not read as a wrong code.
  const [codeError, setCodeError] = useState<string | null>(null);
  // Set once the server confirmed the deletion AND reported store
  // subscriptions that are still billing: the account is gone, but the user
  // has to read this before the app signs out.
  const [stillBilling, setStillBilling] = useState<string[] | null>(null);
  // Second-pass #9: what the server says a deletion would leave billing, asked
  // for when the dialog opens. Null while loading or after a failure.
  const [preflight, setPreflight] = useState<DeletionPreflight | null>(null);
  // Once the account is gone, every way out of the dialog must finish the
  // sign-out; merely closing it would leave the UI on a deleted account.
  const dismiss = stillBilling ? onDeleted : onDismiss;

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    invoke<DeletionPreflight | null>('deletion_preflight')
      .then((result) => {
        if (!cancelled && result) setPreflight(result);
      })
      .catch(() => {
        /* best effort: the static warning stays */
      });
    return () => {
      cancelled = true;
    };
  }, [open]);
  const namedStores = preflight?.storeSubscriptionsStillBilling ?? [];

  const canSubmit =
    !deleting &&
    (hasPassword ? password.length > 0 : confirmText.trim().toUpperCase() === 'DELETE') &&
    (!askingTwoFactor || isTwoFactorCode(twoFactorCode));

  const handleConfirm = async () => {
    if (!canSubmit) return;
    setDeleting(true);
    setError(null);
    setCodeError(null);
    try {
      // Password-less accounts send the typed confirmation token: the server
      // skips the password check for them, and the command's request type is
      // non-optional, so a non-empty value satisfies it without a fake secret.
      const result = await invoke<DeleteAccountResult | null>('delete_account', {
        request: {
          password: hasPassword ? password : confirmText.trim(),
          ...(askingTwoFactor ? { two_factor_code: twoFactorCode } : {}),
        },
      });
      // Confirmed: Rust has already taken the tunnel down. Mirror that now
      // rather than waiting for the next status.
      const ns = useAppStore.getState();
      ns.setConnectionState('disconnected');
      ns.setCurrentServer(null);
      const billing = result?.storeSubscriptionsStillBilling ?? [];
      if (billing.length > 0) {
        setStillBilling(billing);
        setDeleting(false);
        return;
      }
      onDeleted();
    } catch (e: unknown) {
      const err = toIpcError(e);
      if (err.code === 'two_factor_required') {
        // Not an error the user made: the next step. The field and its hint
        // say what to do.
        setAskingTwoFactor(true);
      } else if (err.code === 'two_factor_invalid' || (askingTwoFactor && err.code === 'rate_limited')) {
        setAskingTwoFactor(true);
        setCodeError(deletionErrorText(err));
      } else {
        setError(deletionErrorText(err));
      }
      setDeleting(false);
    }
  };

  return (
    <BirdoDialog
      open={open}
      onClose={dismiss}
      busy={deleting}
      title="Delete Account"
      icon={ShieldAlert}
      iconColor={statusTokens.red}
      titleColor={statusTokens.red}
    >
      {stillBilling ? (
        <StillBillingNotice stores={stillBilling} onDone={onDeleted} />
      ) : (
        <>
          <p className="text-[13px]" style={{ color: white.w60 }}>
            This deletes your account. It is anonymised immediately and fully deleted within 30
            days; payment records are kept, anonymised, for 7 years for tax. This cannot be undone.
            {hasPassword ? ' Enter your password to confirm.' : ' Type DELETE below to confirm.'}
          </p>
          {/* The stores the preflight names, before the confirm button; the
              static warning when it has not answered, failed, or named none. */}
          <p
            className="rounded-birdo-sm px-3 py-2 text-[12px]"
            style={{
              backgroundColor: white.w05,
              color: namedStores.length > 0 ? statusTokens.red : white.w80,
            }}
          >
            {namedStores.length > 0 ? preflightStoreWarning(namedStores) : STORE_BILLING_WARNING}
          </p>
          {namedStores.length > 0 && preflight?.webSubscriptionWillBeCancelled && (
            <p className="text-[12px]" style={{ color: white.w80 }}>
              {PREFLIGHT_WEB_CANCELLED}
            </p>
          )}
          {!hasPassword ? (
            <BirdoTextField
              value={confirmText}
              onChange={(v) => {
                setConfirmText(v);
                if (error) setError(null);
              }}
              label="Type DELETE to confirm"
              type="text"
              placeholder="DELETE"
              errorText={error}
              disabled={deleting}
              autoComplete="off"
            />
          ) : (
            <BirdoTextField
              value={password}
              onChange={(v) => {
                setPassword(v);
                if (error) setError(null);
              }}
              label="Password"
              type="password"
              placeholder="••••••••"
              errorText={error}
              disabled={deleting}
              autoComplete="current-password"
            />
          )}
          {askingTwoFactor && (
            <TwoFactorField
              value={twoFactorCode}
              onChange={(v) => {
                setTwoFactorCode(v);
                if (codeError) setCodeError(null);
              }}
              errorText={codeError}
              disabled={deleting}
            />
          )}
          <div className="flex gap-2.5">
            <BirdoButton text="Cancel" variant="secondary" fullWidth disabled={deleting} onClick={onDismiss} />
            <BirdoButton
              text={deleting ? 'Deleting…' : 'Delete My Account'}
              variant="danger"
              fullWidth
              isLoading={deleting}
              disabled={!canSubmit}
              onClick={handleConfirm}
            />
          </div>
        </>
      )}
    </BirdoDialog>
  );
}

/** The sign-in screen's code field, for an account with 2FA. Focused on arrival. */
function TwoFactorField({
  value,
  onChange,
  errorText,
  disabled,
}: {
  value: string;
  onChange: (next: string) => void;
  errorText: string | null;
  disabled: boolean;
}) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => {
    ref.current?.focus();
  }, []);
  return (
    <BirdoTextField
      inputRef={ref}
      value={value}
      onChange={(v) => onChange(sanitizeTwoFactorInput(v))}
      label="Two-factor code"
      type="text"
      placeholder={TWO_FACTOR_PLACEHOLDER}
      hint={TWO_FACTOR_HINT}
      errorText={errorText}
      disabled={disabled}
      autoComplete="one-time-code"
    />
  );
}

/**
 * Shown after a CONFIRMED deletion when the server reports store
 * subscriptions it could not cancel. The account is already gone; this is the
 * user's last chance to learn that Apple or Google will keep charging.
 */
function StillBillingNotice({ stores, onDone }: { stores: string[]; onDone: () => void }) {
  return (
    <>
      <p className="text-[13px]" style={{ color: white.w80 }}>
        Your account has been deleted. These subscriptions are still active and will keep billing
        until you cancel them in the store:
      </p>
      <ul className="list-disc pl-5 text-[13px]" style={{ color: white.w80 }}>
        {stores.map((store) => (
          <li key={store}>{store}</li>
        ))}
      </ul>
      <p className="text-[12px]" style={{ color: white.w60 }}>
        Cancel them in your Apple or Google account settings. Birdo cannot cancel a store
        subscription for you.
      </p>
      <BirdoButton text="OK" variant="primary" fullWidth onClick={onDone} />
    </>
  );
}
