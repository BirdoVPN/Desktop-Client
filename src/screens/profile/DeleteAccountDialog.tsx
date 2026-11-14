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
 *
 * MR-179 (owner 2026-11-13): a fresh re-auth before deletion, like the
 * website. The preflight's `stepUpFactors` (or a refusal by code:
 * `account_number_required` / `email_code_required`) makes the dialog ask for
 * what the server expects:
 *  - an anonymous account re-enters its 24-digit number;
 *  - an SSO account with no 2FA taps "Email me a code" (`send_deletion_code`)
 *    and types the 6-digit code it receives;
 *  - a password account keeps the password (+ 2FA code), as before.
 * A wrong number / code says so under its own field. A server that predates
 * this sends no factors, and nothing new is asked or sent.
 *
 * MR-2335 (MR-179 hold fallback, birdo-web #883): while the preflight says
 * `stepUpHoldAvailable` (`holdAvailable === true`, its own switch,
 * independent of `enforced`), a user who cannot present the number or the
 * e-mailed code can instead ask for "Delete in 24 hours". The password and
 * 2FA are still asked for. The answer is a HOLD, not a deletion: nothing is
 * signed out, cleared or disconnected (Rust `request_deletion_hold` touches no
 * local state), and the dialog shows when it applies with a Cancel button. A
 * hold already waiting (409 `change_already_pending`) is shown the same way.
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
import { command } from '@/session/command';
import { cancelErrorText, holdWhen, SIGN_OUT_CANCELS_HOLD } from './PendingDeletion';

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
  /** MR-179: the server's step-up factor tokens; absent from an older backend. */
  stepUpFactors?: string[];
  /** MR-179: the server refuses a deletion without them; until then they are optional. */
  stepUpEnforced?: boolean;
  /** MR-2335: the server takes a 24-hour hold instead of the number / code. */
  stepUpHoldAvailable?: boolean;
}

/** Shape returned by the Rust `request_deletion_hold` command (MR-2335). */
export interface DeletionHold {
  /** For `cancel_pending_change`. */
  pendingChangeId: string;
  /** ISO-8601; shown in local time. */
  applyAfter: string;
  /** The server's sentence, when it sent one. */
  message?: string | null;
  /** Filed before this request (409 `change_already_pending`). */
  alreadyPending?: boolean;
}

/** MR-2335: the hold offer, worded by what the user cannot present. */
export const HOLD_OFFER_NUMBER = 'Delete in 24 hours (I lost my account number)';
export const HOLD_OFFER_CODE = "Delete in 24 hours (I can't get the code)";
export const HOLD_OFFER_OTHER = 'Delete in 24 hours instead';
export const HOLD_EXPLAINED =
  'Your account will be deleted 24 hours from now unless you cancel it first, here or on the ' +
  `website. ${SIGN_OUT_CANCELS_HOLD} Any e-mail address on the account is alerted.`;
/** A 202 that could not be read, or any other 2xx, to a hold request. */
export const HOLD_UNEXPECTED =
  "The server's answer wasn't the expected one, so nothing is assumed: your account was not " +
  'deleted from this app. Check your Profile for a pending deletion, or try again.';

/** A usable hold from what `request_deletion_hold` returned, or null. */
function holdOf(result: unknown): DeletionHold | null {
  if (typeof result !== 'object' || result === null) return null;
  const r = result as Record<string, unknown>;
  if (typeof r.pendingChangeId !== 'string' || !r.pendingChangeId) return null;
  if (typeof r.applyAfter !== 'string' || !r.applyAfter) return null;
  return {
    pendingChangeId: r.pendingChangeId,
    applyAfter: r.applyAfter,
    message: typeof r.message === 'string' ? r.message : null,
    alreadyPending: r.alreadyPending === true,
  };
}

/** Shape returned by the Rust `send_deletion_code` command (MR-179). */
export interface DeletionCodeResult {
  /** The masked address the code went to, e.g. "j***@example.com". */
  sentTo: string | null;
  /** How long the code works, in minutes, when the server says. */
  expiresInMinutes?: number | null;
}

/** An anonymous account number is 24 digits; the e-mailed deletion code is 6. */
export const ACCOUNT_NUMBER_LENGTH = 24;
export const EMAIL_CODE_LENGTH = 6;
const digitsOnly = (v: string) => v.replace(/\D/g, '');

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
 * The refusals a deletion can meet, worded by code. Any other code (a 403
 * without a 2FA reason reads `subscription_required`, whose copy is about a
 * plan and a server — REVIEW-WIN2-025) gets the sentence about THIS action.
 */
const DELETION_CODES: ReadonlySet<string> = new Set([
  'invalid_credentials',
  'two_factor_required',
  'two_factor_invalid',
  'account_number_required',
  'account_number_invalid',
  'email_code_required',
  'email_code_invalid',
  'apple_reauth_required',
  'hold_unavailable',
  'step_up_no_factor',
  'step_up_unavailable',
  'rate_limited',
  'session_expired',
  'network_offline',
  'server_error',
  'cert_pin_failed',
  'upgrade_required',
]);

/**
 * A refusal, in words (W2-012). A wrong password is `invalid_credentials`;
 * anything else a deletion cannot be refused for gets a sentence about THIS
 * action rather than another screen's copy or Rust's raw text.
 */
function deletionErrorText(e: unknown): string {
  const err = toIpcError(e);
  return DELETION_CODES.has(err.code)
    ? errorCopy(err, 'password_confirm').message
    : "Couldn't delete your account. Please try again.";
}

/**
 * A refused hold, in words (MR-2335). A 429 carries the server's own sentence
 * from Rust: it alone says whether to wait 15 minutes (the 2FA lockout) or
 * until tomorrow (the daily cap on holds); `hold_unavailable` says why too.
 */
function holdErrorText(e: unknown): string {
  const err = toIpcError(e);
  if (err.code === 'rate_limited' && err.message.trim()) return err.message.trim();
  if (err.code === 'server_error') return HOLD_UNEXPECTED;
  return DELETION_CODES.has(err.code)
    ? errorCopy(err, 'password_confirm').message
    : "Couldn't put the deletion on hold. Nothing was deleted. Please try again.";
}

export function DeleteAccountDialog({
  open,
  hasPassword,
  onDismiss,
  onDeleted,
  onHoldChanged,
}: {
  open: boolean;
  hasPassword: boolean;
  onDismiss: () => void;
  onDeleted: () => void;
  /** MR-2335: a hold was filed, cancelled, or may exist: read the list again. */
  onHoldChanged?: () => void;
}) {
  const [password, setPassword] = useState('');
  const [confirmText, setConfirmText] = useState('');
  // Set once the server answered `two_factor_required`.
  const [askingTwoFactor, setAskingTwoFactor] = useState(false);
  const [twoFactorCode, setTwoFactorCode] = useState('');
  // MR-179: set from the preflight's factors, or once the server answered
  // `account_number_required` / `email_code_required`.
  const [askingNumber, setAskingNumber] = useState(false);
  const [accountNumber, setAccountNumber] = useState('');
  const [numberError, setNumberError] = useState<string | null>(null);
  const [askingEmailCode, setAskingEmailCode] = useState(false);
  const [emailCode, setEmailCode] = useState('');
  const [emailCodeError, setEmailCodeError] = useState<string | null>(null);
  const [emailCodeSent, setEmailCodeSent] = useState(false);
  const [emailCodeSentTo, setEmailCodeSentTo] = useState<string | null>(null);
  const [sendingCode, setSendingCode] = useState(false);
  const [emailCodeMinutes, setEmailCodeMinutes] = useState<number | null>(null);
  // MR-179: the number / code is OPTIONAL until the server enforces it (the
  // preflight's `enforced`, or it already answered `*_required`), so a user
  // whose code e-mail fails can still delete, as before.
  const [stepUpEnforced, setStepUpEnforced] = useState(false);
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
  // MR-2335: the user chose "Delete in 24 hours"; then the hold the server
  // filed (or the one already waiting), and its cancel.
  const [holdMode, setHoldMode] = useState(false);
  const [hold, setHold] = useState<DeletionHold | null>(null);
  const [cancellingHold, setCancellingHold] = useState(false);
  const [holdCancelError, setHoldCancelError] = useState<string | null>(null);
  const [holdEnded, setHoldEnded] = useState<string | null>(null);
  // Once the account is gone, every way out of the dialog must finish the
  // sign-out; merely closing it would leave the UI on a deleted account.
  const dismiss = stillBilling ? onDeleted : onDismiss;

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    invoke<DeletionPreflight | null>('deletion_preflight')
      .then((result) => {
        if (cancelled || !result) return;
        setPreflight(result);
        if (result.stepUpEnforced) setStepUpEnforced(true);
        const factors = result.stepUpFactors ?? [];
        if (factors.includes('account_number')) setAskingNumber(true);
        if (factors.includes('email_code')) setAskingEmailCode(true);
      })
      .catch(() => {
        /* best effort: the static warning stays */
      });
    return () => {
      cancelled = true;
    };
  }, [open]);
  const namedStores = preflight?.storeSubscriptionsStillBilling ?? [];
  // MR-2335: offered only while the server says the hold is available, and
  // only to an account with a factor the hold stands in for.
  const factors = preflight?.stepUpFactors ?? [];
  const holdOffered =
    preflight?.stepUpHoldAvailable === true &&
    (askingNumber || askingEmailCode || factors.includes('apple_reauth'));
  const holdOfferText = askingNumber ? HOLD_OFFER_NUMBER : askingEmailCode ? HOLD_OFFER_CODE : HOLD_OFFER_OTHER;

  const canSubmit =
    !deleting &&
    (hasPassword ? password.length > 0 : confirmText.trim().toUpperCase() === 'DELETE') &&
    (!askingTwoFactor || isTwoFactorCode(twoFactorCode)) &&
    (!askingNumber ||
      digitsOnly(accountNumber).length === ACCOUNT_NUMBER_LENGTH ||
      (!stepUpEnforced && digitsOnly(accountNumber).length === 0)) &&
    (!askingEmailCode ||
      digitsOnly(emailCode).length === EMAIL_CODE_LENGTH ||
      (!stepUpEnforced && digitsOnly(emailCode).length === 0));

  // The hold needs what the server still checks: the password (or DELETE) and
  // the 2FA code once asked for. Never the number or the e-mailed code.
  const canSubmitHold =
    !deleting &&
    (hasPassword ? password.length > 0 : confirmText.trim().toUpperCase() === 'DELETE') &&
    (!askingTwoFactor || isTwoFactorCode(twoFactorCode));

  const handleHold = async () => {
    if (!canSubmitHold) return;
    setDeleting(true);
    setError(null);
    setCodeError(null);
    try {
      // `command`: an ended session takes the ordinary session-expired path.
      const result = await command<unknown>('request_deletion_hold', {
        request: {
          password: hasPassword ? password : confirmText.trim(),
          ...(askingTwoFactor ? { two_factor_code: twoFactorCode } : {}),
        },
      });
      // NOT a deletion: nothing is signed out or disconnected here.
      const filed = holdOf(result);
      if (filed) setHold(filed);
      else setError(HOLD_UNEXPECTED);
    } catch (e: unknown) {
      const err = toIpcError(e);
      if (err.code === 'two_factor_required') {
        if (askingTwoFactor) setCodeError(holdErrorText(err));
        setAskingTwoFactor(true);
      } else if (err.code === 'two_factor_invalid') {
        setAskingTwoFactor(true);
        setCodeError(holdErrorText(err));
      } else {
        setError(holdErrorText(err));
      }
    } finally {
      setDeleting(false);
      // Filed, already waiting, or refused: the Profile banner reads the list again.
      onHoldChanged?.();
    }
  };

  const handleCancelHold = async () => {
    if (!hold || cancellingHold) return;
    setCancellingHold(true);
    setHoldCancelError(null);
    try {
      const result = await command<{ cancelled?: boolean; alreadyGone?: boolean } | null>(
        'cancel_pending_change',
        { id: hold.pendingChangeId },
      );
      setHold(null);
      setHoldEnded(
        result?.alreadyGone
          ? 'This deletion is no longer waiting, so there was nothing to cancel.'
          : 'The deletion is cancelled. Your account stays as it is.',
      );
      onHoldChanged?.();
    } catch (e: unknown) {
      setHoldCancelError(cancelErrorText(e));
    } finally {
      setCancellingHold(false);
    }
  };

  const handleSendCode = async () => {
    if (sendingCode || deleting) return;
    setSendingCode(true);
    setEmailCodeError(null);
    try {
      const sent = await invoke<DeletionCodeResult | null>('send_deletion_code');
      setEmailCodeSent(true);
      setEmailCodeSentTo(sent?.sentTo ?? null);
      setEmailCodeMinutes(sent?.expiresInMinutes ?? null);
    } catch (e: unknown) {
      setEmailCodeError(deletionErrorText(e));
    } finally {
      setSendingCode(false);
    }
  };

  const handleConfirm = async () => {
    if (!canSubmit) return;
    setDeleting(true);
    setError(null);
    setCodeError(null);
    setNumberError(null);
    setEmailCodeError(null);
    try {
      // Password-less accounts send the typed confirmation token: the server
      // skips the password check for them, and the command's request type is
      // non-optional, so a non-empty value satisfies it without a fake secret.
      const result = await invoke<DeleteAccountResult | null>('delete_account', {
        request: {
          password: hasPassword ? password : confirmText.trim(),
          ...(askingTwoFactor ? { two_factor_code: twoFactorCode } : {}),
          ...(askingNumber && digitsOnly(accountNumber) ? { account_number: digitsOnly(accountNumber) } : {}),
          ...(askingEmailCode && digitsOnly(emailCode) ? { email_code: digitsOnly(emailCode) } : {}),
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
        // say what to do. Asked AGAIN after a code was sent, though, it is an
        // answer, and silence read as nothing happening (REVIEW-WIN2-025).
        if (askingTwoFactor) setCodeError(deletionErrorText(err));
        setAskingTwoFactor(true);
      } else if (err.code === 'two_factor_invalid' || (askingTwoFactor && err.code === 'rate_limited')) {
        setAskingTwoFactor(true);
        setCodeError(deletionErrorText(err));
      } else if (err.code === 'account_number_required' || err.code === 'account_number_invalid') {
        // MR-179: asked for, not an error the user made, unless a number was
        // already sent: then it is the answer.
        if (askingNumber || err.code === 'account_number_invalid') setNumberError(deletionErrorText(err));
        setAskingNumber(true);
        setStepUpEnforced(true);
      } else if (err.code === 'email_code_required' || err.code === 'email_code_invalid') {
        if (askingEmailCode || err.code === 'email_code_invalid') setEmailCodeError(deletionErrorText(err));
        setAskingEmailCode(true);
        setStepUpEnforced(true);
      } else if (askingNumber && err.code === 'rate_limited') {
        setNumberError(deletionErrorText(err));
      } else if (askingEmailCode && err.code === 'rate_limited') {
        setEmailCodeError(deletionErrorText(err));
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
      ) : holdEnded ? (
        <>
          <p className="text-[13px]" style={{ color: white.w80 }}>
            {holdEnded}
          </p>
          <BirdoButton text="OK" variant="primary" fullWidth onClick={onDismiss} />
        </>
      ) : hold ? (
        <HeldNotice
          hold={hold}
          cancelling={cancellingHold}
          cancelError={holdCancelError}
          onCancelHold={() => void handleCancelHold()}
          onClose={onDismiss}
        />
      ) : (
        <>
          <p className="text-[13px]" style={{ color: white.w60 }}>
            This deletes your account. It is anonymised immediately and fully deleted within 30
            days; payment records are kept, anonymised, for 7 years for tax. This cannot be undone.
            {hasPassword ? ' Enter your password to confirm.' : ' Type DELETE below to confirm.'}
          </p>
          {holdMode && (
            <p className="rounded-birdo-sm px-3 py-2 text-[12px]" style={{ backgroundColor: white.w05, color: white.w80 }}>
              {HOLD_EXPLAINED}
            </p>
          )}
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
          {askingNumber && !holdMode && (
            <BirdoTextField
              value={accountNumber}
              onChange={(v) => {
                setAccountNumber(digitsOnly(v).slice(0, ACCOUNT_NUMBER_LENGTH));
                if (numberError) setNumberError(null);
              }}
              label="Account number"
              type="password"
              placeholder="24 digits"
              hint="Enter the 24-digit account number you signed up with"
              errorText={numberError}
              disabled={deleting}
              autoComplete="off"
            />
          )}
          {askingEmailCode && !holdMode && (
            <>
              <p className="text-[12px]" style={{ color: white.w80 }}>
                {emailCodeSent
                  ? emailCodeSentTo
                    ? `We emailed a code to ${emailCodeSentTo}. It works once for ${emailCodeMinutes ?? 10} minutes.`
                    : `We emailed a code to your account address. It works once for ${emailCodeMinutes ?? 10} minutes.`
                  : 'Enter the code we emailed you to delete your account.'}
              </p>
              <BirdoButton
                text={emailCodeSent ? 'Send a new code' : 'Email me a code'}
                variant="secondary"
                fullWidth
                isLoading={sendingCode}
                disabled={sendingCode || deleting}
                onClick={handleSendCode}
              />
              {emailCodeSent && (
                <BirdoTextField
                  value={emailCode}
                  onChange={(v) => {
                    setEmailCode(digitsOnly(v).slice(0, EMAIL_CODE_LENGTH));
                    if (emailCodeError) setEmailCodeError(null);
                  }}
                  label="Emailed code"
                  type="text"
                  placeholder="123456"
                  errorText={emailCodeError}
                  disabled={deleting}
                  autoComplete="one-time-code"
                />
              )}
              {!emailCodeSent && emailCodeError && (
                <p className="text-[12px]" style={{ color: statusTokens.red }}>
                  {emailCodeError}
                </p>
              )}
            </>
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
          {holdMode ? (
            <div className="flex gap-2.5">
              <BirdoButton
                text="Back"
                variant="secondary"
                fullWidth
                disabled={deleting}
                onClick={() => {
                  setHoldMode(false);
                  setError(null);
                }}
              />
              <BirdoButton
                text={deleting ? 'Sending\u2026' : 'Delete in 24 hours'}
                variant="danger"
                fullWidth
                isLoading={deleting}
                disabled={!canSubmitHold}
                onClick={handleHold}
              />
            </div>
          ) : (
            <>
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
              {holdOffered && (
                <BirdoButton
                  text={holdOfferText}
                  variant="ghost"
                  fullWidth
                  disabled={deleting}
                  onClick={() => {
                    setHoldMode(true);
                    setError(null);
                    setNumberError(null);
                    setEmailCodeError(null);
                  }}
                />
              )}
            </>
          )}
        </>
      )}
    </BirdoDialog>
  );
}

/**
 * MR-2335: the deletion is ON HOLD, not done. The account and this sign-in
 * stay until the time shown; Cancel keeps the account.
 */
function HeldNotice({
  hold,
  cancelling,
  cancelError,
  onCancelHold,
  onClose,
}: {
  hold: DeletionHold;
  cancelling: boolean;
  cancelError: string | null;
  onCancelHold: () => void;
  onClose: () => void;
}) {
  return (
    <>
      <p className="text-[13px] font-semibold" style={{ color: white.w100 }}>
        {`Your account will be deleted ${holdWhen(hold.applyAfter)}.`}
      </p>
      <p className="text-[12px]" style={{ color: white.w80 }}>
        {hold.alreadyPending ? 'This deletion was already waiting; nothing new was filed. ' : ''}
        Until then your account works as usual. Cancel it here or on the website to keep your account.{' '}
        {SIGN_OUT_CANCELS_HOLD}
      </p>
      {cancelError && (
        <p className="text-[12px]" style={{ color: statusTokens.red }}>
          {cancelError}
        </p>
      )}
      <div className="flex gap-2.5">
        <BirdoButton
          text="Cancel deletion"
          variant="secondary"
          fullWidth
          isLoading={cancelling}
          disabled={cancelling}
          onClick={onCancelHold}
        />
        <BirdoButton text="Close" variant="primary" fullWidth disabled={cancelling} onClick={onClose} />
      </div>
    </>
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
