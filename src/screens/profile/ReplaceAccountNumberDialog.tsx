/**
 * Replace the anonymous account number (MR-1707, birdo-web #850), two phases.
 *
 * 1. PROOF: the user types the CURRENT number (and the password if the account
 *    has one, and a two-factor code if it is on). `rotate_anonymous_number_prepare`
 *    changes nothing on the account: the server holds a new number pending for
 *    ten minutes and returns it ONCE.
 * 2. SAVE: the new number is shown with a copy button; "I've saved it" must be
 *    ticked to go on.
 * 3. CONFIRM: the user re-types the whole new number and
 *    `rotate_anonymous_number_confirm` swaps it in. The old number dies, every
 *    other device is signed out, and this session continues on fresh tokens
 *    that Rust stores as a sign-in does.
 *
 * The lost-confirm case: if confirm fails for any reason that leaves the
 * account unchanged (offline, a server error), the new number is still in
 * this dialog's memory and the old one still works, so the user can retry or
 * go back and read the number again. Only `not_pending` / `account_changed`
 * send them back to the start, because the pending number is gone.
 *
 * Neither number is logged or persisted: they live in component state for as
 * long as the dialog is open and are dropped when it closes.
 *
 * Reachable only behind `FEATURES.anonNumberRotation` (`lib/features.ts`).
 */
import { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { Check, Copy, KeyRound, ShieldAlert } from 'lucide-react';
import { BirdoButton, BirdoDialog, BirdoTextField } from '@/components/birdo';
import { brand, hairline, status as statusTokens, white } from '@/lib/birdo-theme';
import { copySensitive } from '@/lib/clipboard';
import { errorCopy } from '@/lib/errors';
import { toIpcError } from '@/lib/ipc';
import {
  isTwoFactorCode,
  sanitizeTwoFactorInput,
  TWO_FACTOR_HINT,
  TWO_FACTOR_PLACEHOLDER,
} from '@/lib/two-factor';
import { signOut } from '@/session/session';
import { useAppStore } from '@/store/app-store';
import { formatAccountNumber, identityPatch, type AuthStateIdentity } from '@/utils/helpers';

/** What the Rust `rotate_anonymous_number_*` commands answer (`RotationStep`). */
export interface RotationStep {
  refusal:
    | null
    | 'disabled'
    | 'unauthorized'
    | 'not_pending'
    | 'account_changed'
    | 'mismatch'
    | 'bad_number'
    | 'rate_limited';
  newNumber: string | null;
  expiresInSeconds: number | null;
  retryAfterSecs: number | null;
}

export const ROTATION_COPY = {
  disabled: 'Replacing the account number is not available yet.',
  proofWrong:
    'That did not check out. Check the current number' +
    '{password}{code}, or sign in again if your session ended.',
  notPending: 'The new number expired. Start again to get a new one.',
  accountChanged: 'This account changed in the meantime. Start again to get a new number.',
  mismatch: "That isn't the new number. Check it against the one you saved.",
  confirmSessionEnded:
    'Your session ended. Sign in with your current number, then start again.',
  badNumber: 'Enter all 24 digits of the number.',
  generic: "Couldn't replace the account number. Your current number still works. Try again.",
  maybeActive: 'Your new number may already be active. Sign in with the new number you saved.',
  done: 'Your account number has been replaced. Every other device was signed out and the old number no longer works.',
} as const;

type Phase = 'proof' | 'save' | 'confirm' | 'maybeActive' | 'done';

function waitText(secs: number | null): string {
  if (!secs || secs <= 0) return 'Too many tries. Please wait a while, then try again.';
  const mins = Math.ceil(secs / 60);
  return mins > 1
    ? `Too many tries. Please wait about ${mins} minutes, then try again.`
    : `Too many tries. Please wait ${Math.ceil(secs)} seconds, then try again.`;
}

export function ReplaceAccountNumberDialog({
  open,
  hasPassword,
  onDismiss,
}: {
  open: boolean;
  hasPassword: boolean;
  onDismiss: () => void;
}) {
  const [phase, setPhase] = useState<Phase>('proof');
  const [currentNumber, setCurrentNumber] = useState('');
  const [password, setPassword] = useState('');
  const [twoFactorCode, setTwoFactorCode] = useState('');
  // The NEW number: in memory only, from prepare until the dialog closes.
  const [newNumber, setNewNumber] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const [retyped, setRetyped] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const copyTimer = useRef<ReturnType<typeof setTimeout> | null>(null);
  // Set once a confirm has been SENT. If it committed on the server and its
  // answer was lost, the old tokens are revoked, so a later 401 or 409
  // `rotation_not_pending` means "probably done", not "start again".
  const confirmSent = useRef(false);

  useEffect(
    () => () => {
      if (copyTimer.current) clearTimeout(copyTimer.current);
    },
    [],
  );

  const startOver = (message: string | null) => {
    setNewNumber(null);
    setSaved(false);
    setRetyped('');
    setCopied(false);
    setPhase('proof');
    setError(message);
  };

  const digits = (v: string) => v.replace(/\D/g, '');
  const canPrepare =
    !busy &&
    digits(currentNumber).length === 24 &&
    (!hasPassword || password.length > 0) &&
    (twoFactorCode === '' || isTwoFactorCode(twoFactorCode));

  const prepare = async () => {
    if (!canPrepare) return;
    setBusy(true);
    setError(null);
    try {
      const step = await invoke<RotationStep>('rotate_anonymous_number_prepare', {
        request: {
          currentNumber: digits(currentNumber),
          ...(hasPassword ? { password } : {}),
          ...(twoFactorCode ? { twoFactorCode } : {}),
        },
      });
      if (step.refusal === null && step.newNumber) {
        setNewNumber(step.newNumber);
        // The proof is spent: not kept a moment longer than needed.
        setCurrentNumber('');
        setPassword('');
        setTwoFactorCode('');
        setPhase('save');
      } else if (step.refusal === 'disabled') {
        setError(ROTATION_COPY.disabled);
      } else if (step.refusal === 'rate_limited') {
        setError(waitText(step.retryAfterSecs));
      } else if (step.refusal === 'bad_number') {
        setError(ROTATION_COPY.badNumber);
      } else if (step.refusal === 'unauthorized') {
        setError(
          ROTATION_COPY.proofWrong
            .replace('{password}', hasPassword ? ', the password' : '')
            .replace('{code}', twoFactorCode ? ' and the code' : ''),
        );
      } else {
        setError(ROTATION_COPY.generic);
      }
    } catch (e: unknown) {
      setError(errorCopy(toIpcError(e), 'general').message || ROTATION_COPY.generic);
    } finally {
      setBusy(false);
    }
  };

  const copyNew = async () => {
    if (!newNumber) return;
    try {
      // MR-1723: kept out of clipboard history and cleared after a minute.
      await copySensitive(digits(newNumber));
      setCopied(true);
      if (copyTimer.current) clearTimeout(copyTimer.current);
      copyTimer.current = setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable: the number is on screen to copy by hand */
    }
  };

  const canConfirm = !busy && digits(retyped).length === 24;

  const confirm = async () => {
    if (!canConfirm) return;
    const retry = confirmSent.current;
    confirmSent.current = true;
    setBusy(true);
    setError(null);
    try {
      const step = await invoke<RotationStep>('rotate_anonymous_number_confirm', {
        newNumber: digits(retyped),
      });
      if (step.refusal === null) {
        setNewNumber(null);
        setRetyped('');
        setPhase('done');
        // Rust now holds the fresh tokens; read the identity again (the number
        // shown on Profile is the new one, or its mask).
        try {
          const st = await invoke<AuthStateIdentity>('get_auth_state');
          const patch = st ? identityPatch(st) : {};
          if (Object.keys(patch).length > 0) useAppStore.getState().setAccount(patch);
        } catch {
          /* non-fatal: the next identity refresh shows it */
        }
      } else if (retry && (step.refusal === 'not_pending' || step.refusal === 'unauthorized')) {
        setPhase('maybeActive');
      } else if (step.refusal === 'not_pending') {
        startOver(ROTATION_COPY.notPending);
      } else if (step.refusal === 'account_changed') {
        startOver(ROTATION_COPY.accountChanged);
      } else if (step.refusal === 'mismatch') {
        setError(ROTATION_COPY.mismatch);
      } else if (step.refusal === 'disabled') {
        startOver(ROTATION_COPY.disabled);
      } else if (step.refusal === 'rate_limited') {
        setError(waitText(step.retryAfterSecs));
      } else if (step.refusal === 'unauthorized') {
        setError(ROTATION_COPY.confirmSessionEnded);
      } else {
        setError(ROTATION_COPY.generic);
      }
    } catch (e: unknown) {
      if (retry && toIpcError(e).code === 'session_expired') {
        setPhase('maybeActive');
        return;
      }
      // Offline, a server error, a lost answer: the account is unchanged as
      // far as this client knows, the old number still works, and the new
      // one is still here to type again or to read again.
      setError(errorCopy(toIpcError(e), 'general').message || ROTATION_COPY.generic);
    } finally {
      setBusy(false);
    }
  };

  return (
    <BirdoDialog open={open} onClose={onDismiss} busy={busy} title="Replace account number" icon={KeyRound}>
      {phase === 'proof' && (
        <>
          <p className="text-[13px]" style={{ color: white.w60 }}>
            You get a new number. The old one stops working and every other device is signed out,
            but only once you confirm the new one on the next steps.
          </p>
          <BirdoTextField
            value={currentNumber}
            onChange={(v) => {
              setCurrentNumber(formatAccountNumber(digits(v).slice(0, 24)));
              if (error) setError(null);
            }}
            label="Current account number"
            placeholder="0000 0000 0000 0000 0000 0000"
            inputMode="numeric"
            autoComplete="off"
            disabled={busy}
          />
          {hasPassword && (
            <BirdoTextField
              value={password}
              onChange={(v) => {
                setPassword(v);
                if (error) setError(null);
              }}
              label="Password"
              type="password"
              placeholder="••••••••"
              autoComplete="current-password"
              disabled={busy}
            />
          )}
          <BirdoTextField
            value={twoFactorCode}
            onChange={(v) => {
              setTwoFactorCode(sanitizeTwoFactorInput(v));
              if (error) setError(null);
            }}
            label="Two-factor code (only if turned on)"
            placeholder={TWO_FACTOR_PLACEHOLDER}
            hint={TWO_FACTOR_HINT}
            autoComplete="one-time-code"
            disabled={busy}
          />
          {error && (
            <p role="alert" className="text-[12px]" style={{ color: statusTokens.red }}>
              {error}
            </p>
          )}
          <div className="flex gap-2.5">
            <BirdoButton text="Cancel" variant="secondary" fullWidth disabled={busy} onClick={onDismiss} />
            <BirdoButton
              text={busy ? 'Checking…' : 'Get a new number'}
              variant="primary"
              fullWidth
              isLoading={busy}
              disabled={!canPrepare}
              onClick={prepare}
            />
          </div>
        </>
      )}

      {phase === 'save' && newNumber && (
        <>
          <p className="text-[13px]" style={{ color: white.w60 }}>
            This is your new account number. It is shown only once, here. Save it somewhere safe
            before you go on. Your old number still works until you confirm.
          </p>
          <div
            className="flex w-full items-center gap-2 rounded-birdo-sm px-3 py-2"
            style={{ backgroundColor: white.w04, border: `1px solid ${hairline.soft}` }}
          >
            <span
              className="min-w-0 flex-1 break-all font-mono text-[13px] tracking-wide"
              style={{ color: '#FFFFFF' }}
              data-testid="new-account-number"
            >
              {formatAccountNumber(newNumber)}
            </span>
            <button
              type="button"
              onClick={copyNew}
              aria-label="Copy new account number"
              className="rounded-birdo-xs p-1.5 transition-colors hover:bg-white/5"
            >
              {copied ? (
                <Check size={16} color={brand.accentLight} aria-hidden />
              ) : (
                <Copy size={16} color={white.w60} aria-hidden />
              )}
            </button>
          </div>
          <p className="flex items-start gap-1.5 text-[12px]" style={{ color: white.w60 }}>
            <ShieldAlert size={14} color={statusTokens.yellow} aria-hidden className="mt-0.5 shrink-0" />
            <span>We can&apos;t show it again or reset it if you lose it.</span>
          </p>
          <label className="flex items-center gap-2 text-[13px]" style={{ color: white.w80 }}>
            <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} />
            I&apos;ve saved it
          </label>
          <div className="flex gap-2.5">
            <BirdoButton text="Cancel" variant="secondary" fullWidth onClick={onDismiss} />
            <BirdoButton
              text="Continue"
              variant="primary"
              fullWidth
              disabled={!saved}
              onClick={() => {
                setError(null);
                setPhase('confirm');
              }}
            />
          </div>
        </>
      )}

      {phase === 'confirm' && (
        <>
          <p className="text-[13px]" style={{ color: white.w60 }}>
            Type the new number again to confirm. When it matches, the old number stops working and
            every other device is signed out.
          </p>
          <BirdoTextField
            value={retyped}
            onChange={(v) => {
              setRetyped(formatAccountNumber(digits(v).slice(0, 24)));
              if (error) setError(null);
            }}
            label="New account number"
            placeholder="0000 0000 0000 0000 0000 0000"
            inputMode="numeric"
            autoComplete="off"
            disabled={busy}
          />
          {error && (
            <p role="alert" className="text-[12px]" style={{ color: statusTokens.red }}>
              {error}
            </p>
          )}
          <div className="flex gap-2.5">
            <BirdoButton
              text="Show the number again"
              variant="secondary"
              fullWidth
              disabled={busy}
              onClick={() => {
                setError(null);
                setPhase('save');
              }}
            />
            <BirdoButton
              text={busy ? 'Replacing…' : 'Replace number'}
              variant="primary"
              fullWidth
              isLoading={busy}
              disabled={!canConfirm}
              onClick={confirm}
            />
          </div>
        </>
      )}

      {phase === 'maybeActive' && newNumber && (
        <>
          <p role="alert" className="text-[13px]" style={{ color: statusTokens.yellow }}>
            {ROTATION_COPY.maybeActive}
          </p>
          <div
            className="w-full rounded-birdo-sm px-3 py-2"
            style={{ backgroundColor: white.w04, border: `1px solid ${hairline.soft}` }}
          >
            <span
              className="break-all font-mono text-[13px] tracking-wide"
              style={{ color: '#FFFFFF' }}
              data-testid="new-account-number"
            >
              {formatAccountNumber(newNumber)}
            </span>
          </div>
          <div className="flex gap-2.5">
            <BirdoButton text="Close" variant="secondary" fullWidth onClick={onDismiss} />
            <BirdoButton
              text="Sign in again"
              variant="primary"
              fullWidth
              onClick={() => {
                setNewNumber(null);
                void signOut();
                onDismiss();
              }}
            />
          </div>
        </>
      )}

      {phase === 'done' && (
        <>
          <p className="text-[13px]" style={{ color: white.w80 }}>
            {ROTATION_COPY.done}
          </p>
          <BirdoButton text="OK" variant="primary" fullWidth onClick={onDismiss} />
        </>
      )}
    </BirdoDialog>
  );
}
