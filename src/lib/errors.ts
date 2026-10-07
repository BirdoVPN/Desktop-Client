/**
 * The one place an `IpcError` becomes words (W2-012, P1-parity "Key errors").
 *
 * Copy is chosen by `code`, never by the text of `message`: Rust's message is
 * sanitised but written for logs, and matching substrings of it is how a
 * certificate-pinning warning ended up reading "Unable to reach the server".
 * Wording follows the canonical vocabulary in `audit/P1-parity.md`, sourced
 * from iOS where iOS has a sentence for the case.
 */
import { toIpcError, type IpcError, type IpcErrorCode } from '@/lib/ipc';

/** What the banner's button does, if it has one. */
export type ErrorAction =
  | 'sign_in'
  | 'view_plans'
  | 'open_settings'
  | 'choose_server'
  | 'connect'
  | 'retry'
  | 'update'
  | null;

export interface ErrorCopy {
  message: string;
  action: ErrorAction;
}

/** Where the error happened, for the few codes whose wording depends on it. */
export type ErrorContext = 'vpn' | 'sign_in' | 'anonymous_sign_in' | 'password_confirm' | 'general';

// Canonical sentences that more than one code, screen or test refer to.
export const PQ_FAILED_COPY =
  'Quantum-protected handshake failed. Not connecting, because continuing would fall back to ' +
  'weaker encryption. Try again, or turn off Quantum Protection in Settings to connect without it.';
export const STEALTH_FAILED_COPY =
  "Stealth Mode couldn't start. Not connecting, so your traffic isn't sent unprotected. " +
  'Try again, or choose another location.';
export const REVOKED_COPY = 'Connection has been revoked. Please reconnect.';
export const QUOTA_EXCEEDED_COPY =
  "You've used this month's free data allowance. Upgrade to keep using BirdoVPN.";
export const SESSION_EXPIRED_COPY = 'Your session has expired. Sign in again.';
export const UPDATE_REQUIRED_COPY =
  'This version of BirdoVPN is no longer supported. Update to keep connecting.';
export const DEVICE_LIMIT_COPY =
  'This account is already connected on the maximum number of devices for its plan. ' +
  'Disconnect another device or upgrade your plan.';
export const SERVER_UNREACHABLE_COPY =
  "Couldn't establish a secure tunnel to this server. Try another location.";

const COPY: Record<Exclude<IpcErrorCode, 'cancelled'>, ErrorCopy> = {
  network_offline: {
    message: 'No internet connection. Check your network and try again.',
    action: 'retry',
  },
  server_unreachable: { message: SERVER_UNREACHABLE_COPY, action: 'choose_server' },
  server_unavailable: {
    message: "This server isn't available right now. Try another location.",
    action: 'choose_server',
  },
  session_expired: { message: SESSION_EXPIRED_COPY, action: 'sign_in' },
  revoked: { message: REVOKED_COPY, action: 'connect' },
  // The server ended the session over the Free allowance (birdo-web #590):
  // reconnecting cannot help, a plan can.
  quota_exceeded: { message: QUOTA_EXCEEDED_COPY, action: 'view_plans' },
  device_limit: { message: DEVICE_LIMIT_COPY, action: 'view_plans' },
  subscription_required: {
    message: "Your plan doesn't include this server or feature. Upgrade to unlock.",
    action: 'view_plans',
  },
  upgrade_required: { message: UPDATE_REQUIRED_COPY, action: 'update' },
  rate_limited: { message: 'Too many attempts. Please wait a moment.', action: null },
  invalid_credentials: {
    message: 'Incorrect email or password. Please try again.',
    action: null,
  },
  two_factor_required: {
    message: 'Enter the 6-digit code from your authenticator app.',
    action: null,
  },
  two_factor_invalid: {
    message: 'That verification code is invalid or has expired. Please try again.',
    action: null,
  },
  // Kept apart from every connectivity message on purpose: a pin failure can
  // mean the connection is being intercepted, and "check your internet" would
  // tell the user to keep trying on exactly that network.
  cert_pin_failed: {
    message:
      "BirdoVPN couldn't verify it is talking to its own servers. Something on this network " +
      'may be intercepting secure connections. Try a different network.',
    action: null,
  },
  stealth_failed: { message: STEALTH_FAILED_COPY, action: 'retry' },
  pq_failed: { message: PQ_FAILED_COPY, action: 'open_settings' },
  killswitch_failed: {
    message: "The kill switch couldn't be armed, so BirdoVPN didn't connect. Try again.",
    action: 'retry',
  },
  adapter_failed: {
    message:
      "Couldn't start the VPN network adapter. Try again; if it keeps failing, reinstall BirdoVPN.",
    action: 'retry',
  },
  not_elevated: {
    message: 'BirdoVPN needs administrator rights to connect. Restart it as an administrator.',
    action: null,
  },
  server_error: {
    message: 'Something went wrong on our side. Please try again in a moment.',
    action: 'retry',
  },
  unknown: { message: 'Something went wrong. Please try again.', action: 'retry' },
};

/**
 * The heads-up inside the Free allowance's grace window (birdo-web #590): the
 * session is still up, and ends when the window closes.
 */
export function quotaGraceMessage(secondsRemaining: number | null): string {
  if (secondsRemaining === null) return 'Free data allowance used — your connection ends soon.';
  const minutes = Math.max(1, Math.ceil(secondsRemaining / 60));
  return `Free data allowance used — your connection ends in ${minutes} min.`;
}

/** `cancelled` is the user's own Disconnect during a connect: nothing to say. */
export function isSilentError(e: IpcError | null | undefined): boolean {
  return e?.code === 'cancelled';
}

export function errorCopy(error: IpcError, context: ErrorContext = 'general'): ErrorCopy {
  if (error.code === 'cancelled') return { message: '', action: null };
  if (error.code === 'invalid_credentials') {
    if (context === 'anonymous_sign_in') {
      return { message: 'Incorrect account number or password. Please try again.', action: null };
    }
    if (context === 'password_confirm') {
      return { message: 'Incorrect password. Please try again.', action: null };
    }
  }
  if (error.code === 'rate_limited' && error.retry_after_secs && error.retry_after_secs > 0) {
    const secs = Math.ceil(error.retry_after_secs);
    return {
      message: `Too many attempts. Please wait ${secs} second${secs === 1 ? '' : 's'}.`,
      action: null,
    };
  }
  return COPY[error.code];
}

/** Convenience for call sites that only need the sentence. */
export function errorText(e: unknown, context: ErrorContext = 'general'): string {
  return errorCopy(toIpcError(e), context).message;
}

// ── Reconnect give-up (P1-parity-020) ──────────────────────────────────────

/**
 * Why auto-reconnect stopped, in the three kinds iOS's TunnelCircuitBreaker
 * distinguishes. The final `error` status says THAT it gave up (`gaveUp`,
 * REVIEW-WIN-009) and its error code says why (§3.4); these are the codes
 * that map onto iOS's kinds.
 */
export type GiveUpKind = 'revoked' | 'never_established' | 'died_after_handshake';

export function giveUpKind(error: IpcError | null | undefined): GiveUpKind {
  if (error?.code === 'revoked') return 'revoked';
  if (error?.code === 'server_unreachable') return 'never_established';
  return 'died_after_handshake';
}

/**
 * iOS `TunnelCircuitBreaker.userMessage`, with two deliberate edits: "Click",
 * not "Tap", on a desktop; and the blocked-traffic sentence follows the real
 * `kill_switch_blocking` bit. iOS always releases the block when it gives up;
 * Windows keeps it under the always-on kill switch (contract §3.4), and saying
 * "traffic is no longer being blocked" over a machine that is still firewalled
 * is the exact failure this message exists to end.
 */
export function giveUpMessage(kind: GiveUpKind, attempts: number | null, stillBlocking: boolean): string {
  const blocked = stillBlocking
    ? 'The kill switch is still blocking traffic; click Disconnect to restore your connection.'
    : 'Traffic is no longer being blocked.';
  const tries = attempts && attempts > 0 ? ` after ${attempts} attempt${attempts === 1 ? '' : 's'}` : '';
  switch (kind) {
    case 'revoked':
      return (
        'BirdoVPN stopped reconnecting: the server ended this connection ' +
        '(it may have been revoked, or claimed by another device). ' +
        `${blocked} Click Connect to start a new session.`
      );
    case 'never_established':
      return (
        `BirdoVPN stopped reconnecting${tries}: the tunnel came up but never reached this ` +
        `server, so no traffic could pass. ${blocked} Try a different location, or a different network.`
      );
    case 'died_after_handshake':
      return (
        `BirdoVPN stopped reconnecting${tries}: the connection to this server keeps dropping. ` +
        `${blocked} Click Connect to retry, or pick another location.`
      );
  }
}
