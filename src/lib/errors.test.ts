/**
 * errorCopy — the one IpcError → words map (W2-012, P1-parity "Key errors").
 *
 * Run: npx vitest run src/lib/errors.test.ts
 */
import { describe, it, expect } from 'vitest';
import {
  ACCOUNT_RESTRICTED_COPY,
  appealUrl,
  CLIENT_ATTESTATION_COPY,
  CONSENT_REQUIRED_COPY,
  errorCopy,
  errorText,
  giveUpKind,
  giveUpMessage,
  isSilentError,
  KILLSWITCH_HOLDING_COPY,
  PQ_FAILED_COPY,
  QUOTA_EXCEEDED_COPY,
  REGISTRATION_NOT_ALLOWED_COPY,
  quotaGraceMessage,
  REVOKED_COPY,
  SESSION_EXPIRED_COPY,
  STEALTH_FAILED_COPY,
  UPDATE_REQUIRED_COPY,
  vpnErrorCopy,
} from './errors';
import { toIpcError, type IpcError, type IpcErrorCode } from './ipc';

const err = (code: IpcErrorCode, extra: Partial<IpcError> = {}): IpcError => ({
  code,
  message: 'RAW RUST TEXT: os error 10061 at 192.0.2.1:51820',
  retryable: true,
  retry_after_secs: null,
  ...extra,
});

const ALL: IpcErrorCode[] = [
  'network_offline',
  'server_unreachable',
  'server_unavailable',
  'session_expired',
  'revoked',
  'quota_exceeded',
  'device_limit',
  'subscription_required',
  'upgrade_required',
  'rate_limited',
  'invalid_credentials',
  'two_factor_required',
  'two_factor_invalid',
  'account_number_required',
  'account_number_invalid',
  'email_code_required',
  'email_code_invalid',
  'apple_reauth_required',
  'cert_pin_failed',
  'stealth_failed',
  'pq_failed',
  'killswitch_failed',
  'adapter_failed',
  'not_elevated',
  'cancelled',
  'server_error',
  'settings_unverified',
  'client_attestation_required',
  'consent_required',
  'unknown',
];

/** MR-2229: the two refusals whose own sentence is the explanation. */
describe('account_restricted and registration_not_allowed', () => {
  const restricted = (extra: Partial<IpcError> = {}) =>
    err('account_restricted', {
      message: 'New free-plan connections on this account are paused.',
      retryable: false,
      restriction: { until: '2026-10-31T14:00:00.000Z', appeal_path: '/dashboard/devices' },
      ...extra,
    });

  it('shows the server sentence, the end time and a review link, and never offers Try again', () => {
    const copy = errorCopy(restricted(), 'vpn');
    expect(copy.message).toContain('New free-plan connections on this account are paused.');
    expect(copy.message).toMatch(/Connections resume .+/);
    expect(copy.action).toBe('appeal');
    expect(appealUrl(restricted())).toBe('https://birdo.app/dashboard/devices');
  });

  it('falls back to its own copy without a sentence or a time, and has no link without a path', () => {
    const copy = errorCopy(restricted({ message: '', restriction: undefined }), 'vpn');
    expect(copy).toEqual({ message: ACCOUNT_RESTRICTED_COPY, action: null });
  });

  it.each(['https://evil.example/x', '//evil.example/x', 'dashboard', '/a b', '/a\b', '/a\\b'])(
    'never opens %s',
    (appeal_path) => {
      const e = restricted({ restriction: { until: null, appeal_path } });
      expect(appealUrl(e)).toBeNull();
      expect(errorCopy(e, 'vpn').action).toBeNull();
    },
  );

  it('toIpcError reads the restriction (snake or camel) and ignores it on other codes', () => {
    const wire = { code: 'account_restricted', message: 'm', retryable: false, restriction: { until: 'u', appealPath: '/p' } };
    expect(toIpcError(wire).restriction).toEqual({ until: 'u', appeal_path: '/p' });
    expect(toIpcError({ ...wire, code: 'server_error' }).restriction).toBeUndefined();
    expect(toIpcError({ code: 'some_future_code', message: 'm' }).code).toBe('unknown');
  });

  it('a refused sign-up shows the server sentence instead of "Upgrade to unlock"', () => {
    const sentence = 'BirdoVPN cannot create new accounts in your country right now.';
    const copy = errorCopy(err('registration_not_allowed', { message: sentence, retryable: false }), 'general');
    expect(copy).toEqual({ message: sentence, action: null });
    expect(copy.message).not.toMatch(/upgrade/i);
    expect(errorCopy(err('registration_not_allowed', { message: '' })).message).toBe(REGISTRATION_NOT_ALLOWED_COPY);
    // Other 403s are unchanged.
    expect(errorCopy(err('subscription_required'), 'general').message).toMatch(/Upgrade to unlock/);
  });
});

describe('errorCopy', () => {
  it.each(ALL.filter((c) => c !== 'cancelled'))('%s has canonical copy and never echoes Rust\'s message', (code) => {
    const { message } = errorCopy(err(code));
    expect(message.length).toBeGreaterThan(10);
    expect(message).not.toContain('RAW RUST TEXT');
    expect(message).not.toContain('192.0.2.1');
    // Canonical punctuation: the Unicode ellipsis, never three dots.
    expect(message).not.toContain('...');
  });

  it('cancelled (the user\'s own Disconnect during a connect) is silent', () => {
    expect(isSilentError(err('cancelled'))).toBe(true);
    expect(errorCopy(err('cancelled')).message).toBe('');
  });

  it('uses the canonical sentences from P1-parity', () => {
    expect(errorCopy(err('pq_failed'))).toEqual({ message: PQ_FAILED_COPY, action: 'open_settings' });
    expect(errorCopy(err('stealth_failed')).message).toBe(STEALTH_FAILED_COPY);
    expect(errorCopy(err('revoked'))).toEqual({ message: REVOKED_COPY, action: 'connect' });
    expect(errorCopy(err('quota_exceeded'))).toEqual({ message: QUOTA_EXCEEDED_COPY, action: 'view_plans' });
    expect(QUOTA_EXCEEDED_COPY).toBe(
      "You've used this month's free data allowance. Upgrade to keep using BirdoVPN.",
    );
    expect(errorCopy(err('session_expired'))).toEqual({ message: SESSION_EXPIRED_COPY, action: 'sign_in' });
    expect(errorCopy(err('upgrade_required')).message).toBe(UPDATE_REQUIRED_COPY);
    expect(errorCopy(err('rate_limited')).message).toBe('Too many attempts. Please wait a moment.');
    expect(errorCopy(err('server_unreachable')).message).toBe(
      "Couldn't establish a secure tunnel to this server. Try another location.",
    );
  });

  it('keeps a certificate-pinning failure distinct from "unable to reach the server" (W2-012)', () => {
    const { message } = errorCopy(err('cert_pin_failed'));
    expect(message).toMatch(/intercept/);
    expect(message).not.toMatch(/reach|check your (internet|connection)/i);
  });

  it('words invalid credentials for the place they happened', () => {
    expect(errorCopy(err('invalid_credentials'), 'sign_in').message).toMatch(/email or password/);
    expect(errorCopy(err('invalid_credentials'), 'anonymous_sign_in').message).toMatch(/account number/);
    expect(errorCopy(err('invalid_credentials'), 'password_confirm').message).toBe(
      'Incorrect password. Please try again.',
    );
  });

  // MR-1944: its own words, never the plan copy a bare 403 gets.
  it('an attestation refusal is not a plan refusal, and says what helps without alarm', () => {
    const copy = errorCopy(err('client_attestation_required'), 'vpn');
    expect(copy).toEqual({ message: CLIENT_ATTESTATION_COPY, action: null });
    expect(copy.message).not.toBe(errorCopy(err('subscription_required')).message);
    expect(copy.message).not.toMatch(/plan|upgrade|subscription|unmodified|tamper/i);
    expect(copy.message).toMatch(/latest version/);
    // Rust's wire shape is a known code, not `unknown`.
    expect(errorText({ code: 'client_attestation_required', message: 'raw' })).toBe(CLIENT_ATTESTATION_COPY);
  });

  // MR-2016: the window's own Quick Connect meets `consent_required` only with
  // the consent screen already accepted (Rust's record failed to save), so the
  // copy says it was not saved, and sends nobody to "review the privacy terms".
  it('a consent refusal says the consent was not saved, not "review and accept"', () => {
    expect(errorCopy(err('consent_required'))).toEqual({ message: CONSENT_REQUIRED_COPY, action: null });
    expect(CONSENT_REQUIRED_COPY).toMatch(/wasn't saved/);
    expect(CONSENT_REQUIRED_COPY).not.toMatch(/review|accept/i);
  });

  it('says how long to wait when Rust knows', () => {
    expect(errorCopy(err('rate_limited', { retry_after_secs: 30 })).message).toBe(
      'Too many attempts. Please wait 30 seconds.',
    );
  });

  it('a legacy string error gets the generic sentence, not its own text', () => {
    expect(errorText('Session expired — please reconnect')).toBe('Something went wrong. Please try again.');
  });
});

// MR-2111: the kept tunnel (Desktop #313) is `killswitch_failed` with traffic
// held. Try again repeats the failure; Disconnect releases it.
describe('vpnErrorCopy', () => {
  it('says traffic is held, with Disconnect, for a kill-switch failure while blocking', () => {
    expect(vpnErrorCopy(err('killswitch_failed'), true)).toEqual({
      message: KILLSWITCH_HOLDING_COPY,
      action: 'disconnect',
    });
    expect(KILLSWITCH_HOLDING_COPY).toMatch(/traffic is held/);
    expect(KILLSWITCH_HOLDING_COPY).toMatch(/Disconnect/);
    expect(KILLSWITCH_HOLDING_COPY).not.toMatch(/try again/i);
  });

  it('is errorCopy for everything else', () => {
    expect(vpnErrorCopy(err('killswitch_failed'), false)).toEqual(errorCopy(err('killswitch_failed'), 'vpn'));
    expect(vpnErrorCopy(err('server_unreachable'), true)).toEqual(errorCopy(err('server_unreachable'), 'vpn'));
  });
});

describe('reconnect give-up (P1-parity-020)', () => {
  it('picks the iOS kind from the final error code', () => {
    expect(giveUpKind(err('revoked'))).toBe('revoked');
    expect(giveUpKind(err('server_unreachable'))).toBe('never_established');
    expect(giveUpKind(err('adapter_failed'))).toBe('died_after_handshake');
    expect(giveUpKind(null)).toBe('died_after_handshake');
  });

  it('says what stopped, how many tries, and the next step', () => {
    expect(giveUpMessage('died_after_handshake', 10, false)).toBe(
      'BirdoVPN stopped reconnecting after 10 attempts: the connection to this server keeps dropping. ' +
        'Traffic is no longer being blocked. Click Connect to retry, or pick another location.',
    );
  });

  // MR-2071: recovery stopped because the kill switch could not be armed. It
  // used to read as 'died_after_handshake': blamed the server and sent the
  // user to another location, when the cause is on this device.
  it('names the kill switch when it is why reconnecting stopped', () => {
    expect(giveUpKind(err('killswitch_failed'))).toBe('killswitch_failed');
    const m = giveUpMessage(giveUpKind(err('killswitch_failed')), 10, false);
    expect(m).toBe(
      "BirdoVPN stopped reconnecting after 10 attempts: the kill switch couldn't be armed on this " +
        "device, so BirdoVPN didn't reconnect without it. Traffic is no longer being blocked. " +
        'Click Connect to try again.',
    );
    expect(m).not.toMatch(/server|location/);
  });

  it('never claims traffic is unblocked while the always-on kill switch still holds it', () => {
    const m = giveUpMessage('never_established', 1, true);
    expect(m).not.toContain('no longer being blocked');
    expect(m).toContain('still blocking traffic');
    expect(m).toContain('after 1 attempt:');
  });
});

/** birdo-web #590: the heads-up inside the Free allowance's grace window. */
describe('quotaGraceMessage', () => {
  it('says how many minutes are left, rounded up, never "0 min"', () => {
    expect(quotaGraceMessage(540)).toBe('Free data allowance used — your connection ends in 9 min.');
    expect(quotaGraceMessage(61)).toBe('Free data allowance used — your connection ends in 2 min.');
    expect(quotaGraceMessage(5)).toBe('Free data allowance used — your connection ends in 1 min.');
  });

  it('without a figure from the server, says soon', () => {
    expect(quotaGraceMessage(null)).toBe('Free data allowance used — your connection ends soon.');
  });
});
