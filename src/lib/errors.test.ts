/**
 * errorCopy — the one IpcError → words map (W2-012, P1-parity "Key errors").
 *
 * Run: npx vitest run src/lib/errors.test.ts
 */
import { describe, it, expect } from 'vitest';
import {
  errorCopy,
  errorText,
  giveUpKind,
  giveUpMessage,
  isSilentError,
  PQ_FAILED_COPY,
  REVOKED_COPY,
  SESSION_EXPIRED_COPY,
  STEALTH_FAILED_COPY,
  UPDATE_REQUIRED_COPY,
} from './errors';
import type { IpcError, IpcErrorCode } from './ipc';

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
  'device_limit',
  'subscription_required',
  'upgrade_required',
  'rate_limited',
  'invalid_credentials',
  'two_factor_required',
  'two_factor_invalid',
  'cert_pin_failed',
  'stealth_failed',
  'pq_failed',
  'killswitch_failed',
  'adapter_failed',
  'not_elevated',
  'cancelled',
  'server_error',
  'unknown',
];

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

  it('says how long to wait when Rust knows', () => {
    expect(errorCopy(err('rate_limited', { retry_after_secs: 30 })).message).toBe(
      'Too many attempts. Please wait 30 seconds.',
    );
  });

  it('a legacy string error gets the generic sentence, not its own text', () => {
    expect(errorText('Session expired — please reconnect')).toBe('Something went wrong. Please try again.');
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

  it('never claims traffic is unblocked while the always-on kill switch still holds it', () => {
    const m = giveUpMessage('never_established', 1, true);
    expect(m).not.toContain('no longer being blocked');
    expect(m).toContain('still blocking traffic');
    expect(m).toContain('after 1 attempt:');
  });
});
