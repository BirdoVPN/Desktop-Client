/**
 * The two-factor code field, one definition for every place that asks for it:
 * the sign-in challenge and account deletion (Account API contract item 85:
 * "the same input style and backup-code support as the login 2FA screen").
 */

/** A 6-digit TOTP, or a hex backup code (16 hex digits, dashes optional). */
export function isTwoFactorCode(code: string): boolean {
  return /^\d{6}$/.test(code) || /^[0-9A-Fa-f]{4}(?:-?[0-9A-Fa-f]{4})+$/.test(code);
}

/** Keep digits, hex letters and dashes; a dashed backup code is 19 characters. */
export const TWO_FACTOR_MAX_LENGTH = 19;
export function sanitizeTwoFactorInput(raw: string): string {
  return raw.replace(/[^0-9A-Fa-f-]/g, '').slice(0, TWO_FACTOR_MAX_LENGTH);
}

export const TWO_FACTOR_PLACEHOLDER = '000000 or backup code';
export const TWO_FACTOR_HINT = 'Enter the 6-digit code from your authenticator, or a backup code';
