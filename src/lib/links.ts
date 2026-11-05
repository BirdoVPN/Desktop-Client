/**
 * Web destinations the app opens in the system browser. One place, so the
 * billing link Profile, Pricing and Settings each spelled out cannot drift
 * (W2-038).
 */
import { openUrl } from '@tauri-apps/plugin-opener';

export const DASHBOARD_URL = 'https://dashboard.birdo.app';
export const BILLING_URL = `${DASHBOARD_URL}/billing`;
/** The website's own origin: `birdo.app/dashboard/...` redirects to the dashboard host. */
export const WEBSITE_URL = 'https://birdo.app';

/**
 * A website link from a path the server named, only if it is a plain same-site
 * path (`/x`): never `//host`, a scheme, a backslash or whitespace.
 */
export function websiteUrl(path: string | null | undefined): string | null {
  if (!path || !path.startsWith('/') || path.startsWith('//') || /[^\u0021-\u007e]|\u005c/.test(path)) return null;
  return `${WEBSITE_URL}${path}`;
}

/** Open a link from `websiteUrl` in the system browser; a refusal is not an error here. */
export function openWebsite(url: string): void {
  openUrl(url).catch(() => {});
}
export const PRIVACY_URL = 'https://birdo.app/privacy';
export const TERMS_URL = 'https://birdo.app/terms';
