/**
 * Native notification utility for BirdoVPN.
 *
 * Sends native desktop notifications for VPN connection events, gated behind
 * the user's notification preference. Copy is the canonical set (P1-parity-028):
 * "BirdoVPN — Protected / Reconnecting… / Not connected / Connection error /
 * Kill Switch — all traffic blocked", body "via {server}[ · location][ · IP]" —
 * one word per event on every client, where this used to say "Connected",
 * "Secured" and "Connection Lost" for what the phones call "Protected".
 */

import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from '@tauri-apps/plugin-notification';
import { useAppStore, type ConnectionState } from '@/store/app-store';

let permissionReady = false;

/** Ensure notification permission is granted (call once at startup) */
export async function initNotifications(): Promise<void> {
  try {
    let granted = await isPermissionGranted();
    if (!granted) {
      const result = await requestPermission();
      granted = result === 'granted';
    }
    permissionReady = granted;
  } catch {
    // Notification plugin not available (e.g. dev mode)
    permissionReady = false;
  }
}

/** Send a notification if the user has notifications enabled */
function notify(title: string, body: string): void {
  if (!permissionReady) return;
  if (!(useAppStore.getState().settings?.notifications ?? false)) return;

  try {
    sendNotification({ title, body });
  } catch (err) {
    // Notification failures are non-fatal; log for debuggability.
    console.error('Failed to send notification:', err);
  }
}

/** Optional connection detail appended to connect/reconnect notifications. */
export interface ConnectionDetails {
  ip?: string | null;
  location?: string | null;
}

/**
 * Build a connect/reconnect body, appending IP and/or location only when the
 * user has the corresponding "show in notification" toggle enabled. Order:
 * location first, then IP — matching the order of the toggles in Settings.
 */
function connectionBody(prefix: string, serverName: string, details?: ConnectionDetails): string {
  const settings = useAppStore.getState().settings;
  let body = `${prefix} ${serverName || 'your VPN server'}`;
  const extras: string[] = [];
  if (settings?.showLocationInNotification && details?.location) extras.push(details.location);
  if (settings?.showIpInNotification && details?.ip) extras.push(details.ip);
  if (extras.length > 0) body += ` · ${extras.join(' · ')}`;
  return body;
}

export function notifyConnected(serverName: string, details?: ConnectionDetails): void {
  notify('BirdoVPN — Protected', connectionBody('via', serverName, details));
}

export function notifyReconnected(serverName: string, details?: ConnectionDetails): void {
  notify('BirdoVPN — Protected', connectionBody('Reconnected via', serverName, details));
}

export function notifyDisconnected(): void {
  notify('BirdoVPN — Not connected', 'Your connection is no longer protected.');
}

export function notifyConnectionLost(): void {
  notify('BirdoVPN — Reconnecting…', 'The connection dropped. BirdoVPN is restoring it.');
}

export function notifyConnectionError(message: string): void {
  notify('BirdoVPN — Connection error', message);
}

export function notifyKillSwitchActive(): void {
  notify(
    'BirdoVPN — Kill Switch — all traffic blocked',
    'Traffic is held until the VPN reconnects. Open BirdoVPN to disconnect.',
  );
}

/**
 * Which notification (if any) a state change deserves. Pure, so the rules are
 * testable without a store or a plugin: only transitions Rust REPORTED count,
 * and a Disconnect the user pressed (`userInitiated`) is not news to them.
 */
export type ConnectionNotification =
  | { kind: 'protected'; reconnected: boolean }
  | { kind: 'reconnecting' }
  | { kind: 'not_connected' }
  | { kind: 'error' }
  | { kind: 'blocking' };

export function connectionNotification(
  prev: { state: ConnectionState; blocking: boolean },
  next: { state: ConnectionState; blocking: boolean },
  userInitiated: boolean,
): ConnectionNotification | null {
  if (next.blocking && !prev.blocking) return { kind: 'blocking' };
  if (prev.state === next.state) return null;
  if (next.state === 'connected') {
    return { kind: 'protected', reconnected: prev.state === 'reconnecting' };
  }
  if (next.state === 'reconnecting' && prev.state === 'connected') return { kind: 'reconnecting' };
  if (
    next.state === 'error' &&
    (prev.state === 'connected' || prev.state === 'reconnecting' || prev.state === 'switching')
  ) {
    return { kind: 'error' };
  }
  if (next.state === 'disconnected' && prev.state === 'connected' && !userInitiated) {
    return { kind: 'not_connected' };
  }
  return null;
}

/**
 * Update-available notice from the daily background check. Deliberately NOT
 * gated on the connection-notifications preference: shipping security fixes
 * to a VPN client matters more than notification quiet, and it fires at most
 * once per app run.
 */
export function notifyUpdateAvailable(version: string): void {
  if (!permissionReady) return;
  try {
    sendNotification({
      title: 'BirdoVPN update available',
      body: `Version ${version} is ready — open Settings › About to install.`,
    });
  } catch (err) {
    console.error('Failed to send update notification:', err);
  }
}
