/**
 * Native notification utility for Birdo VPN
 *
 * Sends native desktop notifications for VPN connection events,
 * gated behind the user's notification preference.
 */

import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from '@tauri-apps/plugin-notification';
import { useAppStore } from '@/store/app-store';

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
  let body = `${prefix} ${serverName || 'VPN Server'}`;
  const extras: string[] = [];
  if (settings?.showLocationInNotification && details?.location) extras.push(details.location);
  if (settings?.showIpInNotification && details?.ip) extras.push(details.ip);
  if (extras.length > 0) body += ` · ${extras.join(' · ')}`;
  return body;
}

export function notifyConnected(serverName: string, details?: ConnectionDetails): void {
  notify('VPN Connected', connectionBody('Secured via', serverName, details));
}

export function notifyDisconnected(): void {
  notify('VPN Disconnected', 'Your connection is no longer protected');
}

export function notifyConnectionLost(): void {
  notify('Connection Lost', 'Attempting to reconnect...');
}

export function notifyKillSwitchActive(): void {
  notify('Kill Switch Active', 'Internet traffic is blocked for your protection');
}

export function notifyReconnected(serverName: string, details?: ConnectionDetails): void {
  notify('VPN Reconnected', connectionBody('Back online via', serverName, details));
}
