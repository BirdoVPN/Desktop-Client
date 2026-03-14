/**
 * Native notification utility for Birdo VPN
 *
 * Sends Windows toast notifications for VPN connection events,
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
  if (!useAppStore.getState().settings.notifications) return;

  try {
    sendNotification({ title, body });
  } catch {
    // Silently ignore notification failures
  }
}

export function notifyConnected(serverName: string): void {
  notify('VPN Connected', `Secured via ${serverName}`);
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

export function notifyReconnected(serverName: string): void {
  notify('VPN Reconnected', `Back online via ${serverName}`);
}
