import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock the Tauri notification plugin BEFORE importing the module under test.
const sendNotification = vi.fn();
vi.mock('@tauri-apps/plugin-notification', () => ({
  isPermissionGranted: vi.fn().mockResolvedValue(true),
  requestPermission: vi.fn().mockResolvedValue('granted'),
  sendNotification: (...args: unknown[]) => sendNotification(...args),
}));

import {
  initNotifications,
  notifyConnected,
  notifyReconnected,
} from './notifications';
import { useAppStore } from '@/store/app-store';

function setNotificationSettings(opts: {
  notifications: boolean;
  showIp: boolean;
  showLocation: boolean;
}) {
  useAppStore.setState((s) => ({
    settings: {
      ...s.settings,
      notifications: opts.notifications,
      showIpInNotification: opts.showIp,
      showLocationInNotification: opts.showLocation,
    },
  }));
}

describe('notifications — detail toggles + gating', () => {
  beforeEach(async () => {
    sendNotification.mockClear();
    // Grant permission so notify() is allowed to send.
    await initNotifications();
  });

  it('sends a bare body when both detail toggles are off', () => {
    setNotificationSettings({ notifications: true, showIp: false, showLocation: false });
    notifyConnected('Frankfurt', { ip: '1.2.3.4', location: 'Frankfurt, DE' });
    expect(sendNotification).toHaveBeenCalledTimes(1);
    const body = sendNotification.mock.calls[0][0].body as string;
    expect(body).toBe('Secured via Frankfurt');
  });

  it('appends location then IP, in that order, when both toggles are on', () => {
    setNotificationSettings({ notifications: true, showIp: true, showLocation: true });
    notifyConnected('Frankfurt', { ip: '1.2.3.4', location: 'Frankfurt, DE' });
    const body = sendNotification.mock.calls[0][0].body as string;
    expect(body).toBe('Secured via Frankfurt · Frankfurt, DE · 1.2.3.4');
  });

  it('appends only the location when just that toggle is on', () => {
    setNotificationSettings({ notifications: true, showIp: false, showLocation: true });
    notifyConnected('Frankfurt', { ip: '1.2.3.4', location: 'Frankfurt, DE' });
    const body = sendNotification.mock.calls[0][0].body as string;
    expect(body).toBe('Secured via Frankfurt · Frankfurt, DE');
  });

  it('uses the reconnect prefix for notifyReconnected', () => {
    setNotificationSettings({ notifications: true, showIp: false, showLocation: false });
    notifyReconnected('Frankfurt');
    const body = sendNotification.mock.calls[0][0].body as string;
    expect(body).toBe('Back online via Frankfurt');
  });

  it('does not send anything when notifications are disabled', () => {
    setNotificationSettings({ notifications: false, showIp: true, showLocation: true });
    notifyConnected('Frankfurt', { ip: '1.2.3.4', location: 'Frankfurt, DE' });
    expect(sendNotification).not.toHaveBeenCalled();
  });
});
