/**
 * Account API contract item 40 / owner decision D6: Custom DNS is on every
 * plan, and only an explicit `false` from the server's client-config for the
 * user's plan turns it off. When it does, the switch goes off in Rust as well
 * (a save with `custom_dns: null`, and a rebuild of a live tunnel), so the
 * Settings row never reads OFF over a tunnel still using the addresses.
 *
 * Against the real store; only `invoke` is mocked.
 *
 * Run: npx vitest run src/__tests__/CustomDnsGate.test.tsx
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderHook, waitFor, act } from '@testing-library/react';
import { invoke } from '@tauri-apps/api/core';
import { useCustomDnsGate } from '@/session/custom-dns-gate';
import { cancelScheduledReapply } from '@/session/settings-persist';
import { customDnsAvailable } from '@/lib/plan';
import { customDnsFlags } from '@/hooks/useClientConfig';
import { defaultSettings, useAppStore } from '@/store/app-store';

vi.mock('@tauri-apps/api/core');

const mockedInvoke = vi.mocked(invoke);
let saveFails = false;
const saves = () =>
  mockedInvoke.mock.calls
    .filter(([c]) => c === 'save_settings')
    .map(([, a]) => (a as { settings: Record<string, unknown> }).settings);

beforeEach(() => {
  saveFails = false;
  cancelScheduledReapply();
  mockedInvoke.mockReset();
  mockedInvoke.mockImplementation(async (cmd: string) => {
    if (cmd === 'save_settings' && saveFails) throw 'disk full';
    return undefined;
  });
  useAppStore.setState({
    settingsHydrated: true,
    connectionState: 'disconnected',
    notice: null,
    account: { ...useAppStore.getState().account, plan: 'RECON' },
    settings: { ...defaultSettings, customDnsEnabled: true, customDns: ['9.9.9.9'] },
    customDnsByPlan: {},
  });
});

afterEach(() => cancelScheduledReapply());

describe('customDnsAvailable / customDnsFlags', () => {
  it('only an explicit false for the known plan turns it off', () => {
    expect(customDnsAvailable('RECON', {})).toBe(true);
    expect(customDnsAvailable(null, { RECON: false })).toBe(true);
    expect(customDnsAvailable('recon', { RECON: false })).toBe(false);
    expect(customDnsAvailable('RECON', { RECON: true, SOVEREIGN: false })).toBe(true);
    // A plan this build does not know is NOT the free tier here.
    expect(customDnsAvailable('ENTERPRISE', { RECON: false })).toBe(true);
  });

  it('a server without the flag, and one sending true everywhere, both leave it on', () => {
    expect(customDnsFlags({ dnsFilteringAvailable: true })).toBeNull();
    expect(customDnsFlags({ features: { RECON: { customDns: null }, OPERATIVE: null } })).toEqual({});
    expect(
      customDnsFlags({
        features: { RECON: { customDns: true }, OPERATIVE: { customDns: true }, SOVEREIGN: { customDns: true } },
      }),
    ).toEqual({ RECON: true, OPERATIVE: true, SOVEREIGN: true });
    expect(customDnsFlags({ features: { recon: { customDns: false } } })).toEqual({ RECON: false });
    // An unknown plan's entry is ignored, never filed under another plan.
    expect(customDnsFlags({ features: { ENTERPRISE: { customDns: false }, RECON: { customDns: true } } })).toEqual({
      RECON: true,
    });
  });
});

describe('useCustomDnsGate', () => {
  it('does nothing while the plan has it (every plan, per D6)', async () => {
    useAppStore.setState({ customDnsByPlan: { RECON: true } });
    renderHook(() => useCustomDnsGate());
    await act(async () => {});
    expect(saves()).toHaveLength(0);
    expect(useAppStore.getState().settings.customDnsEnabled).toBe(true);
  });

  it('a false for the plan switches it off in Rust too, keeping the addresses', async () => {
    renderHook(() => useCustomDnsGate());
    act(() => useAppStore.setState({ customDnsByPlan: { RECON: false } }));
    await waitFor(() => expect(saves()).toHaveLength(1));
    expect(saves()[0].custom_dns).toBeNull();
    expect(useAppStore.getState().settings.customDnsEnabled).toBe(false);
    expect(useAppStore.getState().settings.customDns).toEqual(['9.9.9.9']);
  });

  it('waits for the saved settings to load before writing anything', async () => {
    useAppStore.setState({ settingsHydrated: false, customDnsByPlan: { RECON: false } });
    renderHook(() => useCustomDnsGate());
    await act(async () => {});
    expect(saves()).toHaveLength(0);
    act(() => useAppStore.setState({ settingsHydrated: true }));
    await waitFor(() => expect(saves()).toHaveLength(1));
  });

  it('a failed save is tried once, not in a loop', async () => {
    saveFails = true;
    renderHook(() => useCustomDnsGate());
    act(() => useAppStore.setState({ customDnsByPlan: { RECON: false } }));
    await waitFor(() => expect(saves()).toHaveLength(1));
    await waitFor(() => expect(useAppStore.getState().settings.customDnsEnabled).toBe(true));
    await act(async () => {});
    expect(saves()).toHaveLength(1);
  });
});
