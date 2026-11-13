/**
 * BirdoShield row with the fleet gate UNKNOWN, through the REAL store (review
 * of #433).
 *
 * `BirdoShieldToggle.test.tsx` stubs the store module, so its "unknown hides"
 * case sets `undefined` by hand and would pass whatever the store starts at.
 * This file renders the real screen against the real store, and the first test
 * reads the gate before anything in this file has written it: a store that
 * started at `true` (the old default) renders the row and fails here.
 *
 * Owner 2026-11-13: the row exists only while the gate is known to be on.
 *
 * Run: npx vitest run src/__tests__/BirdoShieldGateDefault.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { act, render, screen } from '@testing-library/react';
import { invoke } from '@tauri-apps/api/core';
import { VpnSettings } from '@/screens/VpnSettings';
import { defaultSettings, useAppStore } from '@/store/app-store';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/plugin-opener', () => ({ openUrl: vi.fn().mockResolvedValue(undefined) }));
vi.mock('@tauri-apps/plugin-process', () => ({ relaunch: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));

const mockedInvoke = vi.mocked(invoke);

// Read at import, before any test (or beforeEach) in this file runs: the
// store's own initial value, not one a test wrote.
const gateAtStart = useAppStore.getState().dnsFilteringAvailable;

beforeEach(() => {
  mockedInvoke.mockReset();
  mockedInvoke.mockResolvedValue(undefined);
});

describe('BirdoShield row with the real store default', () => {
  it('the store starts the gate unknown', () => {
    expect(gateAtStart).toBeUndefined();
  });

  it('unknown hides the row, even with BirdoShield saved ON, and clears nothing', async () => {
    // Only the preference is set; the gate is left at the store default.
    useAppStore.setState({ settings: { ...defaultSettings, dnsFiltering: true } });
    expect(useAppStore.getState().dnsFilteringAvailable).toBeUndefined();

    render(<VpnSettings />);

    // The screen is there (a neighbour row renders), the BirdoShield row is not.
    expect(await screen.findByRole('switch', { name: /local network sharing/i })).toBeInTheDocument();
    expect(screen.queryByRole('switch', { name: /birdoshield/i })).not.toBeInTheDocument();
    expect(screen.queryByText('BirdoShield')).not.toBeInTheDocument();
    expect(useAppStore.getState().settings.dnsFiltering).toBe(true);
  });

  it('the row appears once the config fetch says the gate is on', async () => {
    render(<VpnSettings />);
    expect(await screen.findByRole('switch', { name: /local network sharing/i })).toBeInTheDocument();
    expect(screen.queryByRole('switch', { name: /birdoshield/i })).not.toBeInTheDocument();

    act(() => useAppStore.getState().setDnsFilteringAvailable(true));

    expect(await screen.findByRole('switch', { name: /birdoshield/i })).toBeInTheDocument();
  });
});
