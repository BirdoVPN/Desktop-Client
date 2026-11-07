/**
 * The DNS banner (live run on the owner's PC, WIN-FIX-1): it showed Rust's
 * raw line ("… SMHNR may race the tunnel") as its message. Rust's entries are
 * free text, so the banner now says one human sentence and keeps the entries
 * behind Details.
 *
 * Against the real store.
 *
 * Run: npx vitest run src/__tests__/HomeBanners.test.tsx
 */
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DNS_DEGRADED_COPY, HomeBanners } from '@/components/home/HomeBanners';
import { KILLSWITCH_HOLDING_COPY } from '@/lib/errors';
import type { IpcError } from '@/lib/ipc';
import { useAppStore } from '@/store/app-store';

const RAW = 'Wi-Fi: Ethernet DNS 192.0.2.53 still set; SMHNR may race the tunnel';

beforeEach(() => {
  useAppStore.setState({
    isAdmin: true,
    connectionState: 'disconnected',
    dnsDegraded: [],
    giveUp: null,
    vpnError: null,
    commandError: null,
    killSwitchBlocking: false,
  });
});

describe('the DNS banner', () => {
  it('says one human sentence, never a raw Rust line', () => {
    useAppStore.setState({ dnsDegraded: [RAW] });
    render(<HomeBanners onAction={() => {}} />);
    expect(screen.getByText(DNS_DEGRADED_COPY)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('SMHNR');
    expect(document.body.textContent).not.toContain('192.0.2.53');
  });

  it("keeps Rust's lines behind Details, every one of them", async () => {
    useAppStore.setState({
      dnsDegraded: [RAW, "The VPN's DNS servers could not be set, so websites may not load"],
    });
    render(<HomeBanners onAction={() => {}} />);
    const details = screen.getByRole('button', { name: 'Details' });
    expect(details).toHaveAttribute('aria-expanded', 'false');

    await userEvent.click(details);
    expect(screen.getByRole('button', { name: 'Hide details' })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByText(RAW)).toBeInTheDocument();
    expect(screen.getByText("The VPN's DNS servers could not be set, so websites may not load")).toBeInTheDocument();
    // Still one sentence for the banner itself, however many lines.
    expect(screen.getAllByText(DNS_DEGRADED_COPY)).toHaveLength(1);

    await userEvent.click(screen.getByRole('button', { name: 'Hide details' }));
    expect(document.body.textContent).not.toContain('SMHNR');
  });

  it('is absent when Rust reports nothing', () => {
    render(<HomeBanners onAction={() => {}} />);
    expect(screen.queryByText(DNS_DEGRADED_COPY)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Details' })).not.toBeInTheDocument();
  });
});

/**
 * MR-2111: a failed connect kept its tunnel in place of the block the kill
 * switch could not put up (Desktop #313): `error`, `killswitch_failed`, and
 * `kill_switch_blocking`. The banner offered Try again, which repeats the same
 * failure, and never said that traffic is held or how to release it.
 */
describe('the kill-switch error while traffic is held', () => {
  // `session::kept_tunnel_error` as Rust sends it.
  const KEPT: IpcError = {
    code: 'killswitch_failed',
    message:
      'The kill switch could not block traffic, so the old tunnel is kept in place and nothing leaves ' +
      'outside it. Disconnect to release it.',
    retryable: true,
    retry_after_secs: null,
  };

  it('says traffic is held and offers Disconnect, never Try again', async () => {
    useAppStore.setState({ connectionState: 'error', vpnError: KEPT, killSwitchBlocking: true });
    const onAction = vi.fn();
    render(<HomeBanners onAction={onAction} />);

    expect(screen.getByText(KILLSWITCH_HOLDING_COPY)).toBeInTheDocument();
    expect(KILLSWITCH_HOLDING_COPY).toMatch(/traffic is held/);
    expect(screen.queryByRole('button', { name: 'Try again' })).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/Try again/);

    await userEvent.click(screen.getByRole('button', { name: 'Disconnect' }));
    expect(onAction).toHaveBeenCalledTimes(1);
    expect(onAction).toHaveBeenCalledWith('disconnect');
  });

  it('keeps Try again for a kill-switch failure that holds nothing', () => {
    useAppStore.setState({ connectionState: 'error', vpnError: KEPT, killSwitchBlocking: false });
    render(<HomeBanners onAction={() => {}} />);
    expect(screen.queryByText(KILLSWITCH_HOLDING_COPY)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Disconnect' })).not.toBeInTheDocument();
  });
});
