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
import { describe, it, expect, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DNS_DEGRADED_COPY, HomeBanners } from '@/components/home/HomeBanners';
import { useAppStore } from '@/store/app-store';

const RAW = 'Wi-Fi: Ethernet DNS 192.0.2.53 still set; SMHNR may race the tunnel';

beforeEach(() => {
  useAppStore.setState({
    isAdmin: true,
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
