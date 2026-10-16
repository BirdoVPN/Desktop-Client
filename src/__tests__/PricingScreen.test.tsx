/**
 * Desktop Pricing screen (audit 2026-09-29: A-24 / A-34 / D-4).
 *
 * - No "Split tunneling" anywhere: the desktop app has no route-based split
 *   tunnelling, and the free card used to list it.
 * - Savings per plan (Operative 20%, Sovereign 17%) or "up to 20%", never a
 *   flat figure that overstates Sovereign.
 * - Prices unchanged: £3.99 / £38 and £9.99 / £99. No location counts.
 * - MR-132 / MR-630 / MR-1767 / MR-1979: prices, savings and caps render from
 *   the server's `plans` (birdo-web #708); without it, or for a plan it left
 *   out, the fallback (the prices above, the free cap at 50 GB, not 10).
 *
 * Run: npx vitest run src/__tests__/PricingScreen.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Pricing } from '@/screens/Pricing';

vi.mock('@tauri-apps/plugin-opener', () => ({ openUrl: vi.fn().mockResolvedValue(undefined) }));
vi.mock('zustand/react/shallow', () => ({ useShallow: (fn: unknown) => fn }));

const mockStoreState = {
  account: { plan: 'RECON' },
  popRoute: vi.fn(),
  /** `GET /api/client-config` → `plans`, as `useClientConfig` stores it. */
  planPrices: {} as Record<string, unknown>,
  /** `features.<PLAN>`'s gating flags (MR-1517). */
  planGates: {} as Record<string, unknown>,
};
vi.mock('@/store/app-store', () => {
  const useAppStore = vi.fn((selector) => selector(mockStoreState));
  return { useAppStore };
});

beforeEach(() => {
  mockStoreState.planPrices = {};
  mockStoreState.planGates = {};
});

const plan = (monthlyPrice: number, yearlyPrice: number, currency: string, bandwidthLimitGb: number | null) => ({
  monthlyPrice,
  yearlyPrice,
  currency,
  bandwidthLimitGb,
});

const showMonthly = () => userEvent.click(screen.getByRole('button', { name: /^monthly$/i }));

describe('Pricing', () => {
  it('lists no split tunnelling on any card', () => {
    const { container } = render(<Pricing />);
    expect(container.textContent ?? '').not.toMatch(/split[- ]?tunnel/i);
  });

  it('shows per-plan yearly savings and "up to 20%" on the toggle', () => {
    const { container } = render(<Pricing />);
    const text = container.textContent ?? '';
    expect(screen.getByText('Save up to 20%')).toBeInTheDocument();
    expect(text).toContain('Save 20% vs paying monthly');
    expect(text).toContain('Save 17% vs paying monthly');
    expect(text).not.toMatch(/~2 months/);
    expect(text).toContain('£38');
    expect(text).toContain('£99');
  });

  it('keeps the monthly prices', async () => {
    render(<Pricing />);
    await userEvent.click(screen.getByRole('button', { name: /^monthly$/i }));
    expect(screen.getByText('£3.99')).toBeInTheDocument();
    expect(screen.getByText('£9.99')).toBeInTheDocument();
  });

  it('states the tax position and makes no location count claim', () => {
    const { container } = render(<Pricing />);
    const text = container.textContent ?? '';
    expect(text).toContain('Prices include VAT for customers in the UK, EU and most other countries');
    expect(text).not.toMatch(/\d+\s+(server\s+)?locations/i);
  });

  it('uses the mobile wording and sells no server tier that does not exist', () => {
    // Second-pass #16.
    const { container } = render(<Pricing />);
    const text = container.textContent ?? '';
    expect(text).toContain('Core server locations');
    expect(text).toContain('All server locations');
    expect(text).toContain('Stealth mode');
    expect(text).toContain('Multi-hop routing');
    expect(text).not.toMatch(/high-speed|priority servers|premium servers|maximum privacy/i);
    // Custom DNS is on every plan (owner decision D6): listed once, on the free
    // tier, which every paid card includes ("Everything in Recon"), and never
    // on a paid card as if it were an upgrade.
    expect(text.match(/custom dns/gi)).toHaveLength(1);
    expect(text.indexOf('Custom DNS servers')).toBeLessThan(text.indexOf('Everything in Recon'));
  });
});

describe('Pricing renders the server price feed (MR-132 / MR-630 / MR-1767 / MR-1979)', () => {
  it("shows the server's prices, savings and caps, not the built-in ones", async () => {
    mockStoreState.planPrices = {
      RECON: plan(0, 0, 'GBP', 75),
      OPERATIVE: plan(4.49, 45, 'GBP', null),
      SOVEREIGN: plan(10.99, 109, 'GBP', null),
    };
    const { container } = render(<Pricing />);
    const text = () => container.textContent ?? '';
    // Yearly (the default): the ANNUAL total as sent, with "/yr".
    expect(screen.getByText('£45')).toBeInTheDocument();
    expect(screen.getByText('£109')).toBeInTheDocument();
    // Floored from the server's numbers: 45 vs 53.88 = 16.5%, 109 vs 131.88 = 17.3%.
    expect(text()).toContain('Save 16% vs paying monthly');
    expect(text()).toContain('Save 17% vs paying monthly');
    expect(screen.getByText('Save up to 17%')).toBeInTheDocument();
    expect(text()).toContain('75 GB monthly bandwidth');
    expect(text()).not.toMatch(/£38|£99|\b50 GB|\b10 GB/);
    expect(screen.getByText('Free')).toBeInTheDocument();
    await showMonthly();
    expect(screen.getByText('£4.49')).toBeInTheDocument();
    expect(screen.getByText('£10.99')).toBeInTheDocument();
    expect(text()).not.toMatch(/£3\.99|£9\.99/);
  });

  it('a paid plan the server caps shows its cap instead of "Unlimited bandwidth"', () => {
    mockStoreState.planPrices = { OPERATIVE: plan(3.99, 38, 'GBP', 200) };
    const { container } = render(<Pricing />);
    const text = container.textContent ?? '';
    expect(text).toContain('200 GB monthly bandwidth');
    // MR-2030: Sovereign (the fallback, unlimited) says its own cap now; it
    // used to inherit Operative's 200 GB through "Everything in Operative".
    expect(text.indexOf('200 GB monthly bandwidth')).toBeLessThan(text.indexOf('Everything in Operative'));
    expect(text.indexOf('Everything in Operative')).toBeLessThan(text.indexOf('Unlimited bandwidth'));
    expect(text.match(/Unlimited bandwidth/g)).toHaveLength(1);
  });

  it('without `plans` (older server, offline, failed fetch) it shows the fallback, free cap 50 GB', async () => {
    const { container } = render(<Pricing />);
    const text = () => container.textContent ?? '';
    expect(text()).toContain('50 GB monthly bandwidth');
    expect(text()).not.toMatch(/\b10 ?GB/);
    expect(text()).toContain('Unlimited bandwidth');
    expect(screen.getByText('£38')).toBeInTheDocument();
    expect(screen.getByText('£99')).toBeInTheDocument();
    expect(screen.getByText('Save up to 20%')).toBeInTheDocument();
    expect(text()).toContain('Prices in GBP.');
    await showMonthly();
    expect(screen.getByText('£3.99')).toBeInTheDocument();
    expect(screen.getByText('£9.99')).toBeInTheDocument();
  });

  // MR-2030: the line under the title follows the plans' caps. It used to say
  // "unlimited bandwidth" whatever the server priced.
  it('the line under the title follows the caps', () => {
    const intro = () => screen.getByText(/^Upgrade for /).textContent;
    const { unmount } = render(<Pricing />);
    expect(intro()).toBe(
      'Upgrade for unlimited bandwidth, every server location and more devices. Billing is managed securely on the web.',
    );
    unmount();
    mockStoreState.planPrices = { OPERATIVE: plan(3.99, 38, 'GBP', 500), SOVEREIGN: plan(9.99, 99, 'GBP', 2000) };
    render(<Pricing />);
    expect(intro()).toBe(
      'Upgrade for more bandwidth, every server location and more devices. Billing is managed securely on the web.',
    );
  });

  // MR-2030: a paid plan priced 0 a month is not offered monthly: its card
  // shows the yearly price, never "£0" (unreachable today, guarded anyway).
  it('a paid plan with no monthly price never shows £0', async () => {
    mockStoreState.planPrices = { SOVEREIGN: plan(0, 99, 'GBP', null) };
    const { container } = render(<Pricing />);
    await showMonthly();
    const text = container.textContent ?? '';
    expect(text).not.toMatch(/£0(?![.\d])/);
    expect(screen.getByText('£99')).toBeInTheDocument();
    expect(screen.getByText('£3.99')).toBeInTheDocument();
    expect(text).toContain('Prices in GBP.');
  });

  // MR-1517: each gated feature is sold on the card of the lowest plan the
  // server's gating table gives it to. On main the cards were fixed: Stealth
  // on Operative, whatever the server said.
  it("sells each gated feature on the plan the server's gating table gives it to", () => {
    const { container, unmount } = render(<Pricing />);
    let text = container.textContent ?? '';
    // The built-in table, as before: Stealth on Operative, the rest on Sovereign.
    expect(text.indexOf('Stealth mode')).toBeLessThan(text.indexOf('Everything in Operative'));
    expect(text.indexOf('Everything in Operative')).toBeLessThan(text.indexOf('Multi-hop routing'));
    unmount();

    mockStoreState.planGates = {
      RECON: { stealthMode: false },
      OPERATIVE: { stealthMode: false, multiHop: false },
      SOVEREIGN: { stealthMode: true, multiHop: true, portForwarding: true },
    };
    text = render(<Pricing />).container.textContent ?? '';
    expect(text.match(/Stealth mode/g)).toHaveLength(1);
    expect(text.indexOf('Everything in Operative')).toBeLessThan(text.indexOf('Stealth mode'));
  });

  it('a partial `plans` uses the server for the plans it priced and the fallback for the rest', () => {
    mockStoreState.planPrices = { OPERATIVE: plan(4.99, 48, 'GBP', null) };
    const { container } = render(<Pricing />);
    const text = container.textContent ?? '';
    expect(screen.getByText('£48')).toBeInTheDocument(); // server
    expect(text).toContain('Save 19% vs paying monthly'); // 48 vs 59.88 = 19.8%
    expect(screen.getByText('£99')).toBeInTheDocument(); // fallback Sovereign
    expect(text).toContain('Save 17% vs paying monthly');
    expect(text).toContain('50 GB monthly bandwidth'); // fallback Recon
    expect(text).not.toContain('£38');
  });

  it('an entry that is not a valid price falls back for that plan alone', () => {
    mockStoreState.planPrices = {
      OPERATIVE: plan(Number.NaN, 38, 'GBP', null),
      SOVEREIGN: plan(9.99, 99, 'pounds', null),
      RECON: plan(0, 0, 'GBP', 0),
    };
    const { container } = render(<Pricing />);
    const text = container.textContent ?? '';
    expect(screen.getByText('£38')).toBeInTheDocument();
    expect(screen.getByText('£99')).toBeInTheDocument();
    expect(text).toContain('50 GB monthly bandwidth');
    expect(text).not.toMatch(/NaN|pounds|\b0 GB/);
  });

  it('formats a non-GBP currency with Intl.NumberFormat and says which currency', async () => {
    mockStoreState.planPrices = {
      RECON: plan(0, 0, 'EUR', 50),
      OPERATIVE: plan(4.49, 42, 'EUR', null),
      SOVEREIGN: plan(10.99, 99.5, 'EUR', null),
    };
    const { container } = render(<Pricing />);
    const text = () => container.textContent ?? '';
    expect(screen.getByText('€42')).toBeInTheDocument();
    // A fractional annual total keeps its pence; a whole one drops ".00".
    expect(screen.getByText('€99.50')).toBeInTheDocument();
    expect(text()).toContain('Prices in EUR.');
    expect(text()).not.toMatch(/£|GBP/);
    await showMonthly();
    expect(screen.getByText('€4.49')).toBeInTheDocument();
    expect(screen.getByText('€10.99')).toBeInTheDocument();
  });
});
