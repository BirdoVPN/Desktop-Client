/**
 * Desktop Pricing screen (audit 2026-09-29: A-24 / A-34 / D-4).
 *
 * - No "Split tunneling" anywhere: the desktop app has no route-based split
 *   tunnelling, and the free card used to list it.
 * - Savings per plan (Operative 20%, Sovereign 17%) or "up to 20%", never a
 *   flat figure that overstates Sovereign.
 * - Prices unchanged: £3.99 / £38 and £9.99 / £99. No location counts.
 *
 * Run: npx vitest run src/__tests__/PricingScreen.test.tsx
 */
import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { Pricing } from '@/screens/Pricing';

vi.mock('@tauri-apps/plugin-shell', () => ({ open: vi.fn().mockResolvedValue(undefined) }));
vi.mock('zustand/react/shallow', () => ({ useShallow: (fn: unknown) => fn }));

const mockStoreState = {
  account: { plan: 'RECON' },
  popRoute: vi.fn(),
};
vi.mock('@/store/app-store', () => {
  const useAppStore = vi.fn((selector) => selector(mockStoreState));
  return { useAppStore };
});

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
});
