/**
 * Consent screen copy and controls (audit 2026-09-29: P0-1, B-1, B-3, B-13,
 * C-3, D-1). The text is fixed by REMEDIATION-DECISIONS.md §1.5; these tests
 * pin what it must say and, just as much, what it must never say again.
 *
 * Run: npx vitest run src/__tests__/ConsentScreen.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { open as openExternal } from '@tauri-apps/plugin-shell';
import { ConsentScreen, CONSENT_COPY, TERMS_URL, PRIVACY_URL } from '@/components/ConsentScreen';

vi.mock('@tauri-apps/plugin-shell', () => ({
  open: vi.fn().mockResolvedValue(undefined),
}));

function stripMotion(props: Record<string, unknown>) {
  const {
    initial: _i,
    animate: _a,
    exit: _e,
    transition: _t,
    whileHover: _h,
    whileTap: _p,
    ...rest
  } = props;
  return rest;
}
type MotionProps = React.PropsWithChildren<Record<string, unknown>>;
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: MotionProps) => (
      <div {...(stripMotion(props) as React.HTMLAttributes<HTMLDivElement>)}>{children}</div>
    ),
    button: ({ children, ...props }: MotionProps) => (
      <button {...(stripMotion(props) as React.ButtonHTMLAttributes<HTMLButtonElement>)}>
        {children}
      </button>
    ),
    p: ({ children, ...props }: MotionProps) => (
      <p {...(stripMotion(props) as React.HTMLAttributes<HTMLParagraphElement>)}>{children}</p>
    ),
    h1: ({ children, ...props }: MotionProps) => (
      <h1 {...(stripMotion(props) as React.HTMLAttributes<HTMLHeadingElement>)}>{children}</h1>
    ),
  },
  AnimatePresence: ({ children }: React.PropsWithChildren) => <>{children}</>,
}));

const onAccept = vi.fn();
const onDecline = vi.fn();

beforeEach(() => {
  onAccept.mockReset();
  onDecline.mockReset();
  vi.mocked(openExternal).mockClear();
});

describe('ConsentScreen copy', () => {
  it('states the decided privacy model verbatim', () => {
    render(<ConsentScreen onAccept={onAccept} onDecline={onDecline} />);
    expect(screen.getByText(CONSENT_COPY.noActivityLogs)).toBeInTheDocument();
    expect(screen.getByText(CONSENT_COPY.accountHolds)).toBeInTheDocument();
    expect(screen.getByText(CONSENT_COPY.crashReports)).toBeInTheDocument();
    expect(CONSENT_COPY.noActivityLogs).toContain('keeps a live record of your session');
    // Second-pass #7: the app sends error events as well as crashes.
    expect(CONSENT_COPY.crashReports).toContain('crash and error reports');
    expect(CONSENT_COPY.crashReports).not.toMatch(/crash details|\bonly\b/i);
    // Second-pass #2: the nightly dump leaves it out; the 7-day PITR copy can hold it.
    expect(CONSENT_COPY.noActivityLogs).toContain('is left out of our nightly backups');
  });

  it('never repeats a withdrawn claim', () => {
    const { container } = render(<ConsentScreen onAccept={onAccept} onDecline={onDecline} />);
    const text = container.textContent ?? '';
    for (const banned of [
      /RAM-only/i,
      /volatile/i,
      /diskless/i,
      /zero[- ]logs?/i,
      /no personal data/i,
      /non-reversible/i,
      /IP addresses are logged/i,
      /connection timestamps/i,
      /never included in backups/i,
      /never in backups/i,
      /not in any backup/i,
    ]) {
      expect(text).not.toMatch(banned);
    }
  });

  it('states the age requirement and that continuing accepts both documents', () => {
    render(<ConsentScreen onAccept={onAccept} onDecline={onDecline} />);
    expect(screen.getByText(/You must be 18 or over to use BirdoVPN/)).toBeInTheDocument();
    expect(
      screen.getByText(/you accept the Terms of Service and the Privacy Policy/),
    ).toBeInTheDocument();
  });
});

describe('ConsentScreen controls', () => {
  it('links both the Terms of Service and the Privacy Policy in the system browser', async () => {
    render(<ConsentScreen onAccept={onAccept} onDecline={onDecline} />);
    await userEvent.click(screen.getByRole('button', { name: /terms of service/i }));
    await userEvent.click(screen.getByRole('button', { name: /privacy policy/i }));
    expect(openExternal).toHaveBeenCalledWith(TERMS_URL);
    expect(openExternal).toHaveBeenCalledWith(PRIVACY_URL);
    expect(TERMS_URL).toBe('https://birdo.app/terms');
    expect(PRIVACY_URL).toBe('https://birdo.app/privacy');
  });

  it('crash reports start OFF: accepting without touching the toggle opts out', async () => {
    render(<ConsentScreen onAccept={onAccept} onDecline={onDecline} />);
    const toggle = screen.getByRole('switch', { name: /send crash reports/i });
    expect(toggle).toHaveAttribute('aria-checked', 'false');
    await userEvent.click(screen.getByRole('button', { name: /i agree & continue/i }));
    expect(onAccept).toHaveBeenCalledWith(false);
  });

  it('passes an explicit opt-in through', async () => {
    render(<ConsentScreen onAccept={onAccept} onDecline={onDecline} />);
    await userEvent.click(screen.getByRole('switch', { name: /send crash reports/i }));
    await userEvent.click(screen.getByRole('button', { name: /i agree & continue/i }));
    expect(onAccept).toHaveBeenCalledWith(true);
  });

  it('Decline declines', async () => {
    render(<ConsentScreen onAccept={onAccept} onDecline={onDecline} />);
    await userEvent.click(screen.getByRole('button', { name: /^decline$/i }));
    expect(onDecline).toHaveBeenCalled();
    expect(onAccept).not.toHaveBeenCalled();
  });
});
