/**
 * Dialogs are modal (W2-017) and Escape goes back (W2-033).
 *
 * None of the hand-rolled dialogs moved focus in, trapped Tab or gave focus
 * back; the Home dialogs had no Escape and no aria-modal; the page behind every
 * modal stayed focusable. These drive the shared BirdoDialog and the shell.
 *
 * Run: npx vitest run src/__tests__/ModalFocus.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { useState } from 'react';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { BirdoDialog } from '@/components/birdo';
import { AppShell } from '@/components/AppShell';
import { useAppStore } from '@/store/app-store';
import { isModalOpen } from '@/lib/modal';
import { invoke } from '@tauri-apps/api/core';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));

// Plain elements instead of animated ones, so mount/unmount is immediate.
function stripMotion(props: Record<string, unknown>) {
  const { initial: _i, animate: _a, exit: _e, transition: _t, whileHover: _h, whileTap: _p, ...rest } = props;
  return rest;
}
vi.mock('framer-motion', () => ({
  motion: {
    div: ({ children, ...props }: React.PropsWithChildren<Record<string, unknown>>) => (
      <div {...(stripMotion(props) as React.HTMLAttributes<HTMLDivElement>)}>{children}</div>
    ),
    button: ({ children, ...props }: React.PropsWithChildren<Record<string, unknown>>) => (
      <button {...(stripMotion(props) as React.ButtonHTMLAttributes<HTMLButtonElement>)}>{children}</button>
    ),
  },
  AnimatePresence: ({ children }: React.PropsWithChildren) => <>{children}</>,
  MotionConfig: ({ children }: React.PropsWithChildren) => <>{children}</>,
}));

// The shell's screens are stand-ins: this file is about the shell's keyboard.
vi.mock('@/components/Dashboard', () => ({ Dashboard: () => <button type="button">tab content</button> }));
vi.mock('@/screens/Profile', () => ({ Profile: () => <div /> }));
vi.mock('@/screens/Limit', () => ({ Limit: () => <div /> }));
vi.mock('@/components/Settings', () => ({ Settings: () => <div /> }));
vi.mock('@/screens/VpnSettings', () => ({ VpnSettings: () => <div data-testid="pushed">pushed</div> }));
vi.mock('@/screens/SplitTunnel', () => ({ SplitTunnel: () => <div /> }));
vi.mock('@/screens/PortForward', () => ({ PortForward: () => <div /> }));
vi.mock('@/screens/Pricing', () => ({ Pricing: () => <div /> }));
vi.mock('@/components/PixelCanvas', () => ({ PixelCanvas: () => <canvas /> }));

function Harness({ busy = false }: { busy?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <div>
      <button type="button" onClick={() => setOpen(true)}>
        Open
      </button>
      <button type="button">Behind</button>
      <BirdoDialog open={open} onClose={() => setOpen(false)} title="Confirm thing" busy={busy}>
        <button type="button">First</button>
        <button type="button">Last</button>
      </BirdoDialog>
    </div>
  );
}

describe('BirdoDialog', () => {
  it('is a labelled modal dialog that takes focus on open', async () => {
    render(<Harness />);
    await userEvent.click(screen.getByRole('button', { name: 'Open' }));
    const dialog = screen.getByRole('dialog', { name: 'Confirm thing' });
    expect(dialog).toHaveAttribute('aria-modal', 'true');
    expect(screen.getByRole('button', { name: 'First' })).toHaveFocus();
    expect(isModalOpen()).toBe(true);
  });

  it('traps Tab and Shift+Tab inside', async () => {
    render(<Harness />);
    await userEvent.click(screen.getByRole('button', { name: 'Open' }));
    await userEvent.tab();
    expect(screen.getByRole('button', { name: 'Last' })).toHaveFocus();
    await userEvent.tab();
    expect(screen.getByRole('button', { name: 'First' })).toHaveFocus();
    await userEvent.tab({ shift: true });
    expect(screen.getByRole('button', { name: 'Last' })).toHaveFocus();
  });

  it('makes the page behind it inert, and undoes that on close', async () => {
    render(<Harness />);
    const behind = screen.getByRole('button', { name: 'Behind' });
    await userEvent.click(screen.getByRole('button', { name: 'Open' }));
    expect(behind.closest('[inert]')).not.toBeNull();
    await userEvent.keyboard('{Escape}');
    expect(behind.closest('[inert]')).toBeNull();
  });

  it('Escape closes it and focus returns to the control that opened it', async () => {
    render(<Harness />);
    const opener = screen.getByRole('button', { name: 'Open' });
    await userEvent.click(opener);
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(opener).toHaveFocus();
    expect(isModalOpen()).toBe(false);
  });

  it('a busy dialog ignores Escape (a request is in flight)', async () => {
    render(<Harness busy />);
    await userEvent.click(screen.getByRole('button', { name: 'Open' }));
    await userEvent.keyboard('{Escape}');
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });
});

describe('AppShell keyboard', () => {
  beforeEach(() => {
    vi.mocked(invoke).mockResolvedValue(undefined);
    useAppStore.setState({ tab: 'home', navStack: [], deepLinkConfirm: null });
  });

  it('Escape pops a pushed screen, and the tab beneath is inert while it is up', async () => {
    useAppStore.setState({ tab: 'settings', navStack: ['vpnSettings'] });
    render(<AppShell />);
    expect(screen.getByTestId('pushed')).toBeInTheDocument();
    await userEvent.keyboard('{Escape}');
    await waitFor(() => expect(useAppStore.getState().navStack).toEqual([]));
  });

  it('the tab root is inert under a pushed screen', () => {
    useAppStore.setState({ tab: 'home', navStack: ['vpnSettings'] });
    render(<AppShell />);
    expect(screen.getByRole('button', { name: 'tab content', hidden: true }).closest('[inert]')).not.toBeNull();
  });

  it('Escape in an open dialog closes the dialog only, not the screen under it', async () => {
    useAppStore.setState({ tab: 'settings', navStack: ['vpnSettings'] });
    render(
      <>
        <AppShell />
        <Harness />
      </>,
    );
    await userEvent.click(screen.getByRole('button', { name: 'Open' }));
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(useAppStore.getState().navStack).toEqual(['vpnSettings']);
  });

  it('the bottom nav is a tablist with the canonical four tabs, arrow keys move (P1-parity-009)', async () => {
    render(<AppShell />);
    const tabs = screen.getAllByRole('tab').map((t) => t.textContent);
    expect(tabs).toEqual(['Profile', 'Connect', 'Limit', 'Settings']);
    screen.getByRole('tab', { name: 'Connect' }).focus();
    await userEvent.keyboard('{ArrowRight}');
    expect(useAppStore.getState().tab).toBe('limit');
    expect(screen.getByRole('tab', { name: 'Limit' })).toHaveFocus();
  });
});
