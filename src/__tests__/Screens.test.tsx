/**
 * Loading, empty and error states per screen, and the canonical wording.
 *
 *  - Limit tab (P1-parity-009): loading, error + Retry, unlimited, capped,
 *    near-cap, never synced — Profile's old card rendered nothing for most;
 *    and (owner 2026-10-21) mobile's layout with the speed-dial gauge.
 *  - Profile (W2-011, P1-parity-033): an unknown plan is not "Free plan";
 *    the connection status row; "MMM d, yyyy" dates; canonical chips.
 *  - Port Forwarding (W2-030): a failed load is not "No rules yet".
 *  - Kill Switch Exceptions (W2-043): the banner does not claim exceptions
 *    are active while the feature is off.
 *  - Offline banner (P1-parity-029), the update wall's Disconnect (W2-025),
 *    the updater surviving a remount (W2-024), Pricing (W2-042).
 *  - An update download held by the kill switch (MR-1824): it waits, says
 *    why, starts by itself only once nothing is active, and is offered again
 *    (never installed unattended) once the tunnel is up.
 *
 * Run: npx vitest run src/__tests__/Screens.test.tsx
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, act, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { Limit } from '@/screens/Limit';
import { Profile } from '@/screens/Profile';
import { PortForward } from '@/screens/PortForward';
import { SplitTunnel } from '@/screens/SplitTunnel';
import { Pricing } from '@/screens/Pricing';
import { OfflineBanner } from '@/components/OfflineBanner';
import { UpdateRequired } from '@/components/UpdateRequired';
import { UpdateChecker } from '@/components/UpdateChecker';
import { defaultSettings, useAppStore } from '@/store/app-store';
import {
  cancelUpdateWait,
  heldUpdateStep,
  installUpdate,
  resetUpdater,
  UPDATE_DOWNLOAD_FAILED_COPY,
  UPDATE_INSTALL_FAILED_COPY,
  UPDATE_WAITING_COPY,
  useUpdater,
} from '@/session/updater';
import { resetSessionData } from '@/session/session-data';

vi.mock('@tauri-apps/api/core');
vi.mock('@tauri-apps/plugin-opener', () => ({ openUrl: vi.fn().mockResolvedValue(undefined) }));
vi.mock('@tauri-apps/plugin-process', () => ({ relaunch: vi.fn(), exit: vi.fn() }));
vi.mock('@tauri-apps/plugin-dialog', () => ({ open: vi.fn() }));
vi.mock('@tauri-apps/api/event', () => ({ listen: vi.fn(async () => () => {}) }));

const mockedInvoke = vi.mocked(invoke);
const callsTo = (cmd: string) => mockedInvoke.mock.calls.filter(([c]) => c === cmd);

beforeEach(() => {
  mockedInvoke.mockReset();
  mockedInvoke.mockResolvedValue(undefined);
  resetUpdater();
  resetSessionData();
  useAppStore.getState().logout();
  useAppStore.setState({ isAuthenticated: true, settings: { ...defaultSettings } });
});

describe('Limit tab', () => {
  // The plan table is not an account field, so logout() leaves it: reset it
  // here, once the screen is gone (a reset under a mounted screen re-renders it).
  afterEach(() => {
    cleanup();
    useAppStore.setState({ planPrices: {} });
  });

  const usage = (fields: Record<string, unknown>) => {
    mockedInvoke.mockImplementation(async (cmd: string) =>
      cmd === 'get_usage_stats'
        ? { plan: 'RECON', bandwidthLimitGb: 10, bandwidthUsedGb: 4, bandwidthPeriodEnd: '2026-10-31T23:59:59Z',
            bandwidthLastSyncAt: new Date().toISOString(), bandwidthIsFresh: true, ...fields }
        : undefined,
    );
  };

  it('says it is loading, instead of rendering nothing', () => {
    mockedInvoke.mockImplementation(() => new Promise(() => {}));
    render(<Limit />);
    expect(screen.getByText('Loading your usage…')).toBeInTheDocument();
  });

  it('a failed load says so and Retry asks again', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'get_usage_stats') throw 'offline';
      return undefined;
    });
    render(<Limit />);
    expect(await screen.findByText("Couldn't load your usage.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(callsTo('get_usage_stats')).toHaveLength(2));
  });

  it('an uncapped plan reads "Unlimited data"', async () => {
    usage({ bandwidthLimitGb: 0, plan: 'SOVEREIGN' });
    render(<Limit />);
    expect(await screen.findByText('Unlimited data')).toBeInTheDocument();
    expect(screen.getByText('Your plan has no data cap — use as much as you like.')).toBeInTheDocument();
  });

  it('a capped plan shows the gauge, the freshness line, Refresh, and the upgrade card', async () => {
    usage({});
    render(<Limit />);
    const meter = await screen.findByRole('meter', { name: 'Data used this month' });
    expect(meter).toHaveAttribute('aria-valuenow', '40');
    expect(meter).toHaveAttribute('aria-valuetext', '4.0 of 10 GB used, 40%');
    expect(screen.getByText('Updated just now')).toBeInTheDocument();
    expect(screen.getByText('Need more data?')).toBeInTheDocument();
    await userEvent.click(await screen.findByRole('button', { name: 'Refresh usage' }));
    await waitFor(() => expect(callsTo('get_usage_stats')).toHaveLength(2));
    await userEvent.click(screen.getByRole('button', { name: 'Upgrade for unlimited' }));
    expect(useAppStore.getState().navStack).toEqual(['pricing']);
  });

  // Owner 2026-10-21: the Limit tab as on mobile (Android LimitScreen.kt /
  // iOS LimitView.swift), with the speed-dial gauge.
  it('is laid out as mobile: plan header, speed-dial gauge, stat cells, upgrade card', async () => {
    usage({ bandwidthLimitGb: 50, bandwidthUsedGb: 12.4 });
    const { container } = render(<Limit />);
    const meter = await screen.findByRole('meter', { name: 'Data used this month' });
    // The dial: a 270° track, the used share dashed onto the same arc, the
    // knob a one-dot dash at the reading, the figure in the centre, % in the gap.
    const track = container.querySelector('.birdo-gauge__track') as SVGPathElement;
    const fill = container.querySelector('.birdo-gauge__fill') as SVGPathElement;
    expect(track.getAttribute('stroke-width')).toBe('18');
    expect(fill.getAttribute('d')).toBe(track.getAttribute('d'));
    expect(fill.getAttribute('pathLength')).toBe('1');
    expect(fill.getAttribute('stroke-dasharray')).toBe('1 2');
    expect(Number(fill.style.strokeDashoffset)).toBeCloseTo(1 - 12.4 / 50, 6);
    const knob = [...container.querySelectorAll('.birdo-gauge__knob')] as SVGPathElement[];
    expect(knob.map((k) => k.getAttribute('stroke-width'))).toEqual(['26', '11']);
    for (const k of knob) {
      expect(k.getAttribute('d')).toBe(track.getAttribute('d'));
      expect(k.getAttribute('stroke-dasharray')).toBe('0 2');
      expect(Number(k.style.strokeDashoffset)).toBeCloseTo(-12.4 / 50, 6);
    }
    expect(meter).toHaveTextContent('12');
    expect(meter).toHaveTextContent('of 50 GB used');
    expect(meter).toHaveTextContent('25%');
    // Plan header and the pill.
    expect(screen.getByRole('heading', { name: 'Your plan' })).toBeInTheDocument();
    expect(screen.getByText('Free plan')).toBeInTheDocument();
    expect(screen.getByText('50 GB / month')).toBeInTheDocument();
    // Used / Left / Resets.
    expect(screen.getByText('12 GB')).toBeInTheDocument();
    expect(screen.getByText('38 GB')).toBeInTheDocument();
    expect(screen.getByText('Oct 31')).toBeInTheDocument();
    expect(screen.getByText('Counts uploads and downloads · Updates about every minute')).toBeInTheDocument();
    // Mobile's upgrade copy, while the server's plan table says Operative is uncapped.
    expect(
      screen.getByText(
        'Free accounts include 50 GB per month. Upgrade to Operative for unlimited data on every server.',
      ),
    ).toBeInTheDocument();
  });

  it('does not promise unlimited data when no paid plan is uncapped (MR-2030)', async () => {
    useAppStore.setState({
      planPrices: {
        OPERATIVE: { monthlyPrice: 3.99, yearlyPrice: 38, currency: 'GBP', bandwidthLimitGb: 500 },
        SOVEREIGN: { monthlyPrice: 9.99, yearlyPrice: 99, currency: 'GBP', bandwidthLimitGb: 2000 },
      },
    });
    usage({});
    render(<Limit />);
    expect(await screen.findByText('Free accounts include 10 GB per month. Paid plans include more data.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'View plans' })).toBeInTheDocument();
    expect(screen.queryByText(/unlimited/i)).not.toBeInTheDocument();
  });

  it('Refresh says it is updating while the request is out', async () => {
    usage({});
    render(<Limit />);
    const refresh = await screen.findByRole('button', { name: 'Refresh usage' });
    const reading = await mockedInvoke('get_usage_stats');
    let release: (v: unknown) => void = () => {};
    mockedInvoke.mockImplementation(() => new Promise((r) => { release = r; }));
    await userEvent.click(refresh);
    expect(screen.getByRole('button', { name: 'Updating…' })).toBeDisabled();
    await act(async () => release(reading));
    expect(await screen.findByRole('button', { name: 'Refresh usage' })).toBeEnabled();
  });

  it('warns before the cap', async () => {
    usage({ bandwidthUsedGb: 9.6 });
    render(<Limit />);
    expect(await screen.findByText("You're almost out of data")).toBeInTheDocument();
  });

  it('over the cap: the gauge is full and red, and nothing is left', async () => {
    usage({ bandwidthLimitGb: 50, bandwidthUsedGb: 63.4 });
    const { container } = render(<Limit />);
    const meter = await screen.findByRole('meter', { name: 'Data used this month' });
    expect(meter).toHaveAttribute('aria-valuenow', '100');
    expect(meter).toHaveTextContent('100%');
    expect((container.querySelector('.birdo-gauge__fill') as SVGPathElement).getAttribute('stroke')).toBe('#F87171');
    expect(screen.getByText('0.0 GB')).toBeInTheDocument();
    expect(screen.getByText("You're almost out of data")).toBeInTheDocument();
  });

  it('a held reading stays up when a refresh fails, with the reason above it', async () => {
    usage({});
    render(<Limit />);
    await screen.findByRole('meter', { name: 'Data used this month' });
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'get_usage_stats') throw 'offline';
      return undefined;
    });
    await userEvent.click(await screen.findByRole('button', { name: 'Refresh usage' }));
    expect(await screen.findByRole('alert')).toHaveTextContent("Couldn't refresh your usage. Showing the last reading.");
    expect(screen.getByRole('meter', { name: 'Data used this month' })).toHaveAttribute('aria-valuenow', '40');
  });

  it('a never-synced node says so rather than showing a frozen 0', async () => {
    usage({ bandwidthUsedGb: 0, bandwidthLastSyncAt: null, bandwidthIsFresh: false });
    render(<Limit />);
    expect(await screen.findByText('Awaiting first sync — connect to start counting')).toBeInTheDocument();
  });
});

describe('Profile', () => {
  it('an unknown plan is "Loading your plan…", never "Free plan", and a failure offers Retry (W2-011)', async () => {
    useAppStore.setState({ planStatus: 'error', account: { ...useAppStore.getState().account, plan: null } });
    render(<Profile />);
    expect(screen.queryByText('Free plan')).not.toBeInTheDocument();
    expect(screen.queryByText('0 devices')).not.toBeInTheDocument();
    expect(screen.getByText("Couldn't load your plan.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    await waitFor(() => expect(callsTo('get_subscription_status')).toHaveLength(1));
  });

  it('shows the connection status row and canonical dates and chips (P1-parity-033)', () => {
    useAppStore.setState({
      planStatus: 'ready',
      connectionState: 'connected',
      liveServerName: 'Frankfurt #1',
      account: {
        ...useAppStore.getState().account,
        email: 'me@example.com',
        plan: 'SOVEREIGN',
        status: 'active',
        expiresAt: '2026-11-03',
        maxDevices: 10,
        bandwidthLimit: 0,
      },
    });
    render(<Profile />);
    expect(screen.getByText('Protected')).toBeInTheDocument();
    expect(screen.getByText('Connected · Frankfurt #1')).toBeInTheDocument();
    expect(screen.getByText('Renews Nov 3, 2026')).toBeInTheDocument();
    for (const chip of ['10 devices', 'Unlimited data', 'Premium servers']) {
      expect(screen.getByText(chip)).toBeInTheDocument();
    }
    expect(screen.getByText('Manage Subscription')).toBeInTheDocument();
    expect(screen.getByText('Delete Account')).toBeInTheDocument();
  });

  // Account API contract 2026-10-01, item 86.
  it("shows the server's account number, masked until asked, and copies all of it", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    Object.defineProperty(navigator, 'clipboard', { value: { writeText }, configurable: true });
    useAppStore.setState({
      account: {
        ...useAppStore.getState().account,
        email: null,
        isAnonymous: true,
        accountNumber: '123456789012345678901234',
        plan: 'RECON',
      },
    });
    render(<Profile />);
    // The identity card and the Sign out row both say so.
    expect(screen.getAllByText('Anonymous account').length).toBeGreaterThan(0);
    expect(screen.getByTestId('account-number')).toHaveTextContent('•••• •••• •••• •••• •••• 1234');
    expect(document.body.textContent).not.toContain('1234 5678');
    await userEvent.click(screen.getByRole('button', { name: 'Show account number' }));
    expect(screen.getByTestId('account-number')).toHaveTextContent('1234 5678 9012 3456 7890 1234');
    const realUserAgent = navigator.userAgent;
    const setUserAgent = (ua: string) =>
      Object.defineProperty(window.navigator, 'userAgent', { value: ua, configurable: true });
    try {
      // MR-1723, Windows: through Rust's copy_sensitive (kept out of clipboard
      // history, cleared after a minute), not the webview's ordinary clipboard.
      setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/141.0');
      mockedInvoke.mockImplementation(async (cmd: string) => (cmd === 'copy_sensitive' ? true : undefined));
      await userEvent.click(screen.getByRole('button', { name: 'Copy account number' }));
      await waitFor(() =>
        expect(callsTo('copy_sensitive')).toEqual([['copy_sensitive', { text: '123456789012345678901234' }]]),
      );
      expect(writeText).not.toHaveBeenCalled();
      // macOS / Linux: the ordinary copy, at once (inside the click), no IPC.
      setUserAgent('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15');
      await userEvent.click(screen.getByRole('button', { name: 'Copy account number' }));
      expect(writeText).toHaveBeenCalledWith('123456789012345678901234');
      expect(callsTo('copy_sensitive')).toHaveLength(1);
    } finally {
      setUserAgent(realUserAgent);
    }
  });

  it('a server that sends no number: still "Anonymous account", no number, and says why', () => {
    useAppStore.setState({
      account: {
        ...useAppStore.getState().account,
        email: 'member@anonymous.local',
        isAnonymous: true,
        accountNumber: null,
        plan: 'RECON',
      },
    });
    render(<Profile />);
    expect(screen.getAllByText('Anonymous account').length).toBeGreaterThan(0);
    expect(screen.queryByTestId('account-number')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Copy account number' })).not.toBeInTheDocument();
    expect(screen.getByText(/shown once, when this account was created/)).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('member@');
  });

  // MR-918: the number comes from `/auth/me`'s accountNumber only; the
  // synthetic email beside it (phase 1) is neither parsed nor rendered.
  it('the account number comes from accountNumber, never from the synthetic email', () => {
    useAppStore.setState({
      account: {
        ...useAppStore.getState().account,
        email: 'anon_111122223333444455556666@anonymous.local',
        isAnonymous: true,
        accountNumber: '999988887777666655554321',
        plan: 'RECON',
      },
    });
    render(<Profile />);
    // The identity card and the Sign out row both say so.
    expect(screen.getAllByText('Anonymous account').length).toBeGreaterThan(0);
    expect(screen.getByTestId('account-number')).toHaveTextContent('•••• •••• •••• •••• •••• 4321');
    expect(document.body.textContent).not.toContain('anon_');
    expect(document.body.textContent).not.toContain('6666');
  });

  // MR-2014: the identity card never shows the synthetic address, even
  // before `/auth/me` has said the account is anonymous.
  it('the identity card never shows the synthetic address before /auth/me answers', () => {
    useAppStore.setState({
      userEmail: 'anon_111122223333444455556666@anonymous.local',
      account: {
        ...useAppStore.getState().account,
        email: null,
        isAnonymous: null,
        accountNumber: null,
        plan: 'RECON',
      },
    });
    render(<Profile />);
    expect(document.body.textContent).not.toContain('anon_');
    expect(document.body.textContent).not.toContain('@anonymous.local');
    expect(screen.getByText('Signed in')).toBeInTheDocument();
  });

  // MR-2014: a busy (or held) 5xx on redeem says the service is busy and for
  // how long. On main it read "Something went wrong on our side". The
  // rejection is exactly what Rust serialises for ServerBusy/Held{503, 20}
  // (vouchers.rs, `a_busy_or_held_5xx_crosses_ipc_with_its_wait`).
  it('a busy voucher service says so, and how long to wait', async () => {
    useAppStore.setState({ account: { ...useAppStore.getState().account, plan: 'RECON' } });
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'redeem_voucher') {
        throw {
          code: 'server_error',
          message: 'The voucher service is busy right now. Please try again in 20 seconds.',
          retryable: true,
          retry_after_secs: 20,
        };
      }
      return undefined;
    });
    render(<Profile />);
    await userEvent.click(screen.getByRole('button', { name: /Redeem voucher/ }));
    await userEvent.type(screen.getByLabelText('Voucher code'), 'BIRD-AAAA-BBBB-CCCC');
    await userEvent.click(screen.getByRole('button', { name: 'Redeem' }));
    expect(
      await screen.findByText('The voucher service is busy right now. Please try again in 20 seconds.'),
    ).toBeInTheDocument();
    expect(document.body.textContent).not.toContain('Something went wrong');
  });

  it('not connected: "Not connected · Click Connect to start"', () => {
    useAppStore.setState({ account: { ...useAppStore.getState().account, plan: 'RECON' } });
    render(<Profile />);
    expect(screen.getByText('Not connected')).toBeInTheDocument();
    expect(screen.getByText('Click Connect to start')).toBeInTheDocument();
  });

  it('Sign out disconnects first whatever the state — including a held block (W2-005)', async () => {
    useAppStore.setState({ connectionState: 'error', killSwitchBlocking: true });
    render(<Profile />);
    await userEvent.click(screen.getByRole('button', { name: /Sign out/ }));
    await waitFor(() => expect(useAppStore.getState().isAuthenticated).toBe(false));
    const order = mockedInvoke.mock.calls.map(([c]) => c);
    expect(order.indexOf('disconnect_vpn')).toBeGreaterThan(-1);
    expect(order.indexOf('disconnect_vpn')).toBeLessThan(order.indexOf('logout'));
  });
});

describe('Port Forwarding (W2-030)', () => {
  it('a failed load shows an error with Retry, and never "No port forwarding rules yet"', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'get_port_forwards') throw { code: 'server_error', message: '502' };
      return undefined;
    });
    render(<PortForward />);
    expect(await screen.findByText("Couldn't load your rules")).toBeInTheDocument();
    expect(screen.queryByText(/No port forwarding rules yet/)).not.toBeInTheDocument();
    mockedInvoke.mockImplementation(async () => []);
    await userEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByText('No port forwarding rules yet')).toBeInTheDocument();
  });
});

describe('Kill Switch Exceptions (W2-043)', () => {
  it('while off, the banner says exceptions are off instead of counting apps that "keep access"', () => {
    Object.defineProperty(window.navigator, 'userAgent', { value: 'Windows NT 10.0', configurable: true });
    useAppStore.setState({ settings: { ...defaultSettings, splitTunnelingEnabled: false, splitTunnelApps: ['a.exe'] } });
    render(<SplitTunnel />);
    expect(screen.getByText(/Exceptions are off/)).toBeInTheDocument();
    expect(screen.queryByText(/keeps internet access/)).not.toBeInTheDocument();
  });
});

describe('Offline banner (P1-parity-029)', () => {
  it('is hidden over a live tunnel and shown without one', async () => {
    useAppStore.setState({ isOnline: false, connectionState: 'connected' });
    const { rerender } = render(<OfflineBanner />);
    act(() => {
      window.dispatchEvent(new Event('offline'));
    });
    expect(screen.queryByText('No internet connection')).not.toBeInTheDocument();
    act(() => {
      useAppStore.setState({ connectionState: 'disconnected' });
    });
    rerender(<OfflineBanner />);
    expect(await screen.findByText('No internet connection')).toBeInTheDocument();
  });
});

describe('Update wall (W2-025) and updater (W2-024)', () => {
  it('the wall says the tunnel is still up and offers Disconnect', async () => {
    useAppStore.setState({ connectionState: 'connected' });
    render(<UpdateRequired info={{}} />);
    expect(screen.getByText("You're still connected")).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Disconnect' }));
    await waitFor(() => expect(callsTo('disconnect_vpn')).toHaveLength(1));
  });

  it('with no tunnel, there is nothing to disconnect', () => {
    render(<UpdateRequired info={{}} />);
    expect(screen.queryByText("You're still connected")).not.toBeInTheDocument();
    expect(screen.getByText('This version of BirdoVPN is no longer supported. Update to keep connecting.')).toBeInTheDocument();
  });

  it('an install in progress survives leaving Settings: coming back re-offers nothing', async () => {
    useUpdater.setState({ phase: 'installing', progress: 40, info: { version: '9.9.9', currentVersion: '1.0.0' } });
    const { unmount } = render(<UpdateChecker />);
    unmount();
    render(<UpdateChecker />);
    expect(screen.getByRole('progressbar', { name: 'Update download' })).toHaveAttribute('aria-valuenow', '40');
    expect(screen.queryByRole('button', { name: /Download|Install/ })).not.toBeInTheDocument();
    expect(callsTo('check_for_updates')).toHaveLength(0);
  });

  it('asks before installing while connected (installing ends the session)', async () => {
    useAppStore.setState({ connectionState: 'connected' });
    mockedInvoke.mockImplementation(async (cmd: string) =>
      cmd === 'check_for_updates' ? { version: '9.9.9', currentVersion: '1.0.0' } : undefined,
    );
    render(<UpdateChecker />);
    await userEvent.click(await screen.findByRole('button', { name: /Download|Install and restart/ }));
    expect(screen.getByText('Installing will disconnect the VPN and restart BirdoVPN.')).toBeInTheDocument();
    expect(callsTo('install_update')).toHaveLength(0);
  });

  // REVIEW-WIN-002: an install that fails after Rust ended the session for it.
  const installFails = (reconnect: string) =>
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'install_update') {
        throw { code: 'install_failed', message: 'Update failed: os error 225', reconnect };
      }
      return cmd === 'check_for_updates' ? { version: '9.9.9', currentVersion: '1.0.0' } : undefined;
    });

  it('a failed install says the INSTALL failed and offers to reconnect', async () => {
    installFails('offered');
    render(<UpdateChecker />);
    await userEvent.click(await screen.findByRole('button', { name: /Download|Install and restart/ }));
    expect(await screen.findByText(UPDATE_INSTALL_FAILED_COPY)).toBeInTheDocument();
    expect(screen.queryByText(UPDATE_DOWNLOAD_FAILED_COPY)).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Reconnect' }));
    // Rust has no list yet in this test, so the reconnect goes through its own
    // best-server pick.
    await waitFor(() => expect(callsTo('quick_connect')).toHaveLength(1));
    expect(screen.queryByRole('button', { name: 'Reconnect' })).not.toBeInTheDocument();
  });

  it('under always-on Rust reconnects by itself, so nothing is offered', async () => {
    installFails('automatic');
    await installUpdate();
    expect(useUpdater.getState().error).toMatch(/could not be installed\. BirdoVPN is reconnecting/);
    expect(useUpdater.getState().reconnectOffered).toBe(false);
  });

  it('a download or verification failure keeps its own wording', async () => {
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'install_update') throw { code: 'download_failed', message: 'x', reconnect: 'none' };
      return undefined;
    });
    await installUpdate();
    expect(useUpdater.getState().error).toBe(UPDATE_DOWNLOAD_FAILED_COPY);
    expect(useUpdater.getState().reconnectOffered).toBe(false);
  });
});

describe('Update held by the kill switch (MR-1824)', () => {
  const HELD = { code: 'held_by_kill_switch', message: 'The kill switch is blocking the update download', reconnect: 'none' };

  /** Rust holds the first `held` installs, then installs. */
  const rustHolds = (held: number) => {
    let calls = 0;
    mockedInvoke.mockImplementation(async (cmd: string) => {
      if (cmd === 'install_update') {
        calls += 1;
        if (calls <= held) throw HELD;
        return true;
      }
      return cmd === 'check_for_updates' ? { version: '9.9.9', currentVersion: '1.0.0' } : undefined;
    });
  };

  const blockedNoTunnel = () =>
    useAppStore.setState({ connectionState: 'reconnecting', killSwitchBlocking: true, pendingAction: null });

  /** Let any resume the store change kicked off settle. */
  const settle = () => act(async () => {
    await new Promise((r) => setTimeout(r, 0));
  });

  it('decides from the status: resume only with nothing active, ask once the tunnel is up', () => {
    const at = (connectionState: string, killSwitchBlocking: boolean, pendingAction: string | null = null) =>
      heldUpdateStep({ connectionState, killSwitchBlocking, pendingAction } as Parameters<typeof heldUpdateStep>[0]);
    expect(at('reconnecting', true)).toBe('wait');
    expect(at('error', true)).toBe('wait');
    // The block is gone but a session the install would end is not.
    expect(at('error', false)).toBe('wait');
    expect(at('reconnecting', false)).toBe('wait');
    expect(at('disconnected', false, 'disconnecting')).toBe('wait');
    // Nothing active: no session to end.
    expect(at('disconnected', false)).toBe('resume');
    // The tunnel is up (the Unix block is held while connected): ask again.
    expect(at('connected', true)).toBe('ask');
    expect(at('connected', false)).toBe('ask');
  });

  it('waits and says why, instead of failing the download', async () => {
    blockedNoTunnel();
    rustHolds(1);
    useUpdater.setState({ phase: 'available', info: { version: '9.9.9', currentVersion: '1.0.0' } });
    await installUpdate();
    expect(useUpdater.getState().phase).toBe('waiting');
    expect(useUpdater.getState().error).toBeNull();

    render(<UpdateChecker />);
    expect(screen.getByText(UPDATE_WAITING_COPY)).toBeInTheDocument();
    expect(screen.queryByText(UPDATE_DOWNLOAD_FAILED_COPY)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Download|Install|Retry/ })).not.toBeInTheDocument();
    // A revisit (or the daily check) does not clobber the wait.
    expect(callsTo('check_for_updates')).toHaveLength(0);
  });

  // Review of #259 (M1): an auto-reconnect hours later must not end the
  // session it just restored, and lift the block, with nobody watching.
  it('once the tunnel is up it offers the update again, and installs nothing by itself', async () => {
    blockedNoTunnel();
    rustHolds(1);
    useUpdater.setState({ info: { version: '9.9.9', currentVersion: '1.0.0' } });
    await installUpdate();

    useAppStore.setState({ connectionState: 'connected' });
    await settle();
    expect(useUpdater.getState().phase).toBe('available');
    expect(callsTo('install_update')).toHaveLength(1);

    // The next click goes through the confirm: installing ends the session.
    render(<UpdateChecker />);
    await userEvent.click(await screen.findByRole('button', { name: /Download|Install and restart/ }));
    expect(screen.getByText('Installing will disconnect the VPN and restart BirdoVPN.')).toBeInTheDocument();
    expect(callsTo('install_update')).toHaveLength(1);

    // And a later drop and recovery does not pick the old wait back up.
    blockedNoTunnel();
    useAppStore.setState({ connectionState: 'disconnected', killSwitchBlocking: false });
    await settle();
    expect(callsTo('install_update')).toHaveLength(1);
  });

  it('starts by itself once a disconnect leaves nothing active', async () => {
    blockedNoTunnel();
    rustHolds(1);
    await installUpdate();

    // Disconnect lands in steps: the command, the block lifting, then the state.
    useAppStore.setState({ pendingAction: 'disconnecting' });
    useAppStore.setState({ killSwitchBlocking: false });
    useAppStore.setState({ connectionState: 'disconnecting' });
    await settle();
    expect(callsTo('install_update')).toHaveLength(1);
    useAppStore.setState({ connectionState: 'disconnected', pendingAction: null });
    await waitFor(() => expect(useUpdater.getState().phase).toBe('ready'));
    expect(callsTo('install_update')).toHaveLength(2);
  });

  it('a block lifted under a session it would end (a give-up error) keeps waiting', async () => {
    blockedNoTunnel();
    rustHolds(1);
    await installUpdate();

    useAppStore.setState({ connectionState: 'error', killSwitchBlocking: false });
    useAppStore.setState({ connectionState: 'reconnecting' });
    await settle();
    expect(callsTo('install_update')).toHaveLength(1);
    expect(useUpdater.getState().phase).toBe('waiting');
  });

  it('a status that disagrees with Rust cannot spin it', async () => {
    // The status says nothing is active; Rust keeps holding the download.
    useAppStore.setState({ connectionState: 'disconnected', killSwitchBlocking: false, pendingAction: null });
    rustHolds(Number.MAX_SAFE_INTEGER);
    await installUpdate();
    await settle();
    // The click, and ONE immediate retry for a status that moved on.
    expect(callsTo('install_update')).toHaveLength(2);
    useAppStore.setState({ connectionState: 'disconnected' });
    useAppStore.setState({ settings: { ...useAppStore.getState().settings } });
    await settle();
    expect(callsTo('install_update')).toHaveLength(2);
    expect(useUpdater.getState().phase).toBe('waiting');
  });

  it('a hold answered while the tunnel is already up asks at once', async () => {
    useAppStore.setState({ connectionState: 'connected', killSwitchBlocking: true });
    rustHolds(Number.MAX_SAFE_INTEGER);
    await installUpdate();
    await settle();
    expect(callsTo('install_update')).toHaveLength(1);
    expect(useUpdater.getState().phase).toBe('available');
  });

  it('Cancel stops the wait and offers the update again', async () => {
    blockedNoTunnel();
    rustHolds(1);
    useUpdater.setState({ info: { version: '9.9.9', currentVersion: '1.0.0' } });
    await installUpdate();
    render(<UpdateChecker />);
    await userEvent.click(screen.getByRole('button', { name: 'Cancel' }));
    expect(useUpdater.getState().phase).toBe('available');

    useAppStore.setState({ connectionState: 'disconnected', killSwitchBlocking: false });
    await settle();
    expect(callsTo('install_update')).toHaveLength(1);
    cancelUpdateWait(); // idempotent once nothing waits
    expect(useUpdater.getState().phase).toBe('available');
  });

  // Review of #259 (L4): a stuck wait still has a way out on the wall.
  it('the update wall says why it waits and keeps its button', async () => {
    blockedNoTunnel();
    rustHolds(1);
    await installUpdate();
    render(<UpdateRequired info={{}} />);
    expect(screen.getByText(UPDATE_WAITING_COPY)).toBeInTheDocument();
    const button = screen.getByRole('button', { name: /Update now|Install and restart/ });
    expect(button).toBeEnabled();
    await userEvent.click(button);
    await waitFor(() => expect(callsTo('install_update')).toHaveLength(2));
  });
});

describe('Pricing (W2-042, W2-011)', () => {
  it('reads cleanly and marks no plan current while the plan is unknown', () => {
    useAppStore.setState({ account: { ...useAppStore.getState().account, plan: null } });
    render(<Pricing />);
    expect(screen.getByText(/every server location and more devices\. Billing/)).toBeInTheDocument();
    expect(screen.queryByText('Current plan')).not.toBeInTheDocument();
    expect(screen.getAllByText('Checking your plan…').length).toBeGreaterThan(0);
  });
});
