/**
 * BirdoShield toggle (OPEN-WORK D18) — VPN Settings → Security.
 *
 * The Rust side sends the per-device `dnsFiltering` connect flag on both dial
 * paths from the persisted `dns_filtering` setting; the only thing the
 * frontend owns is getting that setting persisted through the SAME
 * full-object `save_settings` path every other tunnel setting uses, on every
 * plan (no gate), and scheduling the live rebuild when a session is up. These
 * tests drive the real VpnSettings screen and assert exactly that.
 *
 * Run: npx vitest run src/__tests__/BirdoShieldToggle.test.tsx
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { invoke } from '@tauri-apps/api/core';
import { VpnSettings } from '@/screens/VpnSettings';
import { BirdoListItem } from '@/components/birdo/ListItem';
import type { ConnectionState } from '@/store/app-store';

vi.mock('@tauri-apps/api/core');

// Mutable so each test can pick the plan / connection state the toggle is
// flipped in. `updateSettings` mirrors the real store's shallow patch so the
// `settings` the screen re-reads via getState() carries the new value.
const mockStoreState = {
  connectionState: 'disconnected' as ConnectionState,
  // The fleet gate from GET /api/client-config. `true` is the store default —
  // see the availability describe block at the bottom of this file.
  dnsFilteringAvailable: true as boolean | undefined,
  settings: {
    killSwitchEnabled: true,
    autoConnect: false,
    autostart: false,
    startMinimized: false,
    notifications: true,
    showIpInNotification: false,
    showLocationInNotification: false,
    preferredServerId: null,
    splitTunnelingEnabled: false,
    splitTunnelApps: [] as string[],
    customDns: null as string[] | null,
    protocol: 'wireguard' as const,
    localNetworkSharing: false,
    wireGuardPort: 'auto',
    wireGuardMtu: 0,
    multiHopEnabled: false,
    multiHopEntryNodeId: null,
    multiHopExitNodeId: null,
    stealthMode: false,
    quantumProtection: true,
    dnsFiltering: false,
    lockdownMode: true,
  },
  updateSettings: vi.fn((patch: Record<string, unknown>) => {
    Object.assign(mockStoreState.settings, patch);
  }),
  popRoute: vi.fn(),
  pushRoute: vi.fn(),
  account: {
    email: 'test@birdo.app',
    plan: 'RECON',
    accountId: 'acct_test',
    maxDevices: 1,
    activeDevices: 1,
    expiresAt: null,
    bandwidthUsed: 0,
    bandwidthLimit: 0,
    status: 'active',
  },
};

vi.mock('@/store/app-store', () => {
  const useAppStore = vi.fn((selector) => selector(mockStoreState));
  (useAppStore as unknown as { getState: () => typeof mockStoreState }).getState = () =>
    mockStoreState;
  return { useAppStore };
});

vi.mock('zustand/react/shallow', () => ({
  useShallow: (fn: unknown) => fn,
}));

const mockedInvoke = vi.mocked(invoke);

beforeEach(() => {
  mockedInvoke.mockReset();
  mockedInvoke.mockResolvedValue(undefined);
  mockStoreState.updateSettings.mockClear();
  mockStoreState.settings.dnsFiltering = false;
  mockStoreState.settings.stealthMode = false;
  mockStoreState.settings.customDns = null;
  mockStoreState.connectionState = 'disconnected';
  mockStoreState.account.plan = 'RECON';
  mockStoreState.dnsFilteringAvailable = true;
});


/** The exact fleet-gate reason copy the screen renders. */
const UNAVAILABLE_COPY =
  "Not available on your account's server fleet yet. Your preference is kept and applies as soon as it is.";

const savedSettings = () =>
  mockedInvoke.mock.calls
    .filter(([cmd]) => cmd === 'save_settings')
    .map(([, args]) => (args as { settings: Record<string, unknown> }).settings);

const reapplyCalls = () =>
  mockedInvoke.mock.calls.filter(([cmd]) => cmd === 'reapply_vpn_settings');

describe('BirdoShield toggle → dns_filtering', () => {
  it('renders OFF by default under Security with the resolver copy, on the free plan (no plan gate)', async () => {
    render(<VpnSettings />);
    const row = await screen.findByRole('switch', { name: /birdoshield/i });
    expect(row).toHaveAttribute('aria-checked', 'false');
    // BirdoListItem renders an interactive <button> only when enabled; a
    // gated row degrades to a static <div>.
    expect(row.tagName).toBe('BUTTON');
    // No "applies on your next connection" tail: the screen's info note
    // already states the live-reapply behaviour and the two contradicted.
    expect(
      screen.getByText("Blocks ads, trackers and malware domains at the VPN's DNS resolver."),
    ).toBeInTheDocument();
    // Stealth, by contrast, IS plan-gated on RECON — the two rows differ on purpose.
    expect(screen.getByRole('switch', { name: /stealth mode/i }).tagName).toBe('DIV');
  });

  it('ON persists dnsFiltering through the store patch and the full-object save_settings (dns_filtering: true)', async () => {
    render(<VpnSettings />);
    await userEvent.click(await screen.findByRole('switch', { name: /birdoshield/i }));

    expect(mockStoreState.updateSettings).toHaveBeenCalledWith({ dnsFiltering: true });
    await waitFor(() => {
      expect(savedSettings()).toHaveLength(1);
    });
    const saved = savedSettings()[0];
    expect(saved.dns_filtering).toBe(true);
    // The rest of the object rides along untouched (full-object save path).
    expect(saved.stealth_mode).toBe(false);
    expect(saved.quantum_protection).toBe(true);
    expect(saved.killswitch_enabled).toBe(true);
    // Disconnected: nothing to rebuild — the flag applies at the next connect.
    expect(reapplyCalls()).toHaveLength(0);
  });

  it('OFF persists dns_filtering: false (a real user choice, not an omission)', async () => {
    mockStoreState.settings.dnsFiltering = true;
    render(<VpnSettings />);
    const row = await screen.findByRole('switch', { name: /birdoshield/i });
    expect(row).toHaveAttribute('aria-checked', 'true');
    await userEvent.click(row);

    expect(mockStoreState.updateSettings).toHaveBeenCalledWith({ dnsFiltering: false });
    await waitFor(() => {
      expect(savedSettings()).toHaveLength(1);
    });
    expect(savedSettings()[0].dns_filtering).toBe(false);
  });

  // PR #160 review, must-fix 1: `build_vpn_config` writes the user's Custom
  // DNS servers into the tunnel ahead of the server's resolver, so with Custom
  // DNS set the filtering resolver is never used. The row must not read ON
  // (reassurance from missing data) and must say why it is unavailable.
  describe('with Custom DNS configured', () => {
    it('reads OFF, is disabled and explains the override — even when dnsFiltering is persisted ON', async () => {
      mockStoreState.settings.customDns = ['9.9.9.9', '149.112.112.112'];
      mockStoreState.settings.dnsFiltering = true;
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row).toHaveAttribute('aria-checked', 'false');
      // Disabled rows degrade to a static <div> (same as Stealth on RECON).
      expect(row.tagName).toBe('DIV');
      expect(
        screen.getByText(
          'Custom DNS overrides BirdoShield. Clear your custom DNS servers under Settings › VPN to use the filtering resolver.',
        ),
      ).toBeInTheDocument();
      expect(
        screen.queryByText("Blocks ads, trackers and malware domains at the VPN's DNS resolver."),
      ).not.toBeInTheDocument();

      // Clicking the disabled row must not persist anything.
      await userEvent.click(row);
      expect(mockStoreState.updateSettings).not.toHaveBeenCalled();
      expect(savedSettings()).toHaveLength(0);
    });

    it('a single custom server is enough to gate the row', async () => {
      mockStoreState.settings.customDns = ['1.1.1.1'];
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row.tagName).toBe('DIV');
    });

    it('an empty custom DNS list does NOT gate the row (matches the Rust `!d.is_empty()` rule)', async () => {
      mockStoreState.settings.customDns = [];
      mockStoreState.settings.dnsFiltering = true;
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row.tagName).toBe('BUTTON');
      expect(row).toHaveAttribute('aria-checked', 'true');
    });
  });

  // PR #160/#403 review follow-up: `dnsFilteringAvailable` on
  // GET /api/client-config is the backend's DNS_FILTERING_ENABLED fleet gate.
  // With it off the backend ignores the connect flag and hands out the normal
  // resolver, so a row the user can switch ON is a lie about what the server
  // will do.
  describe('with the fleet gate off (dnsFilteringAvailable: false)', () => {
    it('reads OFF, is disabled and gives the reason — even when dnsFiltering is persisted ON', async () => {
      mockStoreState.dnsFilteringAvailable = false;
      mockStoreState.settings.dnsFiltering = true;
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row).toHaveAttribute('aria-checked', 'false');
      // Disabled rows degrade to a static <div> (same as Stealth on RECON).
      expect(row.tagName).toBe('DIV');
      expect(screen.getByText(UNAVAILABLE_COPY)).toBeInTheDocument();
      expect(
        screen.queryByText("Blocks ads, trackers and malware domains at the VPN's DNS resolver."),
      ).not.toBeInTheDocument();

      // Clicking the disabled row must not persist anything — and, crucially,
      // must not CLEAR the stored preference either: it has to come back on
      // its own when the gate does.
      await userEvent.click(row);
      expect(mockStoreState.updateSettings).not.toHaveBeenCalled();
      expect(savedSettings()).toHaveLength(0);
      expect(mockStoreState.settings.dnsFiltering).toBe(true);
    });

    it('names the fleet gate, not Custom DNS, when both block the row', async () => {
      mockStoreState.dnsFilteringAvailable = false;
      mockStoreState.settings.customDns = ['1.1.1.1'];
      render(<VpnSettings />);
      expect(screen.getByText(UNAVAILABLE_COPY)).toBeInTheDocument();
      expect(
        screen.queryByText(
          'Custom DNS overrides BirdoShield. Clear your custom DNS servers under Settings › VPN to use the filtering resolver.',
        ),
      ).not.toBeInTheDocument();
    });
  });

  describe('with the fleet gate on or unknown', () => {
    it('true leaves the row enabled and switchable', async () => {
      mockStoreState.dnsFilteringAvailable = true;
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row.tagName).toBe('BUTTON');
      await userEvent.click(row);
      expect(mockStoreState.updateSettings).toHaveBeenCalledWith({ dnsFiltering: true });
    });

    // The default that matters: a failed/absent fetch leaves the store value
    // untouched, and `undefined` must NOT read as "off". Hiding a feature that
    // works because the client could not reach the web app is the failure this
    // whole flag exists to avoid.
    it('an unknown value (failed fetch, older web deploy) leaves the row enabled', async () => {
      mockStoreState.dnsFilteringAvailable = undefined;
      mockStoreState.settings.dnsFiltering = true;
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row.tagName).toBe('BUTTON');
      expect(row).toHaveAttribute('aria-checked', 'true');
      expect(
        screen.getByText("Blocks ads, trackers and malware domains at the VPN's DNS resolver."),
      ).toBeInTheDocument();
      expect(screen.queryByText(UNAVAILABLE_COPY)).not.toBeInTheDocument();
    });
  });

  // PR #162 review, must-fix 1: `expect(screen.getByText(COPY))` reads DOM
  // text, and jsdom applies no CSS, so it passes on copy the user can never
  // read. The subtitle was `mt-0.5 truncate text-xs` -- ONE ellipsised line --
  // in a window that is `"width": 380, "height": 640, "resizable": false`
  // (src-tauri/tauri.conf.json). Subtracting the screen padding (32), the row
  // padding (28), the 36px leading icon, the 48px switch and their 14px gaps
  // leaves the subtitle column about 208px; at `text-xs` (12px, ~6px average
  // glyph) roughly 34 characters survive. The fleet-gate reason is 104
  // characters, so the second half -- "Your preference is kept and applies as
  // soon as it is.", the entire reassurance -- never rendered, with no resize,
  // no tooltip and no horizontal scroll to recover it.
  //
  // There is no layout engine here to measure, so the assertion is structural:
  // a subtitle longer than one line must not be in a truncating container.
  describe('the blocked reason must be readable, not just present in the DOM', () => {
    /** Characters that fit on one 12px line in the 380px window (see above). */
    const ONE_LINE_BUDGET = 34;

    /** The row's subtitle element (the title is `text-[15px]`). */
    const subtitleOf = (row: HTMLElement) => {
      const el = row.querySelector('.text-xs');
      expect(el).not.toBeNull();
      return el as HTMLElement;
    };

    const states: Array<[string, () => void]> = [
      ['default', () => {}],
      ['fleet gate off', () => { mockStoreState.dnsFilteringAvailable = false; }],
      ['custom DNS', () => { mockStoreState.settings.customDns = ['1.1.1.1']; }],
    ];

    it.each(states)('%s: the whole subtitle is rendered untruncated', async (_name, setup) => {
      setup();
      render(<VpnSettings />);
      const subtitle = subtitleOf(await screen.findByRole('switch', { name: /birdoshield/i }));
      // Every one of the three copies is longer than a line -- if one ever is
      // not, the budget below stops being the thing under test.
      expect(subtitle.textContent!.length).toBeGreaterThan(ONE_LINE_BUDGET);
      expect(subtitle.className).not.toMatch(/\btruncate\b/);
      expect(subtitle.className).toMatch(/\bwhitespace-normal\b/);
    });

    it('spells out the fleet-gate reason past the truncation point', async () => {
      mockStoreState.dnsFilteringAvailable = false;
      render(<VpnSettings />);
      const subtitle = subtitleOf(await screen.findByRole('switch', { name: /birdoshield/i }));
      expect(subtitle).toHaveTextContent(UNAVAILABLE_COPY);
      // The half that used to fall off the end. Asserted separately so the
      // failure names the thing that was lost, not just "text mismatch".
      expect(UNAVAILABLE_COPY.slice(ONE_LINE_BUDGET)).toContain('Your preference is kept');
      expect(subtitle).toHaveTextContent('Your preference is kept and applies as soon as it is.');
    });

    it('rows whose subtitle is a short value keep the default truncation', () => {
      // The opt-out is per row, not a blanket change to BirdoListItem: only a
      // subtitle that is an EXPLANATION pays the extra height.
      render(
        <BirdoListItem title="Port" subtitle="Automatic" />,
      );
      const subtitle = screen.getByText('Automatic');
      expect(subtitle.className).toMatch(/\btruncate\b/);
    });
  });


  // PR #162 review, nit: a disabled control still has to BE a control.
  // `BirdoListItem` degrades a blocked row from <button role="switch"> to
  // <div role="switch">, and a div carries no `disabled` attribute and is not
  // focusable — so the blocked row was announced as an ordinary switch whose
  // state was simply "off". That is the visual lie this PR removes, re-told to
  // a screen reader. Fixed with `aria-disabled` and a tab stop.
  //
  // The rest of the round-4 justification for this block — that the reason sat
  // "in a separate, unlinked node" — was false, and is corrected in the
  // name/description block below rather than quietly dropped.
  describe('the disabled row has a correct accessible representation', () => {
    const reasonOf = (row: HTMLElement) => {
      const id = row.getAttribute('aria-describedby');
      expect(id).toBeTruthy();
      return document.getElementById(id!);
    };

    it('the fleet-gate row is announced as disabled, is reachable, and points at its reason', async () => {
      mockStoreState.dnsFilteringAvailable = false;
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });

      // Not a <button>, so `disabled` cannot carry it — ARIA has to.
      expect(row.tagName).toBe('DIV');
      expect(row).toHaveAttribute('aria-disabled', 'true');
      // Focusable on purpose: an aria-disabled control stays in the tab order
      // so its state and description can be read. It has no click handler, so
      // reaching it does nothing (asserted above in the gate-off block).
      expect(row).toHaveAttribute('tabindex', '0');
      expect(reasonOf(row)).toHaveTextContent(UNAVAILABLE_COPY);
    });

    it('the Custom DNS row does the same', async () => {
      mockStoreState.settings.customDns = ['1.1.1.1'];
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row).toHaveAttribute('aria-disabled', 'true');
      expect(row).toHaveAttribute('tabindex', '0');
      expect(reasonOf(row)).toHaveTextContent('Custom DNS overrides BirdoShield.');
    });

    it('an enabled row is NOT announced as disabled and keeps the button tab stop', async () => {
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /birdoshield/i });
      expect(row.tagName).toBe('BUTTON');
      expect(row).not.toHaveAttribute('aria-disabled');
      // A <button> is focusable already; adding tabindex would be noise.
      expect(row).not.toHaveAttribute('tabindex');
      expect(reasonOf(row)).toHaveTextContent(
        "Blocks ads, trackers and malware domains at the VPN's DNS resolver.",
      );
    });

    it('the plan-gated Stealth row gets the same treatment (not a BirdoShield special case)', async () => {
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: /stealth mode/i });
      expect(row.tagName).toBe('DIV');
      expect(row).toHaveAttribute('aria-disabled', 'true');
      expect(row).toHaveAttribute('tabindex', '0');
    });
  });

  // PR #162 review, must-fix 2 (round 5). Round 4 added `aria-describedby` on
  // the stated grounds that the reason was "sitting in a sibling node with
  // nothing linking it" and that a screen reader announced only "BirdoShield,
  // switch, off". Both were false, and the fix that followed from them said
  // the reason TWICE: the subtitle is a DESCENDANT of the element carrying
  // role="switch", so it was already the tail of the row's accessible NAME,
  // and pointing `aria-describedby` at it made the same sentence the
  // DESCRIPTION as well — on every subtitled toggle row, enabled ones
  // included, since describedBy is set whenever a `role` is present.
  //
  // What the pair is really for: the NAME is the setting, the DESCRIPTION is
  // why it cannot be used, and neither is allowed to be the other. Drop
  // `aria-label` and the name assertions fail (the exact-string role query
  // stops matching, because the name grows the reason back onto it); drop
  // `aria-describedby` and the description assertions fail.
  describe('the row NAMES the setting and DESCRIBES the reason, saying neither twice', () => {
    it('the structural premise round 4 got wrong: the subtitle is INSIDE the switch', async () => {
      mockStoreState.dnsFilteringAvailable = false;
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: 'BirdoShield' });
      expect(row.contains(screen.getByText(UNAVAILABLE_COPY))).toBe(true);
    });

    it('the blocked row: name is the setting, description is the reason', async () => {
      mockStoreState.dnsFilteringAvailable = false;
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: 'BirdoShield' });
      expect(row).toHaveAccessibleName('BirdoShield');
      expect(row).toHaveAccessibleDescription(UNAVAILABLE_COPY);
    });

    it('an ENABLED row does not announce its subtitle twice either', async () => {
      render(<VpnSettings />);
      const row = await screen.findByRole('switch', { name: 'BirdoShield' });
      expect(row).toHaveAccessibleName('BirdoShield');
      expect(row).toHaveAccessibleDescription(
        "Blocks ads, trackers and malware domains at the VPN's DNS resolver.",
      );
    });

    // The `subtitle=""` half pins a claim review made and MEASUREMENT refutes:
    // that `subtitle && isSemanticControl ? id : undefined` emits a dangling
    // aria-describedby="". `&&` binds tighter than `?:`, so '' is the falsy
    // condition and the result is undefined — this case passes under both that
    // form and the `Boolean(subtitle)` one now in the component. Kept because
    // the attribute being absent is the property that matters, whichever way
    // the condition is spelled.
    it('a row with no subtitle gets no description, and never an empty aria-describedby', () => {
      const { unmount } = render(
        <BirdoListItem title="Port" role="switch" ariaChecked={false} />,
      );
      const row = screen.getByRole('switch');
      expect(row).toHaveAccessibleName('Port');
      expect(row).toHaveAccessibleDescription('');
      expect(row).not.toHaveAttribute('aria-describedby');
      unmount();

      render(<BirdoListItem title="Port" subtitle="" role="switch" ariaChecked={false} />);
      expect(screen.getByRole('switch')).not.toHaveAttribute('aria-describedby');
    });
  });

  it('while connected, schedules the same debounced fail-closed rebuild Stealth uses', async () => {
    mockStoreState.connectionState = 'connected';
    render(<VpnSettings />);
    await userEvent.click(await screen.findByRole('switch', { name: /birdoshield/i }));

    await waitFor(() => {
      expect(savedSettings()).toHaveLength(1);
    });
    // Debounced (900 ms): not yet, then exactly once.
    expect(reapplyCalls()).toHaveLength(0);
    await waitFor(() => expect(reapplyCalls()).toHaveLength(1), { timeout: 3000 });
  });
});
