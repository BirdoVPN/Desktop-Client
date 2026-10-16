/**
 * VpnSettings — pushed sub-screen, mirroring mobile's `VpnSettingsScreen.kt` /
 * iOS VpnSettingsView.
 *
 * Sections: SECURITY (Stealth Mode, BirdoShield), NETWORK (Local Network
 * Sharing), WIREGUARD (the port, which is not a choice, + MTU), an info note,
 * then FEATURES (Kill Switch Exceptions, Windows-only).
 *
 * Every setting here shapes the tunnel, so each save goes through
 * `persistSettings(…, { reapply: true })`: saved, rolled back and reported if
 * the save fails, and applied to a live session by one debounced fail-closed
 * rebuild. The MTU field is a draft saved when the field is left (W2-007):
 * saving per keystroke rebuilt the tunnel on every digit.
 *
 * The port is not a choice (MR-920, Android and iOS parity): the relays accept
 * WireGuard on 51820 only (WIN-FIX-3). The "53" preset and custom port this
 * screen used to offer failed the handshake on every one of them, and the
 * "51820" choice that outlived them dialled what Automatic dials. The card says
 * so; a saved value is still migrated by Rust (`migrate_wireguard_port`) and
 * by the store (`normalizeWireGuardPort`).
 */
import { useState } from 'react';
import { useShallow } from 'zustand/react/shallow';
import { EyeOff, ShieldCheck, Network, Router, SlidersHorizontal, Info, Split } from 'lucide-react';
import {
  BirdoTopBar,
  BirdoCard,
  BirdoSectionHeader,
  BirdoToggleRow,
  BirdoNavRow,
  BirdoTextField,
} from '@/components/birdo';
import { useAppStore } from '@/store/app-store';
import { isValidMtu, isWindowsPlatform } from '@/utils/helpers';
import { white, status, brand } from '@/lib/birdo-theme';
import { lowestPlanWith, planHasFeature, planName } from '@/lib/plan';
import { persistSettings } from '@/session/settings-persist';
import { loadSubscription } from '@/session/session-data';

export function VpnSettings() {
  const { settings, popRoute, pushRoute, plan, planGates, connectionState, dnsFilteringAvailable, reapplying } =
    useAppStore(
    useShallow((s) => ({
      settings: s.settings,
      popRoute: s.popRoute,
      pushRoute: s.pushRoute,
      plan: s.account.plan,
      planGates: s.planGates,
      connectionState: s.connectionState,
      dnsFilteringAvailable: s.dnsFilteringAvailable,
      reapplying: s.reapplying,
    })),
  );
  const connected = connectionState === 'connected';
  const save = (patch: Parameters<typeof persistSettings>[0]) => void persistSettings(patch, { reapply: true });

  // Stealth Mode is OPERATIVE+ (enforced server-side too). `null` = the plan is
  // not known yet: the row waits instead of showing a paying user a lock.
  // MR-1517: the server's plan-gating table decides, the built-in one where it
  // is silent.
  const stealthUnlocked = planHasFeature(plan, planGates, 'stealthMode');
  const stealthPlan = planName(lowestPlanWith('stealthMode', planGates) ?? 'OPERATIVE');

  // BirdoShield vs Custom DNS (PR #160 review, must-fix 1): the Rust tunnel
  // builder applies the user's Custom DNS servers BEFORE the server-supplied
  // resolver, so with Custom DNS in force the filtering resolver is never
  // written into the tunnel — zero filtering. The row reads OFF, is disabled
  // and says why; Rust's `effective_dns_filtering` applies the same rule.
  // Custom DNS is "in force" only while its switch is on AND it has addresses
  // (the addresses are kept while it is off, P1-parity-042).
  const customDnsActive = settings.customDnsEnabled && (settings.customDns ?? []).length > 0;

  // BirdoShield fleet gate: `=== false` (not `!available`) is the whole point —
  // undefined/unknown means AVAILABLE; only an explicit server "no" greys it out.
  const fleetGateOff = dnsFilteringAvailable === false;

  // Either blocker hides the toggle's effect, so both read OFF and disabled.
  // The saved `settings.dnsFiltering` is NOT cleared by either: clearing
  // Custom DNS, or the fleet gate coming back, restores the user's choice.
  const shieldBlocked = fleetGateOff || customDnsActive;

  // ── MTU (a draft while custom) ─────────────────────────────────────────────
  const mtuAuto = settings.wireGuardMtu === 0;
  const [mtuDraft, setMtuDraft] = useState(settings.wireGuardMtu > 0 ? String(settings.wireGuardMtu) : '');
  const [mtuError, setMtuError] = useState<string | null>(null);
  // A change Rust could not apply is put back (WIN-FIX-3): follow the saved
  // value when it changes under the field (it does not while typing). Adjusted
  // during render, the way React documents for state derived from a prop.
  const [mtuSaved, setMtuSaved] = useState(settings.wireGuardMtu);
  if (mtuSaved !== settings.wireGuardMtu) {
    setMtuSaved(settings.wireGuardMtu);
    setMtuDraft(settings.wireGuardMtu > 0 ? String(settings.wireGuardMtu) : '');
  }
  const commitMtu = () => {
    const v = mtuDraft.trim();
    if (!v) return;
    if (!isValidMtu(v)) {
      setMtuError('Enter a value from 1280 to 1500.');
      return;
    }
    setMtuError(null);
    if (Number(v) !== settings.wireGuardMtu) save({ wireGuardMtu: Number(v) });
  };

  return (
    // Transparent so the App-level PixelCanvas backdrop shows through.
    <div className="flex h-full flex-col">
      <BirdoTopBar title="VPN Settings" onBack={popRoute} />

      <div className="flex-1 overflow-y-auto px-4 pb-8 pt-2">
        {/* ── SECURITY ──────────────────────────────────────────────── */}
        <BirdoSectionHeader title="Security" />

        <BirdoCard padding="0">
          {/* Title without "· Premium" (P1-parity-032): a paying user saw an
              upsell word on a setting they own. When locked, the whole row
              routes to the plans — one affordance, not a dead switch plus a
              separate link. */}
          <BirdoToggleRow
            title="Stealth Mode"
            subtitle={
              stealthUnlocked === null
                ? 'Checking your plan…'
                : 'Wraps WireGuard in an encrypted transport for networks that block VPNs. Slower.'
            }
            subtitleWrap
            leadingIcon={EyeOff}
            leadingTint={status.blue}
            // `&& unlocked` so a saved ON cannot resurface after a downgrade.
            checked={settings.stealthMode && stealthUnlocked === true}
            onCheckedChange={(v) => save({ stealthMode: v })}
            enabled={stealthUnlocked !== null}
            locked={
              stealthUnlocked === false
                ? { onClick: () => pushRoute('pricing'), label: stealthPlan }
                : undefined
            }
          />
          {stealthUnlocked === null && (
            <button
              type="button"
              onClick={() => void loadSubscription(true)}
              className="px-3.5 pb-3 text-xs font-semibold"
              style={{ color: brand.accentSoft }}
            >
              Retry
            </button>
          )}
          {/* BirdoShield (D18): per-device DNS filtering, sent as the
              `dnsFiltering` connect flag by BOTH Rust dial paths. No plan
              gate. Gated by the fleet and by Custom DNS instead. */}
          <BirdoToggleRow
            title="BirdoShield"
            subtitle={
              fleetGateOff
                ? "Not available on your account's server fleet yet. Your preference is kept and applies as soon as it is."
                : customDnsActive
                  ? 'Custom DNS overrides BirdoShield. Turn off Custom DNS Servers under Settings › VPN to use the filtering resolver.'
                  : "Blocks ads, trackers and malware domains at the VPN's DNS resolver."
            }
            // Every subtitle here is an explanation, longer than the ~34
            // characters one 12px line fits in the 380px window; truncated,
            // the user would never see that their preference is kept.
            subtitleWrap
            leadingIcon={ShieldCheck}
            leadingTint={shieldBlocked ? white.w40 : brand.accent}
            checked={settings.dnsFiltering && !shieldBlocked}
            onCheckedChange={(v) => save({ dnsFiltering: v })}
            enabled={!shieldBlocked}
          />
        </BirdoCard>

        {/* ── NETWORK ───────────────────────────────────────────────── */}
        <BirdoSectionHeader title="Network" className="mt-4" />

        <BirdoCard padding="0">
          <BirdoToggleRow
            title="Local Network Sharing"
            subtitle="Allow access to devices on your local network (printers, NAS, etc.) while connected to VPN."
            subtitleWrap
            leadingIcon={Network}
            leadingTint={status.blue}
            checked={settings.localNetworkSharing}
            onCheckedChange={(v) => save({ localNetworkSharing: v })}
          />
        </BirdoCard>

        {/* ── WIREGUARD ─────────────────────────────────────────────── */}
        <BirdoSectionHeader title="WireGuard" className="mt-4" />

        <BirdoCard>
          <div className="flex items-center gap-3.5">
            <Router size={20} color={brand.accent} aria-hidden />
            <div>
              <div className="text-[15px] font-medium text-white">WireGuard Port</div>
              <div className="text-xs" style={{ color: white.w60 }}>
                Automatic
              </div>
            </div>
          </div>
          <p className="mt-2 text-xs" style={{ color: white.w60 }}>
            BirdoVPN servers accept WireGuard on port 51820 only.
          </p>
        </BirdoCard>

        <div className="h-2" />
        <BirdoCard>
          <div className="flex items-center gap-3.5">
            <SlidersHorizontal size={20} color={status.yellow} aria-hidden />
            <div>
              <div className="text-[15px] font-medium text-white">WireGuard MTU</div>
              <div className="text-xs" style={{ color: white.w60 }}>
                Packet size — lower values improve reliability on unstable networks
              </div>
            </div>
          </div>
          <div className="mt-3 space-y-1">
            <BirdoToggleRow
              title="Automatic (server default)"
              checked={mtuAuto}
              onCheckedChange={(auto) => {
                setMtuError(null);
                if (auto) {
                  setMtuDraft('');
                  save({ wireGuardMtu: 0 });
                } else {
                  setMtuDraft('1420');
                  save({ wireGuardMtu: 1420 });
                }
              }}
            />
            {!mtuAuto && (
              <BirdoTextField
                className="px-1 pt-1"
                ariaLabel="WireGuard MTU"
                placeholder="1280-1500"
                inputMode="numeric"
                value={mtuDraft}
                onChange={(raw) => {
                  setMtuDraft(raw.replace(/\D/g, '').slice(0, 4));
                  if (mtuError) setMtuError(null);
                }}
                onBlur={commitMtu}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') commitMtu();
                }}
                errorText={mtuError}
                hint="Valid range: 1280–1500. Recommended: 1420."
              />
            )}
          </div>
        </BirdoCard>

        {/* ── Info note ─────────────────────────────────────────────── */}
        <div
          className="mt-3 flex items-center gap-2.5 rounded-birdo-sm px-3 py-2.5"
          style={{ backgroundColor: white.w10 }}
          aria-live="polite"
        >
          <Info size={16} color={white.w60} aria-hidden className="shrink-0" />
          <p className="text-xs" style={{ color: white.w60 }}>
            {reapplying
              ? 'Applying settings — reconnecting…'
              : connected
                ? 'Changes apply to your current connection automatically (brief reconnect).'
                : 'Changes take effect on the next connection.'}
          </p>
        </div>

        {/* ── FEATURES ──────────────────────────────────────────────── */}
        {/* WFP enforcement is Windows-only. Presented as "Kill Switch
            Exceptions", not "Split Tunneling": WFP permit filters exempt an
            app from the kill-switch block — they cannot route it outside the
            VPN (that needs a signed redirect callout driver). */}
        {isWindowsPlatform() && (
          <>
            <BirdoSectionHeader title="Features" className="mt-4" />
            <BirdoCard padding="0">
              <BirdoNavRow
                title="Kill Switch Exceptions"
                subtitle="Apps that stay online while the kill switch blocks traffic"
                subtitleWrap
                leadingIcon={Split}
                leadingTint={white.w60}
                onClick={() => pushRoute('splitTunnel')}
              />
            </BirdoCard>
          </>
        )}
      </div>
    </div>
  );
}
