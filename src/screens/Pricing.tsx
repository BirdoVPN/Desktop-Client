/**
 * Pricing — informational "Plans & Pricing" pushed sub-screen (desktop parity
 * with the Android SubscriptionScreen).
 *
 * Billing itself stays WEB-MANAGED: this screen never takes an in-app payment.
 * The "Upgrade" CTA opens the web dashboard's billing page in the system browser
 * (dashboard.birdo.app/billing) — the same web-billing model Profile.tsx /
 * Settings.tsx already point users to. The screen only READS `account.plan` to
 * mark and highlight the user's current tier.
 *
 * Like VpnSettings.tsx this is a pushed sub-screen: it renders a BirdoTopBar
 * with a back button wired to the store's `popRoute`. Routing is wired
 * separately — this file only provides the screen.
 *
 * Design: mirrors the existing screens' design-system usage (BirdoTopBar,
 * BirdoCard, BirdoButton, BirdoBadge, brand tokens). Dark-emerald corporate
 * restraint — emerald is an accent only, no colourful gradients / neon glow.
 *
 * PRICES COME FROM THE SERVER (MR-132 / MR-630 / MR-1767 / MR-1979): the
 * prices, currency, savings and data caps are rendered from
 * `GET /api/client-config` → `plans` (birdo-web #708, via `useClientConfig`),
 * the same table the web's /pricing and Polar checkout use. They used to be
 * written here, which is how the free cap still read 10 GB after the server
 * moved. A plan the server has not priced shows `FALLBACK_PLAN_PRICES`.
 *
 * So does the copy around them (MR-2030): the line under the title, and what
 * "Everything in …" claims, follow the plans' caps; and each gated feature is
 * sold on the card of the lowest plan the server's gating table gives it to
 * (MR-1517, `lowestPlanWith`), not on a card of this file's choosing. These
 * are the web checkout's (Polar) card prices; the desktop app has no in-app
 * purchase, so no store price is ever meant here.
 */
import { useMemo, useState } from 'react';
import { openUrl as openExternal } from '@tauri-apps/plugin-opener';
import { useShallow } from 'zustand/react/shallow';
import type { LucideIcon } from 'lucide-react';
import { Check, Shield, Zap, Crown, ExternalLink } from 'lucide-react';
import { BirdoTopBar, BirdoCard, BirdoButton, BirdoBadge } from '@/components/birdo';
import { useAppStore } from '@/store/app-store';
import { brand, white, hairline, surface, accentA } from '@/lib/birdo-theme';
import {
  PLAN_RANK,
  formatPrice,
  lowestPlanWith,
  normalizePlan,
  planHasFeature,
  resolvePlanPrices,
  yearlySavingPct,
  type GatedFeature,
  type PlanGates,
  type PlanId,
  type PlanPrice,
} from '@/lib/plan';
import { BILLING_URL } from '@/lib/links';

// Billing lives on the web (the same host Settings opens for "Manage on web").

type BillingPeriod = 'monthly' | 'yearly';

interface Tier {
  id: PlanId;
  name: string;
  tagline: string;
  icon: LucideIcon;
  iconTint: string;
  /** Both prices are zero: the free tier. */
  free: boolean;
  /**
   * The monthly price as shown, from the server's `plans`; `null` for none (the
   * free tier, or MR-2030: a paid plan priced 0 a month, which is not offered
   * monthly, so the card shows its yearly price instead of "£0").
   */
  monthly: string | null;
  /** The ANNUAL TOTAL as the server gives it, shown with "/yr"; `null` likewise. */
  yearly: string | null;
  /**
   * Yearly saving vs 12 monthly payments, per plan and rounded DOWN (the web
   * floors it too), computed from the server's prices: at £3.99 / £38 that is
   * 20.6% → 20, at £9.99 / £99 17.4% → 17. A single "save 20%" for both
   * overstated Sovereign (audit A-24 / A-34); the toggle says "up to" the
   * largest.
   */
  yearlySavingPct: number | null;
  /** The currency of this tier's prices, for the "Prices in …" line. */
  currency: string;
  features: string[];
}

/** "50 GB monthly bandwidth" / "Unlimited bandwidth", from the plan's own cap. */
function bandwidthFeature(p: PlanPrice): string {
  return p.bandwidthLimitGb === null ? 'Unlimited bandwidth' : `${p.bandwidthLimitGb} GB monthly bandwidth`;
}

/** A plan's price fields for its card. Free means both prices are zero. */
function priced(p: PlanPrice): Pick<Tier, 'free' | 'monthly' | 'yearly' | 'yearlySavingPct' | 'currency'> {
  const free = p.monthlyPrice === 0 && p.yearlyPrice === 0;
  return {
    free,
    // MR-2030: a price of 0 is "not offered for that period", never "£0".
    monthly: p.monthlyPrice > 0 ? formatPrice(p.monthlyPrice, p.currency) : null,
    yearly: p.yearlyPrice > 0 ? formatPrice(p.yearlyPrice, p.currency) : null,
    yearlySavingPct: free ? null : yearlySavingPct(p),
    currency: p.currency,
  };
}

/** A data cap as a number to compare: unlimited is more than any cap. */
const capOf = (p: PlanPrice) => p.bandwidthLimitGb ?? Number.POSITIVE_INFINITY;

/** The gated features, in the order the cards list them, with their lines. */
const GATED_LINES: readonly [GatedFeature, string][] = [
  ['stealthMode', 'Stealth mode'],
  ['multiHop', 'Multi-hop routing'],
  ['portForwarding', 'Port forwarding'],
];

/** The tier below each paid one, which its "Everything in …" line names. */
const LOWER: Partial<Record<PlanId, PlanId>> = { OPERATIVE: 'RECON', SOVEREIGN: 'OPERATIVE' };

/**
 * MR-2030: whether `id` has everything the tier below it has, as far as the
 * plan data says (its cap, and every gated feature): only then may its card
 * say "Everything in …". Otherwise the card lists what it has itself.
 */
function includesTierBelow(id: PlanId, prices: Record<PlanId, PlanPrice>, gates: Partial<Record<PlanId, PlanGates>>): boolean {
  const lower = LOWER[id];
  if (!lower) return false;
  return (
    capOf(prices[id]) >= capOf(prices[lower]) &&
    GATED_LINES.every(([f]) => !planHasFeature(lower, gates, f) || planHasFeature(id, gates, f) === true)
  );
}

/**
 * The gated features `id`'s card sells (MR-1517): each on the lowest plan the
 * gating table gives it to, and, on a card that cannot say "Everything in …",
 * every one the plan has.
 */
function gatedLines(id: PlanId, claimsLower: boolean, gates: Partial<Record<PlanId, PlanGates>>): string[] {
  return GATED_LINES.filter(([f]) =>
    claimsLower ? lowestPlanWith(f, gates) === id : planHasFeature(id, gates, f) === true,
  ).map(([, line]) => line);
}

/**
 * MR-2030: the line under the title, from the plans' caps. It used to say
 * "unlimited bandwidth" whatever the server priced.
 */
function upgradeIntro(prices: Record<PlanId, PlanPrice>): string {
  const paid = [prices.OPERATIVE, prices.SOVEREIGN];
  const bandwidth = paid.every((p) => p.bandwidthLimitGb === null)
    ? prices.RECON.bandwidthLimitGb === null
      ? null
      : 'unlimited bandwidth'
    : paid.every((p) => capOf(p) > capOf(prices.RECON))
      ? 'more bandwidth'
      : null;
  const what = bandwidth
    ? `${bandwidth}, every server location and more devices`
    : 'every server location and more devices';
  return `Upgrade for ${what}. Billing is managed securely on the web.`;
}

function buildTiers(prices: Record<PlanId, PlanPrice>, gates: Partial<Record<PlanId, PlanGates>>): Tier[] {
  const operativeClaims = includesTierBelow('OPERATIVE', prices, gates);
  const sovereignClaims = includesTierBelow('SOVEREIGN', prices, gates);
  return [
    {
      id: 'RECON',
      name: 'Recon',
      tagline: 'Free — get protected',
      icon: Shield,
      iconTint: white.w60,
      ...priced(prices.RECON),
      // No "Split tunneling": the desktop app has none (vpn/mod.rs — Windows
      // only has Kill Switch Exceptions, which keep traffic IN the tunnel), so
      // listing it here sold a feature that does not exist (audit A-24 / D-4).
      // Wording follows the mobile paywalls (second-pass #16). Custom DNS is
      // on EVERY plan (owner decision D6, 2026-10-01), so it is listed here, on
      // the free tier, and the paid tiers have it through "Everything in Recon";
      // listing it on a paid card would sell it as an upgrade.
      features: [
        '1 device connection',
        'Core server locations',
        bandwidthFeature(prices.RECON),
        'WireGuard® encryption',
        'Post-quantum key exchange',
        'Kill switch',
        'Custom DNS servers',
        ...gatedLines('RECON', false, gates),
      ],
    },
    {
      id: 'OPERATIVE',
      name: 'Operative',
      tagline: 'For everyday privacy',
      icon: Zap,
      iconTint: brand.accent,
      ...priced(prices.OPERATIVE),
      // Second-pass #16: no "High-speed servers" line. A node's isHighSpeed is an
      // owner-set display flag (the server list's filter), and no plan gates on
      // it: access is decided by the node's minPlan alone, which "All server
      // locations" already describes. The Recon plan can use a fast node too.
      features: [
        ...(operativeClaims ? ['Everything in Recon'] : []),
        '5 device connections',
        'All server locations',
        bandwidthFeature(prices.OPERATIVE),
        ...gatedLines('OPERATIVE', operativeClaims, gates),
      ],
    },
    {
      id: 'SOVEREIGN',
      name: 'Sovereign',
      tagline: 'Full control',
      icon: Crown,
      iconTint: brand.accentLight,
      ...priced(prices.SOVEREIGN),
      // Second-pass #16: no "Priority servers" line (nothing is prioritised: the
      // backend's isPremium is just minPlan !== 'RECON', and whether any node
      // is Sovereign-only is a per-node owner setting, not a plan feature), and
      // no "Custom DNS": it is on every plan (D6, listed on Recon above).
      // MR-2030: "Everything in Operative" only while the data says so, and
      // its own cap whenever it differs from Operative's (it used to inherit
      // Operative's line, whatever the server priced).
      features: [
        ...(sovereignClaims ? ['Everything in Operative'] : []),
        '10 device connections',
        ...(!sovereignClaims || capOf(prices.SOVEREIGN) !== capOf(prices.OPERATIVE)
          ? [bandwidthFeature(prices.SOVEREIGN)]
          : []),
        ...gatedLines('SOVEREIGN', sovereignClaims, gates),
      ],
    },
  ];
}

export function Pricing() {
  const { account, popRoute, planPrices, planGates } = useAppStore(
    useShallow((s) => ({
      account: s.account,
      popRoute: s.popRoute,
      planPrices: s.planPrices,
      planGates: s.planGates,
    })),
  );
  const prices = useMemo(() => resolvePlanPrices(planPrices), [planPrices]);
  const tiers = useMemo(() => buildTiers(prices, planGates ?? {}), [prices, planGates]);
  // "Save up to N%" is the largest per-plan saving, so it never overstates.
  const maxSavingPct = Math.max(0, ...tiers.map((t) => t.yearlySavingPct ?? 0));
  const currencies = [...new Set(tiers.filter((t) => !t.free).map((t) => t.currency))];
  // `null` while the plan is not known yet: no tier is marked current and no
  // Upgrade button is offered to someone who may already be on it (W2-011).
  const currentPlan = account.plan === null ? null : normalizePlan(account.plan);
  // Default to yearly (matches mobile) so the discounted annual price leads.
  const [period, setPeriod] = useState<BillingPeriod>('yearly');

  const openBilling = () => openExternal(BILLING_URL).catch(() => {});

  return (
    // Transparent so the App-level PixelCanvas backdrop shows through (matches
    // VpnSettings.tsx, the other pushed sub-screen).
    <div className="flex h-full flex-col">
      <BirdoTopBar title="Plans & Pricing" onBack={popRoute} />

      <div className="flex-1 overflow-y-auto px-4 pb-8 pt-3">
        <p className="px-1 text-[13px]" style={{ color: white.w60 }}>
          {upgradeIntro(prices)}
        </p>

        {/* Monthly / Yearly segmented toggle — mirrors the segmented control
            style used by Settings' window-position picker. */}
        <div
          className="mt-4 grid grid-cols-2 gap-1 rounded-birdo-sm p-1"
          style={{ backgroundColor: white.w05 }}
        >
          {(['monthly', 'yearly'] as const).map((p) => {
            const active = period === p;
            return (
              <button
                key={p}
                type="button"
                onClick={() => setPeriod(p)}
                aria-pressed={active}
                className="flex items-center justify-center gap-1.5 rounded-birdo-xs px-3 py-2 text-[13px] font-medium transition-all"
                style={{
                  backgroundColor: active ? brand.accentBg : 'transparent',
                  border: active ? `1px solid ${brand.accent}` : '1px solid transparent',
                  color: active ? brand.accentSoft : white.w60,
                }}
              >
                {p === 'monthly' ? 'Monthly' : 'Yearly'}
                {p === 'yearly' && maxSavingPct > 0 && (
                  <span
                    className="rounded-full px-1.5 py-0.5 text-[10px] font-semibold"
                    style={{ backgroundColor: accentA(0.14), color: brand.accentSoft }}
                  >
                    {`Save up to ${maxSavingPct}%`}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Tier cards */}
        <div className="mt-4 flex flex-col gap-3">
          {tiers.map((tier) => (
            <TierCard
              key={tier.id}
              tier={tier}
              period={period}
              currentPlan={currentPlan}
              onUpgrade={openBilling}
            />
          ))}
        </div>

        {/* VAT wording per REMEDIATION-DECISIONS §3: checkout is Polar's
            (merchant of record), whose tax behaviour decides the total. */}
        <p className="mt-5 px-1 text-xs" style={{ color: white.w60 }}>
          {currencies.length > 0 && `Prices in ${currencies.join(' and ')}. `}
          Prices include VAT for customers in the UK, EU and most
          other countries. In the United States, Canada and India, sales tax is
          added at checkout. Polar, our reseller, shows the final total before
          you pay. Upgrading opens dashboard.birdo.app in your browser to
          complete checkout — payments are never taken inside the app.
        </p>
      </div>
    </div>
  );
}

interface TierCardProps {
  tier: Tier;
  period: BillingPeriod;
  currentPlan: PlanId | null;
  onUpgrade: () => void;
}

function TierCard({ tier, period, currentPlan, onUpgrade }: TierCardProps) {
  const Icon = tier.icon;
  const isFree = tier.free;
  const tRank = PLAN_RANK[tier.id];
  const cRank = currentPlan === null ? null : PLAN_RANK[currentPlan];
  const isCurrent = cRank !== null && tRank === cRank;
  const isUpgrade = cRank !== null && tRank > cRank;

  // MR-2030: a paid tier not offered for the chosen period (a price of 0)
  // shows the period it is offered for, never "£0". A paid tier has at least
  // one price, so the `?? ''` (lint runs at --max-warnings 0, which a non-null
  // assertion would trip) is never reached.
  const showYearly = period === 'yearly' ? tier.yearly !== null : tier.monthly === null;
  const priceAmount = isFree ? 'Free' : (showYearly ? tier.yearly : tier.monthly) ?? '';
  const priceSuffix = isFree ? null : showYearly ? '/yr' : '/mo';

  return (
    <BirdoCard
      cornerRadius={20}
      padding="18px"
      // Highlight the user's current plan with an emerald outline instead of the
      // default glass hairline.
      glassBorder={!isCurrent}
      style={
        isCurrent
          ? { border: `1px solid ${accentA(0.5)}`, backgroundColor: surface.s1 }
          : undefined
      }
    >
      {/* Header: icon + name/tagline (+ Current badge) */}
      <div className="flex items-center gap-3.5">
        <div
          className="flex h-11 w-11 shrink-0 items-center justify-center rounded-birdo-md"
          style={{ backgroundColor: white.w05 }}
        >
          <Icon size={20} color={tier.iconTint} aria-hidden />
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="text-[16px] font-semibold" style={{ color: '#FFFFFF' }}>
              {tier.name}
            </span>
            {isCurrent && <BirdoBadge text="Current" tone="brand" />}
          </div>
          <div className="truncate text-[12px]" style={{ color: white.w60 }}>
            {tier.tagline}
          </div>
        </div>
      </div>

      {/* Price */}
      <div className="mt-4 flex items-baseline gap-1.5">
        <span className="text-[26px] font-bold" style={{ color: '#FFFFFF' }}>
          {priceAmount}
        </span>
        {priceSuffix && (
          <span className="text-[13px]" style={{ color: white.w60 }}>
            {priceSuffix}
          </span>
        )}
      </div>
      {!isFree && showYearly && tier.yearlySavingPct !== null && (
        <div className="mt-1 text-[12px]" style={{ color: brand.accentSoft }}>
          Save {tier.yearlySavingPct}% vs paying monthly
        </div>
      )}

      <div className="my-4 h-px" style={{ backgroundColor: hairline.soft }} />

      {/* Features */}
      <ul className="flex flex-col gap-2.5">
        {tier.features.map((feature) => (
          <li key={feature} className="flex items-start gap-2.5">
            <Check size={16} color={brand.accent} aria-hidden className="mt-0.5 shrink-0" />
            <span className="text-[13px]" style={{ color: white.w80 }}>
              {feature}
            </span>
          </li>
        ))}
      </ul>

      {/* CTA */}
      <div className="mt-5">
        {isCurrent ? (
          <div
            className="flex h-12 items-center justify-center gap-2 rounded-birdo-md text-[14px] font-semibold"
            style={{
              backgroundColor: brand.accentBg,
              border: `1px solid ${accentA(0.35)}`,
              color: brand.accentSoft,
            }}
          >
            <Check size={16} aria-hidden />
            Current plan
          </div>
        ) : cRank === null ? (
          <div
            className="flex h-12 items-center justify-center rounded-birdo-md text-[13px] font-medium"
            style={{ backgroundColor: white.w05, color: white.w60 }}
            aria-busy="true"
          >
            Checking your plan…
          </div>
        ) : isUpgrade ? (
          <BirdoButton
            text="Upgrade"
            variant="primary"
            fullWidth
            icon={ExternalLink}
            onClick={onUpgrade}
          />
        ) : (
          // A lower paid tier while the user is already on a higher plan.
          <div
            className="flex h-12 items-center justify-center rounded-birdo-md text-[13px] font-medium"
            style={{ backgroundColor: white.w05, color: white.w60 }}
          >
            Included in your plan
          </div>
        )}
      </div>
    </BirdoCard>
  );
}
