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
 */
import { useState } from 'react';
import { open as openExternal } from '@tauri-apps/plugin-shell';
import { useShallow } from 'zustand/react/shallow';
import type { LucideIcon } from 'lucide-react';
import { Check, Shield, Zap, Crown, ExternalLink } from 'lucide-react';
import { BirdoTopBar, BirdoCard, BirdoButton, BirdoBadge } from '@/components/birdo';
import { useAppStore } from '@/store/app-store';
import { brand, white, hairline, surface, accentA } from '@/lib/birdo-theme';
import { PLAN_RANK, normalizePlan, type PlanId } from '@/lib/plan';
import { BILLING_URL } from '@/lib/links';

// Billing lives on the web (the same host Settings opens for "Manage on web").

type BillingPeriod = 'monthly' | 'yearly';

interface Tier {
  id: PlanId;
  name: string;
  tagline: string;
  icon: LucideIcon;
  iconTint: string;
  /** Displayed prices, or null for the free tier. */
  monthly: string | null;
  yearly: string | null;
  /**
   * Yearly saving vs 12 monthly payments, per plan and rounded DOWN (the web
   * floors it too): Operative £38 vs £47.88 = 20.6%, Sovereign £99 vs £119.88
   * = 17.4%. A single "save 20%" for both overstated Sovereign (audit A-24 /
   * A-34); the toggle says "up to 20%".
   */
  yearlySavingPct: number | null;
  features: string[];
}

const TIERS: Tier[] = [
  {
    id: 'RECON',
    name: 'Recon',
    tagline: 'Free — get protected',
    icon: Shield,
    iconTint: white.w60,
    monthly: null,
    yearly: null,
    yearlySavingPct: null,
    // No "Split tunneling": the desktop app has none (vpn/mod.rs — Windows
    // only has Kill Switch Exceptions, which keep traffic IN the tunnel), so
    // listing it here sold a feature that does not exist (audit A-24 / D-4).
    // Wording follows the mobile paywalls (second-pass #16).
    features: [
      '1 device connection',
      'Core server locations',
      '10 GB monthly bandwidth',
      'WireGuard® encryption',
      'Post-quantum key exchange',
      'Kill switch',
    ],
  },
  {
    id: 'OPERATIVE',
    name: 'Operative',
    tagline: 'For everyday privacy',
    icon: Zap,
    iconTint: brand.accent,
    monthly: '£3.99',
    yearly: '£38',
    yearlySavingPct: 20,
    // Second-pass #16: no "High-speed servers" line. A node's isHighSpeed is an
    // owner-set display flag (the server list's filter), and no plan gates on
    // it: access is decided by the node's minPlan alone, which "All server
    // locations" already describes. The Recon plan can use a fast node too.
    features: [
      'Everything in Recon',
      '5 device connections',
      'All server locations',
      'Unlimited bandwidth',
      'Stealth mode',
    ],
  },
  {
    id: 'SOVEREIGN',
    name: 'Sovereign',
    tagline: 'Full control',
    icon: Crown,
    iconTint: brand.accentLight,
    monthly: '£9.99',
    yearly: '£99',
    yearlySavingPct: 17,
    // Second-pass #16: no "Priority servers" line (nothing is prioritised: the
    // backend's isPremium is just minPlan !== 'RECON', and whether any node
    // is Sovereign-only is a per-node owner setting, not a plan feature), and
    // no "Custom DNS" either: mobile sells it as Sovereign-only, but the
    // desktop does not gate it by plan (Settings), so listing it here would
    // misstate what the free and Operative plans get on desktop. Whether it
    // should be gated everywhere is an owner decision.
    features: [
      'Everything in Operative',
      '10 device connections',
      'Multi-hop routing',
      'Port forwarding',
    ],
  },
];

export function Pricing() {
  const { account, popRoute } = useAppStore(
    useShallow((s) => ({ account: s.account, popRoute: s.popRoute })),
  );
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
          Upgrade for unlimited bandwidth, every server location and more devices. Billing is
          managed securely on the web.
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
                {p === 'yearly' && (
                  <span
                    className="rounded-full px-1.5 py-0.5 text-[10px] font-semibold"
                    style={{ backgroundColor: accentA(0.14), color: brand.accentSoft }}
                  >
                    Save up to 20%
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Tier cards */}
        <div className="mt-4 flex flex-col gap-3">
          {TIERS.map((tier) => (
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
          Prices in GBP. Prices include VAT for customers in the UK, EU and most
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
  const isFree = tier.monthly === null;
  const tRank = PLAN_RANK[tier.id];
  const cRank = currentPlan === null ? null : PLAN_RANK[currentPlan];
  const isCurrent = cRank !== null && tRank === cRank;
  const isUpgrade = cRank !== null && tRank > cRank;

  // `?? ''` keeps this non-null-assertion-free (eslint no-non-null-assertion is
  // a warning, and lint runs at --max-warnings 0). For a paid tier both prices
  // are non-null, so the fallback is never actually reached.
  const priceAmount = isFree
    ? 'Free'
    : (period === 'monthly' ? tier.monthly : tier.yearly) ?? '';
  const priceSuffix = isFree ? null : period === 'monthly' ? '/mo' : '/yr';

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
      {!isFree && period === 'yearly' && tier.yearlySavingPct !== null && (
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
