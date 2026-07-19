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

// Billing lives on the web (the same host Settings.tsx opens for "Manage on
// web"). `DASHBOARD_URL` is a module-local const in Settings.tsx (not exported),
// so — per the task's guidance — we replicate the same constant and the same
// `open`-from-plugin-shell helper here rather than hardcode a bare URL inline.
const DASHBOARD_URL = 'https://dashboard.birdo.app';

type PlanId = 'RECON' | 'OPERATIVE' | 'SOVEREIGN';
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
    features: [
      '1 device',
      'Limited server locations',
      '10 GB / month data cap',
      'WireGuard + post-quantum (BirdoPQ)',
      'Kill switch',
      'Split tunneling',
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
    features: [
      'Everything in Recon',
      'Unlimited bandwidth',
      'All standard servers',
      'High-speed servers',
      'Stealth (Xray Reality) DPI-evasion',
      'Up to 5 devices',
    ],
  },
  {
    id: 'SOVEREIGN',
    name: 'Sovereign',
    tagline: 'Maximum privacy & control',
    icon: Crown,
    iconTint: brand.accentLight,
    monthly: '£9.99',
    yearly: '£99',
    features: [
      'Everything in Operative',
      'Multi-Hop (double VPN)',
      'Port forwarding',
      'Priority servers',
      'Up to 10 devices',
    ],
  },
];

const PLAN_RANK: Record<PlanId, number> = { RECON: 0, OPERATIVE: 1, SOVEREIGN: 2 };

/** Normalize the store's free-form plan string to a known tier (null → RECON). */
function normalizePlan(plan: string | null | undefined): PlanId {
  const p = (plan ?? '').toUpperCase();
  return p === 'OPERATIVE' || p === 'SOVEREIGN' ? p : 'RECON';
}

export function Pricing() {
  const { account, popRoute } = useAppStore(
    useShallow((s) => ({ account: s.account, popRoute: s.popRoute })),
  );
  const currentPlan = normalizePlan(account.plan);
  // Default to yearly (matches mobile) so the discounted annual price leads.
  const [period, setPeriod] = useState<BillingPeriod>('yearly');

  const openBilling = () => openExternal(`${DASHBOARD_URL}/billing`);

  return (
    // Transparent so the App-level PixelCanvas backdrop shows through (matches
    // VpnSettings.tsx, the other pushed sub-screen).
    <div className="flex h-full flex-col">
      <BirdoTopBar title="Plans & Pricing" onBack={popRoute} />

      <div className="flex-1 overflow-y-auto px-4 pb-8 pt-3">
        <p className="px-1 text-[13px]" style={{ color: white.w60 }}>
          Upgrade for unlimited bandwidth, premium servers and advanced privacy
          features. Billing is managed securely on the web.
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
                    Save ~2 months
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

        <p className="mt-5 px-1 text-xs" style={{ color: white.w40 }}>
          Prices in GBP. Upgrading opens dashboard.birdo.app in your browser to
          complete checkout — payments are never taken inside the app.
        </p>
      </div>
    </div>
  );
}

interface TierCardProps {
  tier: Tier;
  period: BillingPeriod;
  currentPlan: PlanId;
  onUpgrade: () => void;
}

function TierCard({ tier, period, currentPlan, onUpgrade }: TierCardProps) {
  const Icon = tier.icon;
  const isFree = tier.monthly === null;
  const tRank = PLAN_RANK[tier.id];
  const cRank = PLAN_RANK[currentPlan];
  const isCurrent = tRank === cRank;
  const isUpgrade = tRank > cRank;

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
      {!isFree && period === 'yearly' && (
        <div className="mt-1 text-[12px]" style={{ color: brand.accentSoft }}>
          Save ~2 months vs paying monthly
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
