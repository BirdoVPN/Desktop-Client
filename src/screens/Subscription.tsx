/**
 * Subscription — read-only / web-deep-link plan screen.
 *
 * Pixel-faithful port of mobile's `SubscriptionScreen.kt`:
 *   • Pushed sub-screen → BirdoTopBar "Subscription" + back (popRoute) and a
 *     "Manage on Web" BirdoIconAction.
 *   • CurrentPlanHero — driven by the store's `account` (plan/status/expiresAt)
 *     and refreshed via invoke('get_subscription_status') for live device /
 *     bandwidth counters.
 *   • Monthly / Yearly billing toggle.
 *   • Three PlanCards: Recon (free) / Operative (POPULAR) / Sovereign, each with
 *     a feature list and price. The CURRENT plan hides its Upgrade button and
 *     RECON never shows one.
 *
 * This screen makes NO tunnel calls. Upgrades open the web checkout in the
 * user's default browser via the shell plugin (matches MultiHopCard's pattern).
 */
import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open as openExternal } from '@tauri-apps/plugin-shell';
import { useShallow } from 'zustand/react/shallow';
import { Globe, Check, Crown, ShieldCheck } from 'lucide-react';
import { useAppStore } from '@/store/app-store';
import {
  BirdoTopBar,
  BirdoIconAction,
  BirdoCard,
  BirdoButton,
  BirdoBadge,
} from '@/components/birdo';
import { white, brand, status, surface } from '@/lib/birdo-theme';
import { formatBytes } from '@/utils/helpers';

// ── Web entry points (match existing desktop conventions) ─────────────────
const MANAGE_URL = 'https://dashboard.birdo.app';
const upgradeUrl = (planId: string, period: string) =>
  `https://birdo.app/account?plan=${planId.toLowerCase()}&period=${period}#upgrade`;

type BillingPeriod = 'monthly' | 'yearly';

interface PlanInfo {
  id: string;
  name: string;
  tagline: string;
  priceMonthly: string;
  priceYearly: string;
  features: string[];
  /** Accent token used for the popular border + badge + feature ticks. */
  accent: string;
  isPopular?: boolean;
}

// Mirrors lib/plans intent + mobile's `plans` list: free Recon, £3.99/mo
// Operative (popular), £9.99/mo Sovereign. Yearly = ~20% saving.
const PLANS: PlanInfo[] = [
  {
    id: 'RECON',
    name: 'Recon',
    tagline: 'Test the waters',
    priceMonthly: 'Free',
    priceYearly: 'Free',
    features: [
      '1 device connection',
      '2 server locations',
      '10 GB monthly bandwidth',
      'WireGuard® encryption',
      'Post-quantum encryption',
      'Kill switch',
      'DNS leak protection',
    ],
    accent: white.w40,
  },
  {
    id: 'OPERATIVE',
    name: 'Operative',
    tagline: 'Most popular',
    priceMonthly: '£3.99/mo',
    priceYearly: '£38/yr',
    features: [
      '5 device connections',
      'All server locations',
      'Unlimited bandwidth',
      'WireGuard® encryption',
      'Post-quantum encryption',
      'Kill switch',
      'Split tunneling',
      'Stealth mode',
      'Speed test',
      '2FA / TOTP',
      'Biometric lock',
      'Priority support',
    ],
    accent: brand.purple,
    isPopular: true,
  },
  {
    id: 'SOVEREIGN',
    name: 'Sovereign',
    tagline: 'Full control',
    priceMonthly: '£9.99/mo',
    priceYearly: '£99/yr',
    features: [
      '10 device connections',
      'All server locations',
      'Unlimited bandwidth',
      'WireGuard® encryption',
      'Post-quantum encryption',
      'Kill switch',
      'Split tunneling',
      'Stealth mode',
      'Multi-hop routing',
      'Port forwarding',
      'Speed test',
      '2FA / TOTP',
      'Biometric lock',
      'Custom DNS',
      'Priority support',
    ],
    accent: status.yellowLight,
  },
];

const planAccent = (plan: string | null | undefined): string => {
  switch (plan?.toUpperCase()) {
    case 'SOVEREIGN':
      return status.yellowLight;
    case 'OPERATIVE':
      return brand.purple;
    default:
      return white.w60;
  }
};

// Live counters from get_subscription_status (snake_case — DO NOT change).
interface RustSubscription {
  plan: string;
  status: string;
  expires_at: string | null;
  devices_used: number;
  devices_limit: number;
  bandwidth_limit: number | null;
}

export function Subscription() {
  const { popRoute, account } = useAppStore(
    useShallow((s) => ({ popRoute: s.popRoute, account: s.account }))
  );

  const [billingPeriod, setBillingPeriod] = useState<BillingPeriod>('yearly');
  const [live, setLive] = useState<RustSubscription | null>(null);

  // Refresh live device / bandwidth counters for the hero. Read-only.
  useEffect(() => {
    invoke<RustSubscription>('get_subscription_status')
      .then(setLive)
      .catch(() => {
        /* silent — hero falls back to store account */
      });
  }, []);

  const currentPlan = (account.plan ?? '').toUpperCase();
  const hasSubscription = currentPlan.length > 0;

  return (
    <div className="flex h-full flex-col">
      <BirdoTopBar
        title="Subscription"
        onBack={popRoute}
        actions={
          <BirdoIconAction
            icon={Globe}
            contentDescription="Manage on Web"
            onClick={() => {
              openExternal(MANAGE_URL).catch((err) => {
                console.error('Failed to open Manage URL:', err);
              });
            }}
            tint={white.w60}
          />
        }
      />

      <div className="flex-1 overflow-y-auto px-4 pb-8 pt-4">
        {hasSubscription && (
          <div className="mb-5">
            <CurrentPlanHero account={account} live={live} />
          </div>
        )}

        <h2
          className="mb-2.5 pl-1 text-[15px] font-bold"
          style={{ color: white.w80 }}
        >
          Choose a plan
        </h2>

        {/* Billing period toggle */}
        <div
          role="tablist"
          aria-label="Billing period"
          className="flex w-full gap-1 rounded-birdo-sub p-1"
          style={{ backgroundColor: surface.s2 }}
        >
          {(
            [
              { key: 'monthly', label: 'Monthly' },
              { key: 'yearly', label: 'Yearly · Save 20%' },
            ] as const
          ).map(({ key, label }) => {
            const active = billingPeriod === key;
            return (
              <button
                key={key}
                type="button"
                role="tab"
                aria-selected={active}
                onClick={() => setBillingPeriod(key)}
                className="flex-1 rounded-birdo-sm py-2.5 text-center text-[13px] transition-colors"
                style={{
                  backgroundColor: active ? '#FFFFFF' : 'transparent',
                  color: active ? '#000000' : white.w60,
                  fontWeight: active ? 700 : 400,
                }}
              >
                {label}
              </button>
            );
          })}
        </div>

        {/* Plan cards */}
        <div className="mt-4 flex flex-col gap-3">
          {PLANS.map((plan) => {
            const isCurrent = currentPlan === plan.id;
            const price =
              billingPeriod === 'yearly' ? plan.priceYearly : plan.priceMonthly;
            return (
              <PlanCard
                key={plan.id}
                plan={plan}
                isCurrent={isCurrent}
                price={price}
                onSelect={() => {
                  openExternal(upgradeUrl(plan.id, billingPeriod)).catch(
                    (err) => {
                      console.error('Failed to open upgrade URL:', err);
                    }
                  );
                }}
              />
            );
          })}
        </div>

        {/* Footer — purchases are managed on the web. */}
        <p
          className="mt-4 px-2 text-center text-xs"
          style={{ color: white.w40 }}
        >
          Subscriptions are purchased and managed on birdo.app. Have a voucher
          code? Redeem it on the Profile tab.
        </p>
      </div>
    </div>
  );
}

// ── Current plan hero ──────────────────────────────────────────────────────

function CurrentPlanHero({
  account,
  live,
}: {
  account: ReturnType<typeof useAppStore.getState>['account'];
  live: RustSubscription | null;
}) {
  const plan = (account.plan ?? 'RECON').toUpperCase();
  const isActive =
    account.status === 'active' || live?.status?.toLowerCase() === 'active';
  const accent = planAccent(plan);

  const devicesUsed = live?.devices_used ?? account.activeDevices;
  const devicesLimit = live?.devices_limit ?? account.maxDevices;
  const bandwidthLimit =
    live?.bandwidth_limit ?? (account.bandwidthLimit || null);
  const isPremium = plan !== 'RECON';

  return (
    <BirdoCard cornerRadius={18} surfaceColor={surface.s1} padding="18px">
      <div className="flex items-center gap-3.5">
        <div
          className="flex h-11 w-11 shrink-0 items-center justify-center rounded-birdo-sub"
          style={{ backgroundColor: `${accent}26` }}
        >
          <Crown size={24} color={accent} aria-hidden />
        </div>
        <div className="min-w-0 flex-1">
          <div
            className="truncate text-[16px] font-bold"
            style={{ color: '#FFFFFF' }}
          >
            {plan}
          </div>
          <div
            className="truncate text-xs"
            style={{ color: isActive ? status.green : white.w40 }}
          >
            {isActive ? 'Active subscription' : 'Inactive'}
          </div>
        </div>
        <BirdoBadge
          text={isActive ? 'ACTIVE' : 'INACTIVE'}
          tone={isActive ? 'success' : 'neutral'}
        />
      </div>

      <div className="mt-3.5 flex w-full">
        <MetricCell label="DEVICES" value={`${devicesUsed}/${devicesLimit}`} />
        <MetricCell
          label="BANDWIDTH"
          value={
            bandwidthLimit && bandwidthLimit > 0
              ? formatBytes(bandwidthLimit)
              : 'Unlimited'
          }
        />
        <MetricCell label="PREMIUM" value={isPremium ? 'Yes' : 'No'} />
      </div>
    </BirdoCard>
  );
}

function MetricCell({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex-1">
      <div
        className="text-[10px] font-semibold tracking-[1px]"
        style={{ color: white.w40 }}
      >
        {label}
      </div>
      <div
        className="mt-0.5 text-sm font-bold"
        style={{ color: '#FFFFFF' }}
      >
        {value}
      </div>
    </div>
  );
}

// ── Plan card ──────────────────────────────────────────────────────────────

function PlanCard({
  plan,
  isCurrent,
  price,
  onSelect,
}: {
  plan: PlanInfo;
  isCurrent: boolean;
  price: string;
  onSelect: () => void;
}) {
  const showUpgrade = !isCurrent && plan.id !== 'RECON';

  return (
    <BirdoCard
      cornerRadius={16}
      surfaceColor={surface.s1}
      glassBorder={!plan.isPopular}
      padding="20px"
      style={
        plan.isPopular
          ? { border: `1px solid ${plan.accent}` }
          : undefined
      }
    >
      <div className="flex items-start">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span
              className="text-[16px] font-bold"
              style={{ color: white.w80 }}
            >
              {plan.name}
            </span>
            {plan.isPopular && (
              <span
                className="rounded-birdo-xs px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide"
                style={{ backgroundColor: `${plan.accent}26`, color: plan.accent }}
              >
                Popular
              </span>
            )}
            {isCurrent && (
              <span
                className="rounded-birdo-xs px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide"
                style={{ backgroundColor: status.greenBg, color: status.green }}
              >
                Current
              </span>
            )}
          </div>
          <div className="mt-0.5 text-xs" style={{ color: white.w40 }}>
            {plan.tagline}
          </div>
        </div>
        <div
          className="text-[20px] font-bold"
          style={{ color: plan.id === 'RECON' ? white.w60 : '#FFFFFF' }}
        >
          {price}
        </div>
      </div>

      <ul className="mt-4 flex flex-col gap-1.5">
        {plan.features.map((feature) => (
          <li key={feature} className="flex items-center gap-2.5">
            <Check size={16} color={plan.accent} aria-hidden className="shrink-0" />
            <span className="text-[13px]" style={{ color: white.w60 }}>
              {feature}
            </span>
          </li>
        ))}
      </ul>

      {showUpgrade && (
        <div className="mt-4">
          <BirdoButton
            text={`Upgrade to ${plan.name}`}
            onClick={onSelect}
            variant={plan.isPopular ? 'primary' : 'secondary'}
            icon={ShieldCheck}
            fullWidth
          />
        </div>
      )}
    </BirdoCard>
  );
}

export default Subscription;
