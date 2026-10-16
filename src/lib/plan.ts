/**
 * Plan identity in one place. The rank used to be written four times
 * (Dashboard, VpnSettings, Pricing, Profile) and every copy mapped an unknown
 * plan to Recon, so a paying user whose subscription fetch was slow or failed
 * saw locks and upsells for features they own (W2-011, W2-038).
 */
import { PLAN_GRADIENT } from '@/lib/birdo-theme';

export type PlanId = 'RECON' | 'OPERATIVE' | 'SOVEREIGN';

export const PLAN_RANK: Record<PlanId, number> = { RECON: 0, OPERATIVE: 1, SOVEREIGN: 2 };

/** `null` means NOT KNOWN YET — never "free". Callers must not upsell on null. */
export function planRank(plan: string | null | undefined): number | null {
  if (plan == null) return null;
  const p = plan.toUpperCase();
  return p === 'SOVEREIGN' ? 2 : p === 'OPERATIVE' ? 1 : 0;
}

/** A known plan normalised to a tier; an unrecognised slug is treated as the free tier. */
export function normalizePlan(plan: string): PlanId {
  const p = plan.toUpperCase();
  return p === 'OPERATIVE' || p === 'SOVEREIGN' ? p : 'RECON';
}

/**
 * One of the three plan ids, or `null` for a slug this build does not know.
 * Unlike `normalizePlan`, an unknown slug is NOT folded into the free tier:
 * a per-plan server flag must never be read for the wrong plan.
 */
export function knownPlanId(plan: string): PlanId | null {
  const p = plan.toUpperCase();
  return p === 'RECON' || p === 'OPERATIVE' || p === 'SOVEREIGN' ? p : null;
}

/**
 * Whether Custom DNS may be used on this plan (Account API contract item 40,
 * `features.<PLAN>.customDns`). It is on every plan (owner decision D6): only
 * an explicit `false` for the user's own, known plan turns it off. An unknown
 * or not-yet-loaded plan, a plan the server said nothing about, or no answer
 * at all is ENABLED.
 */
export function customDnsAvailable(
  plan: string | null | undefined,
  byPlan: Partial<Record<PlanId, boolean>>,
): boolean {
  const id = plan == null ? null : knownPlanId(plan);
  return id === null || byPlan[id] !== false;
}

/** The features a plan gates (MR-1517), as `features.<PLAN>` names them. */
export type GatedFeature = 'stealthMode' | 'multiHop' | 'portForwarding';

/** One plan's gating flags from `GET /api/client-config` → `features.<PLAN>`. */
export type PlanGates = Partial<Record<GatedFeature, boolean>>;

/**
 * MR-1517: the plan-gating table the owner decided on 2026-10-07 (Stealth from
 * OPERATIVE; Multi-Hop and Port Forwarding on SOVEREIGN), the lowest plan with
 * each feature. The SERVER's table (`features.<PLAN>`, birdo-web
 * app/api/client-config/route.ts, the same rules its `planAllows` enforces)
 * wins wherever it gave a flag; this is what a plan or feature it said nothing
 * about falls back to (an older deploy, no network, a failed fetch).
 */
export const FEATURE_MIN_PLAN: Readonly<Record<GatedFeature, PlanId>> = {
  stealthMode: 'OPERATIVE',
  multiHop: 'SOVEREIGN',
  portForwarding: 'SOVEREIGN',
};

const PLAN_IDS: readonly PlanId[] = ['RECON', 'OPERATIVE', 'SOVEREIGN'];

/**
 * Whether `plan` has `feature` (MR-1517): the server's flag for that plan when
 * it sent one, else `FEATURE_MIN_PLAN`. `null` while the plan is not known yet
 * (no lock, no upsell: W2-011). An unknown plan slug reads no server flag (one
 * plan's flag is never read for another) and ranks as the free tier.
 */
export function planHasFeature(
  plan: string | null | undefined,
  gates: Partial<Record<PlanId, PlanGates>> | undefined,
  feature: GatedFeature,
): boolean | null {
  const rank = planRank(plan);
  if (plan == null || rank === null) return null;
  const id = knownPlanId(plan);
  const said = id === null ? undefined : gates?.[id]?.[feature];
  if (typeof said === 'boolean') return said;
  return rank >= PLAN_RANK[FEATURE_MIN_PLAN[feature]];
}

/** The lowest plan that has `feature`, by `planHasFeature`; `null` if none does. */
export function lowestPlanWith(
  feature: GatedFeature,
  gates: Partial<Record<PlanId, PlanGates>> | undefined,
): PlanId | null {
  return PLAN_IDS.find((id) => planHasFeature(id, gates, feature) === true) ?? null;
}

/**
 * One plan's prices and data cap, as `GET /api/client-config` → `plans.<PLAN>`
 * serves them (birdo-web #708) and the Rust side validates them.
 */
export interface PlanPrice {
  /** The price of one month, billed monthly. */
  monthlyPrice: number;
  /** The ANNUAL TOTAL, billed once a year (38, not 3.17). */
  yearlyPrice: number;
  /** ISO 4217 code of both prices. */
  currency: string;
  /** Data cap per billing period in GB; `null` = unlimited. */
  bandwidthLimitGb: number | null;
}

/**
 * OFFLINE FALLBACK for the Pricing screen (MR-132 / MR-630 / MR-1767 /
 * MR-1979): what a plan shows when the server has not priced it — an older web
 * deploy without `plans`, no network, a failed fetch, or a plan missing from
 * or malformed in the map. The server's values win whenever it sends them.
 * These mirror birdo-web's lib/plans.ts as of #708, with the free cap at
 * 50 GB (owner decision 2026-10-13; it was 10 GB).
 */
export const FALLBACK_PLAN_PRICES: Readonly<Record<PlanId, PlanPrice>> = {
  RECON: { monthlyPrice: 0, yearlyPrice: 0, currency: 'GBP', bandwidthLimitGb: 50 },
  OPERATIVE: { monthlyPrice: 3.99, yearlyPrice: 38, currency: 'GBP', bandwidthLimitGb: null },
  SOVEREIGN: { monthlyPrice: 9.99, yearlyPrice: 99, currency: 'GBP', bandwidthLimitGb: null },
};

/** The largest data cap believed, in GB — Rust's `MAX_PLAN_BANDWIDTH_GB`. */
const MAX_PLAN_BANDWIDTH_GB = 100_000;

const price = (v: unknown): v is number => typeof v === 'number' && Number.isFinite(v) && v >= 0;

/**
 * The same rules as Rust's `PlanPrice::from_wire`, so a value that reached the
 * store some other way (a test, a future caller) cannot render as NaN or make
 * `Intl.NumberFormat` throw.
 */
export function isPlanPrice(v: unknown): v is PlanPrice {
  if (typeof v !== 'object' || v === null) return false;
  const p = v as Record<string, unknown>;
  const cap = p.bandwidthLimitGb;
  return (
    price(p.monthlyPrice) &&
    price(p.yearlyPrice) &&
    typeof p.currency === 'string' &&
    /^[A-Z]{3}$/.test(p.currency) &&
    (cap === null ||
      (typeof cap === 'number' && Number.isInteger(cap) && cap > 0 && cap <= MAX_PLAN_BANDWIDTH_GB))
  );
}

/** Every plan's prices: the server's where it gave a valid entry, else the fallback. */
export function resolvePlanPrices(server: Partial<Record<PlanId, PlanPrice>>): Record<PlanId, PlanPrice> {
  const pick = (id: PlanId) => {
    const p = server[id];
    return isPlanPrice(p) ? p : FALLBACK_PLAN_PRICES[id];
  };
  return { RECON: pick('RECON'), OPERATIVE: pick('OPERATIVE'), SOVEREIGN: pick('SOVEREIGN') };
}

/**
 * "£3.99", "£38", "€9.99": the amount in its own currency, en-GB style. A
 * whole amount drops its ".00" so the yearly totals read as they always have.
 */
export function formatPrice(amount: number, currency: string): string {
  const whole = Number.isInteger(amount);
  try {
    return new Intl.NumberFormat('en-GB', {
      style: 'currency',
      currency,
      ...(whole ? { minimumFractionDigits: 0, maximumFractionDigits: 0 } : {}),
    }).format(amount);
  } catch {
    return `${whole ? amount : amount.toFixed(2)} ${currency}`;
  }
}

/**
 * Whole percent saved by paying yearly instead of 12 monthly payments,
 * FLOORED so it never overstates — the formula birdo-web's /pricing uses
 * (lib/pricing-data.ts `pricingFor`). `null` when there is no saving to show.
 */
export function yearlySavingPct(p: PlanPrice): number | null {
  const undiscounted = p.monthlyPrice * 12;
  if (undiscounted <= 0 || p.yearlyPrice <= 0) return null;
  const pct = Math.floor(((undiscounted - p.yearlyPrice) / undiscounted) * 100);
  return pct > 0 ? pct : null;
}

/** "Free", "Operative", "Sovereign" — the prose names (P1-parity casing rules). */
export function planName(plan: string): string {
  switch (normalizePlan(plan)) {
    case 'SOVEREIGN':
      return 'Sovereign';
    case 'OPERATIVE':
      return 'Operative';
    default:
      return 'Free';
  }
}

/** 'OPERATIVE' -> 'Operative'. For a node's `minPlan`, which is a slug, not a tier we own. */
export function titleCasePlan(plan: string): string {
  return plan.charAt(0).toUpperCase() + plan.slice(1).toLowerCase();
}

export function planGradient(plan: string): string {
  return PLAN_GRADIENT[normalizePlan(plan)];
}
