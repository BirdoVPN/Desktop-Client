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
