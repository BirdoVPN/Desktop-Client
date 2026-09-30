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
