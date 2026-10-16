/**
 * MR-1517: the app gates Stealth, Multi-Hop and Port Forwarding by the
 * server's plan-gating table (`GET /api/client-config` → `features.<PLAN>`),
 * and by its own copy of the decided table only where the server said nothing.
 *
 * Run: npx vitest run src/lib/plan.test.ts
 */
import { describe, it, expect } from 'vitest';
import { FEATURE_MIN_PLAN, lowestPlanWith, planHasFeature } from './plan';

describe('planHasFeature (MR-1517)', () => {
  it('without a server table: the decided one (Stealth from Operative, Multi-Hop and Port Forwarding on Sovereign)', () => {
    expect(FEATURE_MIN_PLAN).toEqual({ stealthMode: 'OPERATIVE', multiHop: 'SOVEREIGN', portForwarding: 'SOVEREIGN' });
    expect(planHasFeature('RECON', {}, 'stealthMode')).toBe(false);
    expect(planHasFeature('OPERATIVE', {}, 'stealthMode')).toBe(true);
    expect(planHasFeature('OPERATIVE', undefined, 'multiHop')).toBe(false);
    expect(planHasFeature('SOVEREIGN', {}, 'multiHop')).toBe(true);
    expect(planHasFeature('sovereign', {}, 'portForwarding')).toBe(true);
  });

  it("the server's flag for the user's plan wins, either way", () => {
    expect(planHasFeature('OPERATIVE', { OPERATIVE: { multiHop: true } }, 'multiHop')).toBe(true);
    expect(planHasFeature('OPERATIVE', { OPERATIVE: { stealthMode: false } }, 'stealthMode')).toBe(false);
    // Another plan's flag says nothing about this one.
    expect(planHasFeature('OPERATIVE', { SOVEREIGN: { stealthMode: false } }, 'stealthMode')).toBe(true);
  });

  it('a plan not known yet is null (no lock, no upsell); an unknown slug reads no server flag', () => {
    expect(planHasFeature(null, {}, 'multiHop')).toBeNull();
    expect(planHasFeature(undefined, { RECON: { stealthMode: true } }, 'stealthMode')).toBeNull();
    expect(planHasFeature('ENTERPRISE', { RECON: { stealthMode: true } }, 'stealthMode')).toBe(false);
  });

  it('lowestPlanWith names the plan each feature comes with', () => {
    expect(lowestPlanWith('stealthMode', {})).toBe('OPERATIVE');
    expect(lowestPlanWith('multiHop', {})).toBe('SOVEREIGN');
    expect(lowestPlanWith('stealthMode', { RECON: { stealthMode: true } })).toBe('RECON');
    expect(lowestPlanWith('stealthMode', { OPERATIVE: { stealthMode: false } })).toBe('SOVEREIGN');
    expect(lowestPlanWith('multiHop', { SOVEREIGN: { multiHop: false } })).toBeNull();
  });
});
