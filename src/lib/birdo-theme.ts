/**
 * Birdo design tokens — mirrors mobile's `Color.kt` / `Brand.kt` / `Theme.kt`
 * so the desktop client renders the exact same palette + gradients.
 *
 * If you change a value here, also update the matching token in:
 *   birdo-client-mobile/app/src/main/java/app/birdo/vpn/ui/theme/Color.kt
 *   birdo-client-mobile/app/src/main/java/app/birdo/vpn/ui/theme/Brand.kt
 */

// ── Surface elevation tiers (dark) ───────────────────────────────────────
export const surface = {
  s0: '#050507', // App background
  s1: '#0B0B10', // Cards
  s2: '#12121A', // Raised cards
  s3: '#1A1A24', // Modals / popovers
} as const;

// ── Brand stops ───────────────────────────────────────────────────────────
export const brand = {
  purpleDeep: '#6D28D9', // violet-700
  purple: '#A855F7',
  purpleSoft: '#C4B5FD', // violet-300
  pink: '#EC4899',
  cyan: '#22D3EE',
  teal: '#14B8A6',
  indigo: '#6366F1',
} as const;

// ── Status colors ─────────────────────────────────────────────────────────
export const status = {
  green: '#22C55E',
  greenLight: '#4ADE80',
  greenBg: 'rgba(34,197,94,0.10)',
  greenShadow: 'rgba(34,197,94,0.30)',
  yellow: '#EAB308',
  yellowLight: '#FACC15',
  yellowBg: 'rgba(234,179,8,0.10)',
  red: '#F87171',
  redBg: 'rgba(248,113,113,0.10)',
  blue: '#3B82F6',
  blueBg: 'rgba(59,130,246,0.10)',
} as const;

// ── White-scale alphas ───────────────────────────────────────────────────
export const white = {
  w100: '#F2F2F2',
  w80: 'rgba(255,255,255,0.80)',
  w60: 'rgba(255,255,255,0.60)',
  w40: 'rgba(255,255,255,0.40)',
  w20: 'rgba(255,255,255,0.20)',
  w10: 'rgba(255,255,255,0.10)',
  w05: 'rgba(255,255,255,0.05)',
  w03: 'rgba(255,255,255,0.03)',
} as const;

// ── Hairlines (borders / dividers) ───────────────────────────────────────
export const hairline = {
  strong: 'rgba(255,255,255,0.12)',
  soft: 'rgba(255,255,255,0.08)',
} as const;

// ── Brushes / gradients (CSS strings) ────────────────────────────────────
export const gradient = {
  /** Primary brand fill — restrained deep-purple matching the app icon. */
  primary: 'linear-gradient(135deg, #7C3AED 0%, #4C1D95 100%)',
  /** Cool secondary — info / tech accents. */
  info: `linear-gradient(135deg, ${brand.indigo} 0%, ${brand.cyan} 100%)`,
  /** Connected (green disc → transparent). */
  connected: `radial-gradient(circle, rgba(34,197,94,0.28) 0%, transparent 70%)`,
  /** Idle ambient (purple bloom). */
  idle: `radial-gradient(circle, rgba(168,85,247,0.18) 0%, transparent 70%)`,
  /** Error halo. */
  error: `radial-gradient(circle, rgba(248,113,113,0.25) 0%, transparent 70%)`,
  /** Glass card stroke — silver-to-transparent border. */
  glassStroke:
    'linear-gradient(135deg, rgba(255,255,255,0.18) 0%, rgba(255,255,255,0.04) 50%, rgba(255,255,255,0.12) 100%)',
  /** Headline text gradient — white → soft white. */
  headlineText:
    'linear-gradient(180deg, #FFFFFF 0%, rgba(255,255,255,0.55) 100%)',
  /** Brand text gradient — purple → pink for accent words. */
  brandText: `linear-gradient(135deg, ${brand.purpleSoft} 0%, ${brand.pink} 100%)`,
  /** Connect button gradient (idle). */
  connectIdle: 'linear-gradient(135deg, #7C3AED 0%, #4C1D95 100%)',
  /** Connect button gradient (busy). */
  connectBusy: `linear-gradient(135deg, ${brand.purpleSoft} 0%, ${brand.purpleDeep} 100%)`,
  /** Connect button gradient (connected). */
  connectGreen: `linear-gradient(135deg, ${status.green} 0%, #166534 100%)`,
} as const;

// ── Motion timings (mirrors mobile's BirdoMotion) ────────────────────────
export const motion = {
  fast: 0.15,
  standard: 0.24,
  slow: 0.36,
  ease: [0.2, 0.0, 0.0, 1.0] as [number, number, number, number],
  easeOut: [0.0, 0.0, 0.2, 1.0] as [number, number, number, number],
} as const;

// ── Radii ────────────────────────────────────────────────────────────────
export const radius = {
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  pill: 9999,
} as const;
