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
  black: '#000000', // Pure black (BirdoBlack) — window gutters
  s0: '#050507', // App background
  s1: '#0B0B10', // Cards
  s2: '#12121A', // Raised cards
  s3: '#1A1A24', // Modals / popovers
  cardGlass: 'rgba(20,20,25,0.70)', // BirdoCard glass fill
} as const;

// ── Brand stops ───────────────────────────────────────────────────────────
export const brand = {
  purpleDeep: '#6D28D9', // violet-700
  purpleMid: '#7C3AED', // violet-600 (BirdoPurpleDark)
  purple: '#A855F7',
  purpleLight: '#C084FC', // violet-300 (BirdoPurpleLight)
  purpleSoft: '#C4B5FD', // violet-300 (Brand.PurpleSoft)
  purpleBg: 'rgba(168,85,247,0.10)', // accent fill / brand badge bg
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
  emerald: '#10B981', // update UI accent
  emeraldBg: 'rgba(16,185,129,0.10)',
} as const;

// ── Primary button (solid white / black text) ─────────────────────────────
export const primary = {
  bg: '#FFFFFF', // BirdoPrimary
  fg: '#000000', // BirdoOnPrimary
} as const;

// ── White-scale alphas ───────────────────────────────────────────────────
export const white = {
  w100: '#F2F2F2',
  w80: 'rgba(255,255,255,0.80)',
  w60: 'rgba(255,255,255,0.60)',
  w40: 'rgba(255,255,255,0.40)',
  w20: 'rgba(255,255,255,0.20)',
  w10: 'rgba(255,255,255,0.10)',
  w06: 'rgba(255,255,255,0.06)', // GlassStrong — secondary btn / topbar bg
  w05: 'rgba(255,255,255,0.05)',
  w04: 'rgba(255,255,255,0.04)', // GlassInput — text field fill
  w03: 'rgba(255,255,255,0.03)',
} as const;

// ── Dim-light theme (mobile's "light" = dark slate, NOT white) ────────────
// Mirrors mobile Color.kt:67-76,135. Applied under the `.light` class.
export const lightSurface = {
  s0: '#1B1C24', // app bg
  s1: '#22232C', // cards
  s2: '#2A2B36', // raised cards / inputs
  s3: '#2F3040', // modals / sheet
  onBackground: '#E8E9F0', // body text
  onSurfaceVariant: '#B7B9C9', // secondary text
  onSurfaceFaint: '#7A7C8E', // faint text
  outline: 'rgba(255,255,255,0.20)', // strong border
  outlineSoft: 'rgba(255,255,255,0.10)', // soft divider
  primary: '#B794F6', // softer violet accent
  accentBg: 'rgba(168,85,247,0.16)', // accent fill
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
  /** Connect button gradient (multi-hop ready). */
  connectMultiHop: `linear-gradient(135deg, ${brand.purple} 0%, ${brand.purpleDeep} 100%)`,
} as const;

// ── Motion timings (mirrors mobile's BirdoMotion.kt) ─────────────────────
export const motion = {
  instant: 0.09, // 90ms
  fast: 0.16, // Quick (160ms) — was 0.15
  standard: 0.24, // 240ms
  emphasis: 0.36, // 360ms
  slow: 0.36,
  slow520: 0.52, // 520ms
  ease: [0.2, 0.0, 0.0, 1.0] as [number, number, number, number], // EaseStandard
  easeOut: [0.0, 0.0, 0.2, 1.0] as [number, number, number, number],
  accel: [0.3, 0.0, 0.8, 0.15] as [number, number, number, number],
  decel: [0.05, 0.7, 0.1, 1.0] as [number, number, number, number],
  spring: [0.34, 1.56, 0.64, 1.0] as [number, number, number, number], // overshoot
} as const;

// ── Radii ────────────────────────────────────────────────────────────────
// NOTE: existing sm/md/lg/xl kept at their current values (consumed by current
// primitives). Mobile's Compose scale (6/10/14/18/24) is added as explicit
// keys so components can target the exact mobile radius without re-valuing.
export const radius = {
  sm: 8,
  md: 12,
  lg: 16,
  xl: 20,
  pill: 9999,
  // Mobile Compose scale (Shapes.kt)
  xs6: 6,
  sm10: 10,
  md14: 14, // button / server card
  lg18: 18,
  xl24: 24, // bottom panel top / sheet
  card16: 16, // BirdoCard default
  sub12: 12, // sub-card / stat / text field / flag badge
} as const;
