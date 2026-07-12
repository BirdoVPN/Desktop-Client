/**
 * Birdo design tokens.
 *
 * COLOR DIVERGENCE (2026-07 brand pivot, web #201): desktop is EMERALD; mobile's
 * Color.kt / Brand.kt are still violet until the mobile rebrand round lands. The
 * structure, motion and radius scales below still mirror mobile — only the accent
 * family diverges. Do NOT copy colour values across the two clients until mobile
 * is rebranded.
 *
 * GREEN BUDGET. Emerald is the brand accent, but green already means "connected"
 * in this app, so the two must never be confusable:
 *   - `status.green` (#22C55E) is reserved for CONNECTED surfaces (the connect
 *     button fill, the Protected pill, the tray icon). It is the only opaque
 *     green fill in the UI.
 *   - `brand.*` emerald is for chrome accents only (tabs, switches, focus rings,
 *     outlines, badges). The idle connect button is neutral glass with an emerald
 *     OUTLINE — never an emerald fill.
 *   - The globe's idle server dots are BLUE, not emerald, so the globe keeps its
 *     own connected-vs-idle signal (see WorldGlobe.tsx).
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

// ── Brand stops (emerald — shade-for-shade with web #201) ─────────────────
export const brand = {
  accentDeep: '#047857', // emerald-700
  accentMid: '#059669', // emerald-600
  accent: '#10B981', // emerald-500 — the brand primary
  accentLight: '#34D399', // emerald-400
  accentSoft: '#6EE7B7', // emerald-300 — accent text on dark
  accentBg: 'rgba(16,185,129,0.10)', // accent fill / brand badge bg
  pink: '#EC4899',
  cyan: '#22D3EE',
  teal: '#14B8A6',
  indigo: '#6366F1',
} as const;

/**
 * Accent rgba at an arbitrary alpha. Every accent tint in the app goes through
 * this so the brand colour lives in exactly one place (the swap to emerald left
 * ~25 hardcoded `rgba(168,85,247,…)` literals scattered across components).
 */
export const accentA = (alpha: number): string => `rgba(16,185,129,${alpha})`;

/** Shared focus treatment — border + ring + bloom, one definition. */
export const focus = {
  border: accentA(0.55),
  ring: accentA(0.16),
  bloom: accentA(0.45),
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
// w40 is BELOW WCAG AA (~3.4:1 on #050507) — it is for decorative icons and
// dividers only. Any text under 14px must use w55 or brighter.
export const white = {
  w100: '#F2F2F2',
  w80: 'rgba(255,255,255,0.80)',
  w60: 'rgba(255,255,255,0.60)',
  w55: 'rgba(255,255,255,0.55)', // caption tier — smallest AA-passing text
  w40: 'rgba(255,255,255,0.40)', // decorative only (fails AA for small text)
  w20: 'rgba(255,255,255,0.20)',
  w10: 'rgba(255,255,255,0.10)',
  w06: 'rgba(255,255,255,0.06)', // GlassStrong — secondary btn / topbar bg
  w05: 'rgba(255,255,255,0.05)',
  w04: 'rgba(255,255,255,0.04)', // GlassInput — text field fill
  w03: 'rgba(255,255,255,0.03)',
} as const;

// ── Hairlines (borders / dividers) ───────────────────────────────────────
export const hairline = {
  strong: 'rgba(255,255,255,0.12)',
  soft: 'rgba(255,255,255,0.08)',
} as const;

// ── Brushes / gradients (CSS strings) ────────────────────────────────────
export const gradient = {
  /** Primary brand fill — emerald CTA (Login / Consent / Split-Tunnel apply). */
  primary: 'linear-gradient(135deg, #059669 0%, #064E3B 100%)',
  /** Cool secondary — info / tech accents. */
  info: `linear-gradient(135deg, ${brand.indigo} 0%, ${brand.cyan} 100%)`,
  /** Connected (green disc → transparent). */
  connected: `radial-gradient(circle, rgba(34,197,94,0.28) 0%, transparent 70%)`,
  /** Idle ambient — BLUE, never emerald (green must stay = connected). */
  idle: `radial-gradient(circle, rgba(59,130,246,0.14) 0%, transparent 70%)`,
  /** Error halo. */
  error: `radial-gradient(circle, rgba(248,113,113,0.25) 0%, transparent 70%)`,
  /** Glass card stroke — silver-to-transparent border. */
  glassStroke:
    'linear-gradient(135deg, rgba(255,255,255,0.18) 0%, rgba(255,255,255,0.04) 50%, rgba(255,255,255,0.12) 100%)',
  /** Headline text gradient — white → soft white. */
  headlineText:
    'linear-gradient(180deg, #FFFFFF 0%, rgba(255,255,255,0.55) 100%)',
  /** Brand text gradient — emerald → cyan for accent words. */
  brandText: `linear-gradient(135deg, ${brand.accentSoft} 0%, ${brand.cyan} 100%)`,

  // ── Connect button states ──────────────────────────────────────────────
  // These four must be instantly distinguishable at a glance. Only `connectGreen`
  // is an opaque green fill; idle is neutral glass (emerald shows in the border
  // only), busy is a translucent emerald wash behind a spinner, and multi-hop is
  // teal — a different hue from both the idle glass and the connected green.
  /** Idle — neutral glass. The emerald lives in the BORDER, not the fill. */
  connectIdle:
    'linear-gradient(135deg, rgba(255,255,255,0.10) 0%, rgba(255,255,255,0.04) 100%)',
  /** Busy — translucent emerald wash (never mistakable for the connected fill). */
  connectBusy:
    'linear-gradient(135deg, rgba(110,231,183,0.22) 0%, rgba(4,120,87,0.30) 100%)',
  /** Connected — the ONE opaque green fill in the app. */
  connectGreen: `linear-gradient(135deg, ${status.green} 0%, #166534 100%)`,
  /** Multi-hop ready — teal, hue-separated from connected green. */
  connectMultiHop: `linear-gradient(135deg, #0D9488 0%, #115E59 100%)`,
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
