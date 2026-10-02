/**
 * Birdo design tokens.
 *
 * REFERENCE: `iosApp/iosApp/Theme/BirdoTheme.swift` (mobile repo), which
 * Android's Color.kt / Brand.kt match value for value. All three clients are
 * one emerald product now; the old note here ("mobile is still violet — do not
 * copy colours across") predates the mobile rebrand and was the reason the
 * Windows connected-green, idle CTA and Operative colour drifted (P1-parity-005).
 * When a value changes, change it on iOS/Android too.
 *
 * THE GREEN BUDGET (iOS's hard rule): the brand is green, so connection state
 * is separated by LUMINANCE, not hue. The idle Connect button is DEEP emerald
 * (`gradient.connectIdle`); connected is luminous mint (`status.green`) with a
 * glow. Never brighten the idle button to brand green. The globe's idle server
 * dots stay BLUE so green on the globe keeps meaning "connected to this node".
 *
 * Corporate and restrained (owner direction): the only gradients left are
 * two stops of ONE hue, exactly as iOS has them. No multi-colour gradients.
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

// ── Brand stops (emerald) ────────────────────────────────────────────────
export const brand = {
  accentDeep: '#047857', // emerald-700
  accentMid: '#059669', // emerald-600
  accent: '#10B981', // emerald-500 — the brand primary
  accentLight: '#34D399', // emerald-400
  accentSoft: '#6EE7B7', // emerald-300 — accent text on dark
  accentBg: 'rgba(16,185,129,0.10)', // accent fill / brand badge bg
  teal: '#14B8A6', // Operative identity
  slate: '#64748B', // Free (Recon) identity
} as const;

/**
 * Accent rgba at an arbitrary alpha. Every accent tint in the app goes through
 * this so the brand colour lives in exactly one place.
 */
export const accentA = (alpha: number): string => `rgba(16,185,129,${alpha})`;

// ── Status colors (muted: green good / amber warning / red danger) ────────
export const status = {
  green: '#34D399', // "luminous mint" — CONNECTED only
  greenLight: '#6EE7B7',
  greenBg: 'rgba(52,211,153,0.10)',
  greenShadow: 'rgba(52,211,153,0.30)',
  yellow: '#EAB308',
  yellowLight: '#FACC15',
  yellowBg: 'rgba(234,179,8,0.10)',
  red: '#F87171',
  redBg: 'rgba(248,113,113,0.10)',
  redBorder: 'rgba(248,113,113,0.30)',
  blue: '#3B82F6',
  blueBg: 'rgba(59,130,246,0.10)',
} as const;

// ── White-scale alphas ───────────────────────────────────────────────────
// w40 is BELOW WCAG AA (~3.4:1 on #050507) — it is for decorative icons and
// dividers only. Any text must use w55 or brighter; `ContrastGuard.test.ts`
// fails the build on a text use of w40.
export const white = {
  w100: '#F2F2F2',
  w80: 'rgba(255,255,255,0.80)',
  w60: 'rgba(255,255,255,0.60)',
  w55: 'rgba(255,255,255,0.55)', // caption tier — smallest AA-passing text
  w40: 'rgba(255,255,255,0.40)', // decorative only (fails AA for text)
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

const linear = (from: string, to: string) => `linear-gradient(135deg, ${from} 0%, ${to} 100%)`;

// ── Brushes (CSS strings; iOS `BirdoTheme.Gradients`) ────────────────────
export const gradient = {
  /** Primary brand fill — DEEP emerald (the green budget). */
  primary: linear('#047857', '#064E3B'),
  /** Glass card stroke — silver-to-transparent border. */
  glassStroke:
    'linear-gradient(135deg, rgba(255,255,255,0.18) 0%, rgba(255,255,255,0.04) 50%, rgba(255,255,255,0.12) 100%)',
  /** Headline text — white to 55% white, one hue. */
  headlineText: 'linear-gradient(180deg, #FFFFFF 0%, rgba(255,255,255,0.55) 100%)',

  // ── Connect button states (iOS connectIdle / Busy / Connected / MultiHop) ──
  connectIdle: linear('#047857', '#064E3B'),
  connectBusy: linear('#6EE7B7', '#047857'),
  connectGreen: linear('#34D399', '#059669'),
  connectMultiHop: linear('#10B981', '#047857'),
} as const;

/** Plan chip / avatar fills — iOS `planSovereign` / `planOperative` / `planRecon`. */
export const PLAN_GRADIENT = {
  SOVEREIGN: linear('#059669', '#064E3B'),
  OPERATIVE: linear('#0D9488', '#115E59'),
  RECON: linear('#475569', '#334155'),
} as const;

// ── Motion timings (iOS BirdoTheme.Motion / Android BirdoMotion.kt) ───────
export const motion = {
  instant: 0.09, // 90ms
  fast: 0.16, // Quick (160ms)
  standard: 0.24, // 240ms
  emphasis: 0.36, // 360ms
  slow: 0.52, // 520ms — was 0.36 here while iOS said 0.52 (W2-034)
  ease: [0.2, 0.0, 0.0, 1.0] as [number, number, number, number], // EaseStandard
  easeOut: [0.0, 0.0, 0.2, 1.0] as [number, number, number, number],
  accel: [0.3, 0.0, 0.8, 0.15] as [number, number, number, number],
  decel: [0.05, 0.7, 0.1, 1.0] as [number, number, number, number],
  spring: [0.34, 1.56, 0.64, 1.0] as [number, number, number, number], // overshoot
} as const;
