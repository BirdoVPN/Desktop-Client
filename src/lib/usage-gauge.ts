/**
 * The Limit tab's speed-dial gauge: its geometry and the figures around it.
 *
 * REFERENCE: Android `LimitScreen.kt` (`SpeedDialGauge`, `gaugeColor`,
 * `gaugeValue`, `gbFigure`) and iOS `LimitView.swift`, which draw the same
 * dial: a 232 x 232 box, a 270° arc starting at 135° (so the gap is at the
 * bottom), an 18 px round-capped stroke, and a knob riding the arc (a 13 px
 * coloured ring round a 5.5 px surface-coloured core). Angles follow the
 * screen convention both platforms use: 0° points right and positive angles
 * turn clockwise, because y grows downwards — which is SVG's convention too.
 *
 * Pure, so the maths is tested without a renderer.
 */

export const GAUGE_SIZE = 232;
export const GAUGE_STROKE = 18;
export const GAUGE_KNOB_OUTER = 13;
export const GAUGE_KNOB_INNER = 5.5;
export const GAUGE_START_DEG = 135;
export const GAUGE_SWEEP_DEG = 270;

/**
 * The knob is the widest thing riding the arc: inset for it (plus 2 px) so
 * nothing clips at the edges and the arc stays optically centred.
 */
export const GAUGE_INSET = Math.max(GAUGE_STROKE / 2, GAUGE_KNOB_OUTER) + 2;
export const GAUGE_RADIUS = (GAUGE_SIZE - GAUGE_INSET * 2) / 2;
export const GAUGE_CENTER = GAUGE_SIZE / 2;

/**
 * True when the plan has a monthly cap. `/vpn/stats` sends `null` (or 0) for
 * an uncapped plan or an active reward window: that is "Unlimited", never a
 * "0 GB" dial.
 */
export function hasDataCap(limitGb: number | null | undefined): limitGb is number {
  return typeof limitGb === 'number' && Number.isFinite(limitGb) && limitGb > 0;
}

/** Share of the cap used, 0–1. Over the cap reads 1; no cap reads 0. */
export function usageFraction(usedGb: number | null | undefined, limitGb: number | null | undefined): number {
  if (!hasDataCap(limitGb)) return 0;
  const used = typeof usedGb === 'number' && Number.isFinite(usedGb) ? usedGb : 0;
  return Math.min(Math.max(used / limitGb, 0), 1);
}

export type GaugeTone = 'accent' | 'yellow' | 'red';

/** Accent below 75 %, yellow from 75 %, red from 90 % (Android `gaugeColor`). */
export function gaugeTone(fraction: number): GaugeTone {
  if (fraction >= 0.9) return 'red';
  if (fraction >= 0.75) return 'yellow';
  return 'accent';
}

/** "0%" … "100%": the readout in the gap at the bottom of the dial. */
export function gaugePercent(fraction: number): string {
  return `${Math.round(Math.min(Math.max(fraction, 0), 1) * 100)}%`;
}

const toRad = (deg: number) => (deg * Math.PI) / 180;

/** How far round the arc the knob sits, in degrees (0 at empty, 270 at full). */
export function gaugeSweepDeg(fraction: number): number {
  return GAUGE_SWEEP_DEG * Math.min(Math.max(fraction, 0), 1);
}

/** A point on the dial's centre line at `fraction` of the sweep. */
export function pointOnDial(fraction: number): { x: number; y: number } {
  const a = toRad(GAUGE_START_DEG + gaugeSweepDeg(fraction));
  return { x: GAUGE_CENTER + Math.cos(a) * GAUGE_RADIUS, y: GAUGE_CENTER + Math.sin(a) * GAUGE_RADIUS };
}

/**
 * The progress stroke's dash offset. The arc is drawn with pathLength 1 and
 * dashes "1 2", so an offset of 1 - fraction leaves exactly the used share
 * drawn from the start (the 2-long gap keeps the next dash off the arc).
 */
export function gaugeFillDashOffset(fraction: number): number {
  return 1 - Math.min(Math.max(fraction, 0), 1);
}

/**
 * How far inside the arc's ends the knob's dot is held, as a share of the arc
 * (about half a pixel on the 232 dial). A zero-length dash at exactly 0 or 1
 * can round off the path, and the knob vanished at 100 % at 1x scale.
 */
export const GAUGE_KNOB_END_INSET = 0.001;

/**
 * The knob's dash offset. The knob is the arc again with dashes "0 2" and a
 * round cap — a single dot — and this offset puts that dot at `fraction` of
 * the sweep, so it moves along the arc in step with the fill.
 */
export function gaugeKnobDashOffset(fraction: number): number {
  return -Math.min(Math.max(fraction, GAUGE_KNOB_END_INSET), 1 - GAUGE_KNOB_END_INSET);
}

const fixed = (n: number) => Number(n.toFixed(3));

/**
 * The whole 270° arc as an SVG path, start to end, clockwise. It is both the
 * track and (dashed to the used share) the progress stroke.
 */
export function dialArcPath(): string {
  const from = pointOnDial(0);
  const to = pointOnDial(1);
  // Large-arc flag 1 (270° > 180°), sweep flag 1 (clockwise on screen).
  return `M ${fixed(from.x)} ${fixed(from.y)} A ${GAUGE_RADIUS} ${GAUGE_RADIUS} 0 1 1 ${fixed(to.x)} ${fixed(to.y)}`;
}

/**
 * Kotlin's `Double.toString` after rounding to `places`: trailing zeros go but
 * one decimal stays ("4.00" → "4.0", "0.50" → "0.5"), as the dial and the
 * stat cells read on Android and iOS (`trimmedDecimal`).
 */
function kotlinDecimal(value: number, places: number): string {
  const scale = 10 ** places;
  const rounded = Math.round(value * scale) / scale;
  const text = rounded.toFixed(places).replace(/0+$/, '');
  return text.endsWith('.') ? `${text}0` : text;
}

const safeGb = (gb: number) => (Number.isFinite(gb) ? Math.max(0, gb) : 0);

/** Big dial number: "0.52", "1.7", "10" — the unit lives in the line below. */
export function gaugeValue(gb: number): string {
  const safe = safeGb(gb);
  if (safe >= 10) return String(Math.round(safe));
  if (safe >= 1) return kotlinDecimal(safe, 1);
  return kotlinDecimal(safe, 2);
}

/** "0.52 GB", "7.1 GB", "12 GB": the Used / Left cells. */
export function formatGbFigure(gb: number): string {
  const safe = safeGb(gb);
  return `${safe >= 10 ? String(Math.round(safe)) : kotlinDecimal(safe, 2)} GB`;
}

/** "50", not "50.0", for the allowance pill and the upgrade copy. */
export function wholeGb(gb: number): string {
  return Number.isInteger(gb) ? String(gb) : gb.toFixed(1);
}
