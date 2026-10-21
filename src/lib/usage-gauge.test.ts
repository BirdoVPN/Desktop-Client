/**
 * The Limit tab's speed-dial gauge maths (owner 2026-10-21: the Limit tab as
 * on mobile, with the speedometer gauge). The dial is Android LimitScreen.kt's
 * SpeedDialGauge: 232 box, 270° from 135°, 18 stroke, 13 / 5.5 knob.
 *
 * Run: npx vitest run src/lib/usage-gauge.test.ts
 */
import { describe, it, expect } from 'vitest';
import {
  GAUGE_CENTER,
  GAUGE_INSET,
  GAUGE_RADIUS,
  dialArcPath,
  GAUGE_KNOB_END_INSET,
  formatGbFigure,
  gaugeFillDashOffset,
  gaugeKnobDashOffset,
  gaugePercent,
  gaugeSweepDeg,
  gaugeTone,
  gaugeValue,
  hasDataCap,
  pointOnDial,
  usageFraction,
  wholeGb,
} from './usage-gauge';

const near = (p: { x: number; y: number }, x: number, y: number) => {
  expect(p.x).toBeCloseTo(x, 6);
  expect(p.y).toBeCloseTo(y, 6);
};
// cos 45° · r: how far the arc's ends sit from the centre on each axis.
const D = Math.SQRT1_2 * GAUGE_RADIUS;

describe('dial geometry (Android SpeedDialGauge)', () => {
  it('insets for the knob, so the arc is centred in the 232 box', () => {
    expect(GAUGE_INSET).toBe(15);
    expect(GAUGE_RADIUS).toBe(101);
    expect(GAUGE_CENTER).toBe(116);
  });

  it('the arc runs 270° clockwise from bottom-left to bottom-right, the gap at the bottom', () => {
    expect(dialArcPath()).toBe(
      `M ${Number((116 - D).toFixed(3))} ${Number((116 + D).toFixed(3))} A 101 101 0 1 1 ${Number(
        (116 + D).toFixed(3),
      )} ${Number((116 + D).toFixed(3))}`,
    );
  });
});

describe('usage on the dial', () => {
  it('0 %: empty dial, knob at the start (bottom-left), accent', () => {
    const f = usageFraction(0, 50);
    expect(f).toBe(0);
    expect(gaugePercent(f)).toBe('0%');
    expect(gaugeSweepDeg(f)).toBe(0);
    near(pointOnDial(f), 116 - D, 116 + D);
    expect(gaugeTone(f)).toBe('accent');
    // Nothing of the fill is drawn; the knob's dot sits just inside the start.
    expect(gaugeFillDashOffset(f)).toBe(1);
    expect(gaugeKnobDashOffset(f)).toBe(-GAUGE_KNOB_END_INSET);
  });

  it('50 %: knob at the top of the dial, 135° round', () => {
    const f = usageFraction(25, 50);
    expect(f).toBe(0.5);
    expect(gaugePercent(f)).toBe('50%');
    expect(gaugeSweepDeg(f)).toBe(135);
    near(pointOnDial(f), 116, 116 - 101);
    expect(gaugeTone(f)).toBe('accent');
    expect(gaugeFillDashOffset(f)).toBe(0.5);
    expect(gaugeKnobDashOffset(f)).toBe(-0.5);
  });

  it('100 %: full dial, knob at the end (bottom-right), red', () => {
    const f = usageFraction(50, 50);
    expect(f).toBe(1);
    expect(gaugePercent(f)).toBe('100%');
    expect(gaugeSweepDeg(f)).toBe(270);
    near(pointOnDial(f), 116 + D, 116 + D);
    expect(gaugeTone(f)).toBe('red');
    // All of the fill; the knob's dot just inside the end, where a dash at
    // exactly 1 could round off the path.
    expect(gaugeFillDashOffset(f)).toBe(0);
    expect(gaugeKnobDashOffset(f)).toBe(-(1 - GAUGE_KNOB_END_INSET));
  });

  it('over the cap: the dial stops at 100 % and nothing is left', () => {
    const f = usageFraction(63.4, 50);
    expect(f).toBe(1);
    expect(gaugePercent(f)).toBe('100%');
    near(pointOnDial(f), 116 + D, 116 + D);
    expect(gaugeTone(f)).toBe('red');
    expect(gaugeFillDashOffset(63.4 / 50)).toBe(0);
    expect(gaugeKnobDashOffset(63.4 / 50)).toBe(-(1 - GAUGE_KNOB_END_INSET));
    expect(formatGbFigure(50 - 63.4)).toBe('0.0 GB');
  });

  it('unlimited (null or 0 cap): no cap and an empty dial, however much was used', () => {
    expect(hasDataCap(null)).toBe(false);
    expect(hasDataCap(0)).toBe(false);
    expect(hasDataCap(undefined)).toBe(false);
    expect(hasDataCap(50)).toBe(true);
    expect(usageFraction(812, null)).toBe(0);
    expect(usageFraction(812, 0)).toBe(0);
    expect(usageFraction(812, -5)).toBe(0);
  });

  it('a missing or odd reading is no usage, not NaN', () => {
    expect(usageFraction(null, 50)).toBe(0);
    expect(usageFraction(Number.NaN, 50)).toBe(0);
    expect(usageFraction(-3, 50)).toBe(0);
  });

  it('colour bands: accent, yellow from 75 %, red from 90 %', () => {
    expect(gaugeTone(0.74)).toBe('accent');
    expect(gaugeTone(0.75)).toBe('yellow');
    expect(gaugeTone(0.89)).toBe('yellow');
    expect(gaugeTone(0.9)).toBe('red');
  });

  it('the percentage rounds as mobile does', () => {
    expect(gaugePercent(0.004)).toBe('0%');
    expect(gaugePercent(0.005)).toBe('1%');
    expect(gaugePercent(0.4)).toBe('40%');
  });
});

describe('figures (Android gaugeValue / gbFigure, Kotlin Double rendering)', () => {
  it('the dial number: ≥10 whole, ≥1 one decimal, else two', () => {
    expect(gaugeValue(0)).toBe('0.0');
    expect(gaugeValue(0.523)).toBe('0.52');
    expect(gaugeValue(0.5)).toBe('0.5');
    expect(gaugeValue(1.75)).toBe('1.8');
    expect(gaugeValue(4)).toBe('4.0');
    expect(gaugeValue(12.4)).toBe('12');
    expect(gaugeValue(-1)).toBe('0.0');
  });

  it('the Used / Left cells: ≥10 whole, else up to two decimals', () => {
    expect(formatGbFigure(4)).toBe('4.0 GB');
    expect(formatGbFigure(7.126)).toBe('7.13 GB');
    expect(formatGbFigure(0.52)).toBe('0.52 GB');
    expect(formatGbFigure(46)).toBe('46 GB');
  });

  it('the allowance: "50", not "50.0"', () => {
    expect(wholeGb(50)).toBe('50');
    expect(wholeGb(10.5)).toBe('10.5');
  });
});
