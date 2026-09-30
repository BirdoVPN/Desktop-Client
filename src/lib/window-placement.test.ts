/**
 * Window placement against the monitor work area (W2-020).
 *
 * The audit's cases: a 1920x1080 panel at 150% and 175% with a bottom taskbar
 * (48 logical px), each corner; and a left-side taskbar.
 *
 * Run: npx vitest run src/lib/window-placement.test.ts
 */
import { describe, it, expect } from 'vitest';
import { computePlacement, MIN_WINDOW_HEIGHT, WINDOW_HEIGHT, WINDOW_WIDTH, type PhysicalRect } from './window-placement';

/** A 1920x1080 panel whose taskbar takes `taskbarLogical` px at the bottom. */
const bottomTaskbar = (scale: number, taskbarLogical = 48): PhysicalRect => ({
  x: 0,
  y: 0,
  width: 1920,
  height: 1080 - Math.round(taskbarLogical * scale),
});

const inside = (p: { x: number; y: number; logicalHeight: number }, wa: PhysicalRect, scale: number) => {
  const w = Math.round(WINDOW_WIDTH * scale);
  const h = Math.round(p.logicalHeight * scale);
  return p.x >= wa.x && p.y >= wa.y && p.x + w <= wa.x + wa.width && p.y + h <= wa.y + wa.height;
};

describe('computePlacement', () => {
  it.each([1, 1.25, 1.5, 1.75])('at %s scale every corner fits inside the work area', (scale) => {
    const wa = bottomTaskbar(scale);
    for (const corner of ['top-left', 'top-right', 'bottom-left', 'bottom-right'] as const) {
      expect(inside(computePlacement(corner, wa, scale), wa, scale)).toBe(true);
    }
  });

  it('150%: the bottom corners clear a 72 px taskbar (the fixed 48 px reserve put the nav under it)', () => {
    const wa = bottomTaskbar(1.5);
    const p = computePlacement('bottom-left', wa, 1.5);
    expect(p.logicalHeight).toBe(WINDOW_HEIGHT);
    expect(p.y + Math.round(WINDOW_HEIGHT * 1.5)).toBeLessThanOrEqual(1080 - 72);
  });

  it('175% on 1080p: the window shrinks to fit instead of placing its title bar off-screen', () => {
    const wa = bottomTaskbar(1.75);
    const p = computePlacement('bottom-right', wa, 1.75);
    expect(p.logicalHeight).toBeLessThan(WINDOW_HEIGHT);
    expect(p.logicalHeight).toBeGreaterThanOrEqual(MIN_WINDOW_HEIGHT);
    expect(p.y).toBeGreaterThanOrEqual(0);
  });

  it('a left-side taskbar moves the left corners off it', () => {
    const wa: PhysicalRect = { x: 72, y: 0, width: 1920 - 72, height: 1080 };
    const p = computePlacement('top-left', wa, 1.5);
    expect(p.x).toBeGreaterThanOrEqual(72);
  });

  it('a second monitor to the right is placed in its own coordinates', () => {
    const wa: PhysicalRect = { x: 1920, y: 0, width: 2560, height: 1392 };
    const p = computePlacement('top-right', wa, 1);
    expect(p.x).toBe(1920 + 2560 - WINDOW_WIDTH - 8);
  });

  it('never above or left of the work area, even on a display too small for the minimum height', () => {
    const wa: PhysicalRect = { x: 0, y: 0, width: 800, height: 500 };
    const p = computePlacement('bottom-left', wa, 1);
    expect(p.y).toBeGreaterThanOrEqual(0);
    expect(p.logicalHeight).toBe(MIN_WINDOW_HEIGHT);
  });
});
