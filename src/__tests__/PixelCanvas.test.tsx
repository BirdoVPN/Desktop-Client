/**
 * PixelCanvas parks (W2-022).
 *
 * The loop claimed to stop "once the grid has settled", but every frame gave
 * each cell a 1-in-1000 chance of a new target, so ~1 of 1100 cells was always
 * moving and it repainted at 20 fps for as long as the window was visible.
 *
 * Run: npx vitest run src/__tests__/PixelCanvas.test.tsx
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, act } from '@testing-library/react';
import { PixelCanvas, ACTIVE_TWINKLE_MS } from '@/components/PixelCanvas';

const fillRect = vi.fn();
const ctx = { clearRect: vi.fn(), fillRect, fillStyle: '' };
let reduced = false;

beforeEach(() => {
  fillRect.mockClear();
  reduced = false;
  vi.useFakeTimers({
    toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'requestAnimationFrame', 'cancelAnimationFrame', 'performance', 'Date'],
  });
  vi.spyOn(HTMLCanvasElement.prototype, 'getContext').mockImplementation(
    () => ctx as unknown as CanvasRenderingContext2D,
  );
  vi.spyOn(HTMLCanvasElement.prototype, 'getBoundingClientRect').mockReturnValue({
    width: 380, height: 640, top: 0, left: 0, right: 380, bottom: 640, x: 0, y: 0, toJSON: () => ({}),
  } as DOMRect);
  window.matchMedia = vi.fn().mockImplementation((q: string) => ({
    matches: reduced && q.includes('reduce'),
    media: q,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
});

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

async function advance(ms: number) {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
}

describe('PixelCanvas', () => {
  it('stops scheduling frames once the twinkle window has passed and the grid has settled', async () => {
    render(<PixelCanvas />);
    await advance(ACTIVE_TWINKLE_MS + 8_000);
    const settled = fillRect.mock.calls.length;
    await advance(10_000);
    expect(fillRect.mock.calls.length).toBe(settled);
  });

  it('pointer movement wakes it for another burst, then it parks again', async () => {
    render(<PixelCanvas />);
    await advance(ACTIVE_TWINKLE_MS + 8_000);
    const parked = fillRect.mock.calls.length;
    act(() => {
      window.dispatchEvent(new MouseEvent('mousemove', { clientX: 10, clientY: 10 }));
    });
    await advance(500);
    expect(fillRect.mock.calls.length).toBeGreaterThan(parked);
    await advance(ACTIVE_TWINKLE_MS + 30_000);
    const again = fillRect.mock.calls.length;
    await advance(10_000);
    expect(fillRect.mock.calls.length).toBe(again);
  });

  it('under reduced motion it draws one frame and never animates', async () => {
    reduced = true;
    render(<PixelCanvas />);
    const first = fillRect.mock.calls.length;
    expect(first).toBeGreaterThan(0);
    act(() => {
      window.dispatchEvent(new MouseEvent('mousemove', { clientX: 10, clientY: 10 }));
    });
    await advance(5_000);
    // A static repaint on wake at most; never a running loop.
    expect(fillRect.mock.calls.length).toBeLessThanOrEqual(first * 2);
    const later = fillRect.mock.calls.length;
    await advance(5_000);
    expect(fillRect.mock.calls.length).toBe(later);
  });

  it('draws nothing while paused (a covering screen has its own canvas)', async () => {
    const { rerender } = render(<PixelCanvas paused />);
    await advance(1_000);
    const initial = fillRect.mock.calls.length;
    act(() => {
      window.dispatchEvent(new MouseEvent('mousemove', { clientX: 10, clientY: 10 }));
    });
    await advance(1_000);
    expect(fillRect.mock.calls.length).toBe(initial);
    rerender(<PixelCanvas paused={false} />);
    await advance(500);
    expect(fillRect.mock.calls.length).toBeGreaterThan(initial);
  });
});
