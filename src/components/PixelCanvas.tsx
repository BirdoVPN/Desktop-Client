import { useEffect, useRef } from 'react';

interface PixelCanvasProps {
  /**
   * Positioning class for the canvas. Defaults to a fixed full-window backdrop
   * (App.tsx's global ambient layer). Pass `absolute inset-0 h-full w-full` to
   * embed it as the background of a positioned container (e.g. a pushed
   * settings sub-screen) so the grid fills that box instead of the viewport.
   */
  className?: string;
  /** Stop drawing (a covering screen has its own canvas). Resumes on false. */
  paused?: boolean;
}

/** How long the grid twinkles after the pointer moves or the window gains focus. */
export const ACTIVE_TWINKLE_MS = 4_000;
const FRAME_MS = 50; // ~20fps while animating

const reducedMotion = () =>
  typeof window.matchMedia === 'function' &&
  window.matchMedia('(prefers-reduced-motion: reduce)').matches;

/**
 * The ambient pixel grid behind every screen.
 *
 * IT PARKS (W2-022). It claimed to — "stops entirely once the grid has
 * settled" — but every frame gave each of ~1100 cells a 1-in-1000 chance of a
 * new random target, so about one cell was always in motion and the loop never
 * settled: a VPN client left open on the desktop repainted the grid at 20 fps
 * forever (twice, with a sub-screen open). Now new targets are only chosen for
 * ACTIVE_TWINKLE_MS after the pointer moves or the window gains focus; after
 * that every cell eases onto its target and the loop stops scheduling frames.
 * A frozen frame of a barely-visible grid is indistinguishable from a live one.
 *
 * Under "reduce motion" it draws one static frame and never animates (iOS's
 * PixelCanvasView does the same), and it never draws while hidden or `paused`.
 */
export function PixelCanvas({
  className = 'fixed inset-0 h-full w-full',
  paused = false,
}: PixelCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const setPausedRef = useRef<((p: boolean) => void) | null>(null);
  const pausedRef = useRef(paused);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId = 0;
    let frameTimer: ReturnType<typeof setTimeout> | undefined;
    let running = false;
    let activeUntil = 0;
    let isVisible = !document.hidden;
    let reduce = reducedMotion();
    let pixelSize = 0;
    let columns = 0;
    let rows = 0;
    let grid: {
      x: number;
      y: number;
      alpha: number;
      targetAlpha: number;
      speed: number;
      hoverDecay: number;
    }[][] = [];
    let mouseX = -1000;
    let mouseY = -1000;

    const initGrid = () => {
      // Size to the canvas's own box, NOT window.innerWidth: sizing to the
      // window while the element is a narrow column squashed the square
      // backing store into thin vertical lines when scaled to fit.
      const rect = canvas.getBoundingClientRect();
      const w = Math.max(1, Math.round(rect.width));
      const h = Math.max(1, Math.round(rect.height));
      canvas.width = w;
      canvas.height = h;
      pixelSize = Math.max(15, Math.min(25, w / 80));
      columns = Math.ceil(canvas.width / pixelSize);
      rows = Math.ceil(canvas.height / pixelSize);
      grid = [];
      for (let y = 0; y < rows; y++) {
        grid[y] = [];
        for (let x = 0; x < columns; x++) {
          const alpha = Math.random() * 0.08;
          grid[y][x] = {
            x: x * pixelSize,
            y: y * pixelSize,
            alpha,
            targetAlpha: alpha,
            speed: 0.002 + Math.random() * 0.004,
            hoverDecay: 0,
          };
        }
      }
    };

    /** Paint one frame; returns whether anything is still moving. */
    const paint = (animate: boolean): boolean => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      const twinkle = animate && performance.now() < activeUntil;
      let moving = false;
      for (let y = 0; y < rows; y++) {
        for (let x = 0; x < columns; x++) {
          const p = grid[y][x];
          if (animate) {
            const dx = mouseX - (p.x + pixelSize / 2);
            const dy = mouseY - (p.y + pixelSize / 2);
            // Only a MOVING pointer lights cells: one resting over the window
            // would otherwise hold its trail at full strength and the loop
            // would never park.
            if (twinkle && Math.sqrt(dx * dx + dy * dy) < 60) {
              p.hoverDecay = Math.min(1.0, p.hoverDecay + 0.08);
            } else {
              p.hoverDecay = Math.max(0, p.hoverDecay - 0.004);
            }
            if (p.hoverDecay > 0) moving = true;
            if (twinkle && Math.random() < 0.001) p.targetAlpha = Math.random() * 0.15;
            if (p.alpha !== p.targetAlpha) {
              const step = p.alpha < p.targetAlpha ? p.speed : -p.speed;
              p.alpha += step;
              if ((step > 0 && p.alpha > p.targetAlpha) || (step < 0 && p.alpha < p.targetAlpha)) {
                p.alpha = p.targetAlpha;
              }
              moving = true;
            }
          }
          ctx.fillStyle = `rgba(255, 255, 255, ${Math.min(0.25, p.alpha + p.hoverDecay * 0.2)})`;
          ctx.fillRect(p.x, p.y, pixelSize - 1, pixelSize - 1);
        }
      }
      return moving || twinkle;
    };

    const stop = () => {
      running = false;
      cancelAnimationFrame(animationFrameId);
      clearTimeout(frameTimer);
    };

    const step = () => {
      const moving = paint(true);
      if (!isVisible || pausedRef.current || reduce || !moving) {
        running = false; // parked; the next wake() restarts it
        return;
      }
      frameTimer = setTimeout(() => {
        animationFrameId = requestAnimationFrame(step);
      }, FRAME_MS);
    };

    /** Start (or extend) a burst of animation. Idempotent. */
    const wake = () => {
      if (!isVisible || pausedRef.current) return;
      if (reduce) {
        paint(false);
        return;
      }
      activeUntil = performance.now() + ACTIVE_TWINKLE_MS;
      if (running) return;
      running = true;
      animationFrameId = requestAnimationFrame(step);
    };

    setPausedRef.current = (p: boolean) => {
      if (p) stop();
      else wake();
    };

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouseX = e.clientX - rect.left;
      mouseY = e.clientY - rect.top;
      wake();
    };

    let resizeTimer: ReturnType<typeof setTimeout> | undefined;
    const scheduleInit = () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        initGrid();
        if (reduce) paint(false);
        else wake();
      }, 150);
    };
    const ro = typeof ResizeObserver === 'function' ? new ResizeObserver(scheduleInit) : null;
    ro?.observe(canvas);

    const handleVisibilityChange = () => {
      isVisible = !document.hidden;
      if (isVisible) wake();
      else stop();
    };
    const handleFocus = () => wake();

    const motionQuery =
      typeof window.matchMedia === 'function' ? window.matchMedia('(prefers-reduced-motion: reduce)') : null;
    const handleMotionChange = () => {
      reduce = reducedMotion();
      if (reduce) {
        stop();
        paint(false);
      } else {
        wake();
      }
    };

    window.addEventListener('mousemove', handleMouseMove);
    window.addEventListener('focus', handleFocus);
    document.addEventListener('visibilitychange', handleVisibilityChange);
    motionQuery?.addEventListener?.('change', handleMotionChange);

    initGrid();
    paint(false);
    wake();

    return () => {
      setPausedRef.current = null;
      window.removeEventListener('mousemove', handleMouseMove);
      window.removeEventListener('focus', handleFocus);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      motionQuery?.removeEventListener?.('change', handleMotionChange);
      stop();
      clearTimeout(resizeTimer);
      ro?.disconnect();
    };
  }, []);

  useEffect(() => {
    pausedRef.current = paused;
    setPausedRef.current?.(paused);
  }, [paused]);

  return (
    <canvas
      ref={canvasRef}
      className={className}
      aria-hidden
      // No CSS blur filter: a blur() on a full-window canvas forces a large GPU
      // compositing layer that, under WebView2, smears vertical banding across
      // layers above it.
      style={{ background: '#000000', zIndex: 0, pointerEvents: 'none' }}
    />
  );
}
