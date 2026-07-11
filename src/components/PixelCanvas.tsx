import { useEffect, useRef } from 'react';

interface PixelCanvasProps {
  /**
   * Positioning class for the canvas. Defaults to a fixed full-window backdrop
   * (App.tsx's global ambient layer). Pass `absolute inset-0 h-full w-full` to
   * embed it as the background of a positioned container (e.g. a pushed
   * settings sub-screen) so the grid fills that box instead of the viewport.
   */
  className?: string;
}

export function PixelCanvas({
  className = 'fixed inset-0 h-full w-full',
}: PixelCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;
    let isVisible = !document.hidden;
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
      color: string;
    }[][] = [];
    let mouseX = -1000;
    let mouseY = -1000;

    const initGrid = () => {
      // Size to the canvas's own box, NOT window.innerWidth. Sizing to the
      // window while the element is a narrow column would squash the square
      // backing store into thin vertical lines when scaled to fit — which is
      // itself a "stretched line" artifact. Bounding box keeps squares square.
      const rect = canvas.getBoundingClientRect();
      const w = Math.max(1, Math.round(rect.width));
      const h = Math.max(1, Math.round(rect.height));
      canvas.width = w;
      canvas.height = h;

      // Smaller squares: 15px - 25px range
      pixelSize = Math.max(15, Math.min(25, w / 80));

      columns = Math.ceil(canvas.width / pixelSize);
      rows = Math.ceil(canvas.height / pixelSize);

      grid = [];
      for (let y = 0; y < rows; y++) {
        grid[y] = [];
        for (let x = 0; x < columns; x++) {
          grid[y][x] = {
            x: x * pixelSize,
            y: y * pixelSize,
            alpha: Math.random() * 0.08,
            targetAlpha: 0,
            speed: 0.002 + Math.random() * 0.004,
            hoverDecay: 0,
            color: '255, 255, 255',
          };
        }
      }
    };

    // Frame pacing. The previous loop skip-framed inside rAF, so the JS thread
    // still woke at the display's 60Hz forever while the window was on screen —
    // for an ambient grid whose pixels top out at 0.25 alpha. A VPN client sits
    // open for days, so the loop now:
    //   - schedules the next frame via setTimeout (a real ~20fps sleep, not a
    //     60Hz wake-and-discard), and
    //   - stops entirely once the grid has settled (no pointer nearby and every
    //     cell has reached its target alpha), restarting on the next mousemove.
    // A frozen frame of a barely-visible grid is indistinguishable from a live
    // one, so nothing is lost visually.
    const FRAME_MS = 50; // ~20fps while animating
    let frameTimer: ReturnType<typeof setTimeout> | undefined;
    let running = false;

    const step = () => {
      ctx.clearRect(0, 0, canvas.width, canvas.height);

      // Set while painting if any cell is still in motion (alpha chasing its
      // target, or a hover trail decaying). When nothing moved, the frame we just
      // drew is final and we can stop scheduling.
      let settled = true;

      for (let y = 0; y < rows; y++) {
        for (let x = 0; x < columns; x++) {
          const pixel = grid[y][x];

          // Mouse interaction
          const dx = mouseX - (pixel.x + pixelSize / 2);
          const dy = mouseY - (pixel.y + pixelSize / 2);
          const dist = Math.sqrt(dx * dx + dy * dy);

          // Trail effect: Larger radius, much slower decay for ambient feel
          if (dist < 60) {
            pixel.hoverDecay = Math.min(1.0, pixel.hoverDecay + 0.08);
          } else {
            pixel.hoverDecay = Math.max(0, pixel.hoverDecay - 0.004);
          }
          if (pixel.hoverDecay > 0) settled = false;

          // Twinkling logic - much slower and subtler
          if (Math.random() < 0.001) pixel.targetAlpha = Math.random() * 0.15;

          if (pixel.alpha < pixel.targetAlpha) {
            pixel.alpha += pixel.speed;
            if (pixel.alpha > pixel.targetAlpha) pixel.alpha = pixel.targetAlpha;
            settled = false;
          } else if (pixel.alpha > pixel.targetAlpha) {
            pixel.alpha -= pixel.speed;
            if (pixel.alpha < pixel.targetAlpha) pixel.alpha = pixel.targetAlpha;
            settled = false;
          }

          // Combine effects - subtler max alpha for ambient feel
          const finalAlpha = Math.min(0.25, pixel.alpha + pixel.hoverDecay * 0.2);

          ctx.fillStyle = `rgba(${pixel.color}, ${finalAlpha})`;
          ctx.fillRect(pixel.x, pixel.y, pixelSize - 1, pixelSize - 1);
        }
      }

      if (!isVisible || settled) {
        // Park. A mousemove (or a re-show) wakes us again.
        running = false;
        return;
      }
      frameTimer = setTimeout(
        () => { animationFrameId = requestAnimationFrame(step); },
        FRAME_MS,
      );
    };

    /** Start the loop if it isn't already running (idempotent). */
    const wake = () => {
      if (running || !isVisible) return;
      running = true;
      animationFrameId = requestAnimationFrame(step);
    };

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouseX = e.clientX - rect.left;
      mouseY = e.clientY - rect.top;
      wake();
    };

    // Re-init on element resize (window resize, column reflow, etc.).
    let resizeTimer: ReturnType<typeof setTimeout>;
    const scheduleInit = () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(() => {
        initGrid();
        wake(); // repaint the new grid at least once
      }, 150);
    };
    const ro = new ResizeObserver(scheduleInit);
    ro.observe(canvas);

    // Pause animation when window is hidden to save CPU/GPU
    const handleVisibilityChange = () => {
      isVisible = !document.hidden;
      if (isVisible) {
        wake();
      } else {
        cancelAnimationFrame(animationFrameId);
        clearTimeout(frameTimer);
        running = false;
      }
    };

    window.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    initGrid();
    wake();

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      cancelAnimationFrame(animationFrameId);
      clearTimeout(frameTimer);
      clearTimeout(resizeTimer);
      ro.disconnect();
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className={className}
      aria-hidden
      // No CSS blur filter: a blur() on a full-window canvas forces a large GPU
      // compositing layer that, under WebView2, smears vertical banding across
      // layers above it. The pixels are already very low-alpha so they read
      // fine as an ambient grid unblurred.
      style={{ background: '#000000', zIndex: 0, pointerEvents: 'none' }}
    />
  );
}
