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

    let lastFrameTime = 0;
    const animate = (now: number = 0) => {
      // Throttle to ~30fps — ample for ambient decoration, saves CPU/battery
      if (now && now - lastFrameTime < 33) {
        animationFrameId = requestAnimationFrame(animate);
        return;
      }
      lastFrameTime = now;

      ctx.clearRect(0, 0, canvas.width, canvas.height);

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

          // Twinkling logic - much slower and subtler
          if (Math.random() < 0.001) pixel.targetAlpha = Math.random() * 0.15;

          if (pixel.alpha < pixel.targetAlpha) {
            pixel.alpha += pixel.speed;
            if (pixel.alpha > pixel.targetAlpha) pixel.alpha = pixel.targetAlpha;
          } else if (pixel.alpha > pixel.targetAlpha) {
            pixel.alpha -= pixel.speed;
            if (pixel.alpha < pixel.targetAlpha) pixel.alpha = pixel.targetAlpha;
          }

          // Combine effects - subtler max alpha for ambient feel
          const finalAlpha = Math.min(0.25, pixel.alpha + pixel.hoverDecay * 0.2);

          ctx.fillStyle = `rgba(${pixel.color}, ${finalAlpha})`;
          ctx.fillRect(pixel.x, pixel.y, pixelSize - 1, pixelSize - 1);
        }
      }

      if (isVisible) {
        animationFrameId = requestAnimationFrame(animate);
      }
    };

    const handleMouseMove = (e: MouseEvent) => {
      const rect = canvas.getBoundingClientRect();
      mouseX = e.clientX - rect.left;
      mouseY = e.clientY - rect.top;
    };

    // Re-init on element resize (window resize, column reflow, etc.).
    let resizeTimer: ReturnType<typeof setTimeout>;
    const scheduleInit = () => {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(initGrid, 150);
    };
    const ro = new ResizeObserver(scheduleInit);
    ro.observe(canvas);

    // Pause animation when window is hidden to save CPU/GPU
    const handleVisibilityChange = () => {
      isVisible = !document.hidden;
      if (isVisible) {
        animationFrameId = requestAnimationFrame(animate);
      } else {
        cancelAnimationFrame(animationFrameId);
      }
    };

    window.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    initGrid();
    animate();

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      cancelAnimationFrame(animationFrameId);
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
