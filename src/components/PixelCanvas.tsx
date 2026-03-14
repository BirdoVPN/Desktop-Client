import { useEffect, useRef } from 'react';

export function PixelCanvas() {
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
      canvas.width = window.innerWidth;
      canvas.height = window.innerHeight;

      // Smaller squares: 15px - 25px range
      pixelSize = Math.max(15, Math.min(25, window.innerWidth / 80));

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

    const handleResize = () => {
      initGrid();
    };

    // Pause animation when window is hidden to save CPU/GPU
    const handleVisibilityChange = () => {
      isVisible = !document.hidden;
      if (isVisible) {
        animationFrameId = requestAnimationFrame(animate);
      } else {
        cancelAnimationFrame(animationFrameId);
      }
    };

    window.addEventListener('resize', handleResize);
    window.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('visibilitychange', handleVisibilityChange);

    initGrid();
    animate();

    return () => {
      window.removeEventListener('resize', handleResize);
      window.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('visibilitychange', handleVisibilityChange);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas
      ref={canvasRef}
      className="fixed inset-0 h-full w-full"
      style={{ background: '#000000', zIndex: 0, pointerEvents: 'none', filter: 'blur(10px) contrast(0.9)' }}
    />
  );
}
