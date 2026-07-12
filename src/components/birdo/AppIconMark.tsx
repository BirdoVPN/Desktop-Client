/**
 * AppIconMark — the Birdo brand mark. Two forms:
 *
 *  - default: the rounded-square APP ICON (dark emerald squircle) bundled from
 *    `src/assets/app-icon.png`. Used for the title-bar / small identity slots,
 *    where a platform-style app icon is expected.
 *  - `mark`: the phoenix ALONE on a transparent field, with a soft emerald glow.
 *    Used for hero placements (login / consent) where a hard square box reads as
 *    heavy — this is the "clean, rounded, clear" logo.
 *
 * Both are imported from `src/assets/` so Vite reliably fingerprints + emits them
 * (importing from outside `src` silently failed to bundle → blank box).
 */
import type { CSSProperties } from 'react';
import iconUrl from '@/assets/app-icon.png';
import markUrl from '@/assets/logo-mark.png';

export interface AppIconMarkProps {
  size?: number;
  className?: string;
  style?: CSSProperties;
  /** Render the transparent phoenix mark (with glow) instead of the boxed icon. */
  mark?: boolean;
}

export function AppIconMark({
  size = 32,
  className = '',
  style,
  mark = false,
}: AppIconMarkProps) {
  if (mark) {
    return (
      <div
        className={className}
        style={{ position: 'relative', width: size, height: size, ...style }}
      >
        {/* Soft emerald halo so the mark has presence on the dark background
            without a hard box. Purely decorative. */}
        <div
          style={{
            position: 'absolute',
            inset: '-22%',
            borderRadius: '50%',
            background:
              'radial-gradient(circle, rgba(16,185,129,0.20) 0%, rgba(16,185,129,0.06) 45%, transparent 68%)',
            pointerEvents: 'none',
          }}
          aria-hidden
        />
        <img
          src={markUrl}
          alt="Birdo"
          width={size}
          height={size}
          style={{ display: 'block', position: 'relative', width: size, height: size }}
        />
      </div>
    );
  }

  return (
    <img
      src={iconUrl}
      alt="Birdo"
      width={size}
      height={size}
      className={className}
      style={{ borderRadius: 12, display: 'block', ...style }}
    />
  );
}
