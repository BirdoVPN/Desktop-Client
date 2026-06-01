/**
 * AppIconMark — the Birdo brand mark in a rounded square. There is no dedicated
 * brand asset under `src/assets`, so we reuse the Tauri app icon (the same mark
 * shipped on the window / tray) imported as a static URL by Vite.
 */
import type { CSSProperties } from 'react';
// Relative import: the icon lives outside `src`, so the `@/` alias can't reach it.
import iconUrl from '../../../src-tauri/icons/icon.png';

export interface AppIconMarkProps {
  size?: number;
  className?: string;
  style?: CSSProperties;
}

export function AppIconMark({ size = 32, className = '', style }: AppIconMarkProps) {
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
