/**
 * AppIconMark — the Birdo brand mark in a rounded square. The icon is bundled
 * from `src/assets/app-icon.png` (a copy of the Tauri app icon) so Vite reliably
 * fingerprints + emits it in the production build. Importing from outside `src`
 * (../../../src-tauri/icons) silently failed to bundle, rendering a blank box.
 */
import type { CSSProperties } from 'react';
import iconUrl from '@/assets/app-icon.png';

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
