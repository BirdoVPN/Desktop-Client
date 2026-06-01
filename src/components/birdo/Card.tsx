/**
 * BirdoCard — premium glass card with gradient hairline stroke.
 * Mirrors mobile's `BirdoCard.kt` (BirdoCard, BirdoSubCard, BirdoSectionHeader).
 */
import type { CSSProperties, ReactNode } from 'react';
import { surface, white, hairline, gradient, brand } from '@/lib/birdo-theme';

export interface BirdoCardProps {
  children: ReactNode;
  className?: string;
  cornerRadius?: number;
  surfaceColor?: string;
  /** When true, render gradient hairline border (default). */
  glassBorder?: boolean;
  /** Optional brand glow rendered behind content. */
  glow?: 'idle' | 'connected' | 'error' | null;
  padding?: string;
  style?: CSSProperties;
}

export function BirdoCard({
  children,
  className = '',
  cornerRadius = 16,
  surfaceColor = surface.s1,
  glassBorder = true,
  glow = null,
  padding = '1rem',
  style,
}: BirdoCardProps) {
  const glowBg =
    glow === 'idle'      ? gradient.idle
    : glow === 'connected' ? gradient.connected
    : glow === 'error'   ? gradient.error
    : null;

  return (
    <div
      className={`relative overflow-hidden ${className}`}
      style={{
        borderRadius: cornerRadius,
        backgroundColor: surfaceColor,
        // Two backgrounds: gradient border via padding-box trick + solid bg
        background: glassBorder
          ? `linear-gradient(${surfaceColor}, ${surfaceColor}) padding-box, ${gradient.glassStroke} border-box`
          : surfaceColor,
        border: glassBorder ? '1px solid transparent' : 'none',
        ...style,
      }}
    >
      {glowBg && (
        <div
          className="pointer-events-none absolute inset-0"
          style={{ background: glowBg }}
          aria-hidden
        />
      )}
      <div className="relative" style={{ padding }}>
        {children}
      </div>
    </div>
  );
}

export interface BirdoSubCardProps {
  children: ReactNode;
  className?: string;
  cornerRadius?: number;
  padding?: string;
}

export function BirdoSubCard({
  children,
  className = '',
  cornerRadius = 12,
  padding = '0.75rem',
}: BirdoSubCardProps) {
  return (
    <div
      className={className}
      style={{
        borderRadius: cornerRadius,
        backgroundColor: white.w03,
        border: `1px solid ${hairline.soft}`,
        padding,
      }}
    >
      {children}
    </div>
  );
}

export interface BirdoSectionHeaderProps {
  title: string;
  actionLabel?: string;
  onActionClick?: () => void;
  className?: string;
}

export function BirdoSectionHeader({
  title,
  actionLabel,
  onActionClick,
  className = '',
}: BirdoSectionHeaderProps) {
  return (
    <div className={`flex w-full items-center px-1 py-2 ${className}`}>
      <span
        className="flex-1 text-[11px] font-semibold uppercase tracking-[1.4px]"
        style={{ color: white.w60 }}
      >
        {title}
      </span>
      {actionLabel && (
        <button
          type="button"
          onClick={onActionClick}
          className="rounded-birdo-xs px-1.5 py-1 text-xs font-medium hover:bg-white/5"
          style={{ color: brand.purpleSoft }}
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}
