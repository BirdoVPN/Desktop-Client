/**
 * BirdoTopBar — compact top bar used across sub-screens. Mirrors mobile's
 * `BirdoTopBar.kt` (BirdoTopBar + BirdoIconAction).
 */
import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { ArrowLeft } from 'lucide-react';
import { white, hairline } from '@/lib/birdo-theme';

export interface BirdoTopBarProps {
  title: string;
  subtitle?: string;
  onBack?: () => void;
  /** Trailing slot of round IconAction buttons. */
  actions?: ReactNode;
  showDivider?: boolean;
  className?: string;
}

export function BirdoTopBar({
  title,
  subtitle,
  onBack,
  actions,
  showDivider = true,
  className = '',
}: BirdoTopBarProps) {
  return (
    <div
      className={`w-full ${className}`}
      style={{
        backgroundColor: white.w06,
        borderBottom: showDivider ? `1px solid ${hairline.soft}` : 'none',
      }}
    >
      <div
        className="flex items-center"
        style={{ minHeight: 56, padding: '6px 12px' }}
      >
        {onBack ? (
          <>
            <button
              type="button"
              onClick={onBack}
              aria-label="Back"
              className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full transition-colors hover:bg-white/10"
              style={{ backgroundColor: white.w05 }}
            >
              <ArrowLeft size={20} color={white.w80} aria-hidden />
            </button>
            <div className="w-3 shrink-0" />
          </>
        ) : (
          <div className="w-2 shrink-0" />
        )}
        <div className="min-w-0 flex-1">
          <div
            className="truncate text-[17px] font-semibold"
            style={{ color: '#FFFFFF' }}
          >
            {title}
          </div>
          {subtitle && (
            <div className="truncate text-xs" style={{ color: white.w40 }}>
              {subtitle}
            </div>
          )}
        </div>
        {actions && <div className="flex shrink-0 items-center">{actions}</div>}
      </div>
    </div>
  );
}

/** Round icon button used in BirdoTopBar actions. */
export interface BirdoIconActionProps {
  icon: LucideIcon;
  contentDescription: string;
  onClick: () => void;
  tint?: string;
  disabled?: boolean;
}

export function BirdoIconAction({
  icon: Icon,
  contentDescription,
  onClick,
  tint = white.w80,
  disabled = false,
}: BirdoIconActionProps) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={contentDescription}
      className="flex h-10 w-10 shrink-0 items-center justify-center rounded-full transition-colors hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-50"
    >
      <Icon size={20} color={tint} aria-hidden />
    </button>
  );
}
