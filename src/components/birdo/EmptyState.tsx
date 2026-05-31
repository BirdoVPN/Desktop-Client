/**
 * BirdoEmptyState — reusable empty-state for lists & screens.
 * Mirrors mobile's `BirdoEmptyState.kt`.
 */
import type { ReactNode } from 'react';
import type { LucideIcon } from 'lucide-react';
import { white } from '@/lib/birdo-theme';

export interface BirdoEmptyStateProps {
  icon: LucideIcon;
  title: string;
  description?: string;
  /** Optional action slot (e.g. a BirdoButton). */
  action?: ReactNode;
  className?: string;
}

export function BirdoEmptyState({
  icon: Icon,
  title,
  description,
  action,
  className = '',
}: BirdoEmptyStateProps) {
  return (
    <div
      className={`flex w-full flex-col items-center text-center ${className}`}
      style={{ padding: 32 }}
    >
      <div
        className="flex h-16 w-16 items-center justify-center rounded-full"
        style={{ backgroundColor: white.w05 }}
      >
        <Icon size={28} color={white.w60} aria-hidden />
      </div>
      <div className="mt-4 text-base font-semibold" style={{ color: '#FFFFFF' }}>
        {title}
      </div>
      {description && (
        <div className="mt-1.5 text-[13px]" style={{ color: white.w60 }}>
          {description}
        </div>
      )}
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}
