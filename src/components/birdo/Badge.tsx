/**
 * BirdoBadge — pill-shaped status badge with optional pulsing dot.
 * Mirrors mobile's `BirdoBadge.kt` (BadgeTone enum + PulsingDot).
 */
import { motion } from 'framer-motion';
import type { LucideIcon } from 'lucide-react';
import { brand, status, white, hairline } from '@/lib/birdo-theme';

export type BadgeTone = 'neutral' | 'success' | 'warning' | 'danger' | 'info' | 'brand';

interface ToneStyle {
  bg: string;
  fg: string;
  border: string;
}

const TONE: Record<BadgeTone, ToneStyle> = {
  neutral: { bg: white.w05, fg: white.w80, border: hairline.soft },
  success: { bg: status.greenBg, fg: status.greenLight, border: 'rgba(34,197,94,0.30)' },
  warning: { bg: status.yellowBg, fg: status.yellowLight, border: 'rgba(234,179,8,0.30)' },
  danger:  { bg: status.redBg,    fg: status.red,         border: 'rgba(248,113,113,0.30)' },
  info:    { bg: status.blueBg,   fg: status.blue,        border: 'rgba(59,130,246,0.30)' },
  brand:   { bg: 'rgba(168,85,247,0.10)', fg: brand.purpleSoft, border: 'rgba(168,85,247,0.30)' },
};

export interface BirdoBadgeProps {
  text: string;
  tone?: BadgeTone;
  icon?: LucideIcon;
  pulseDot?: boolean;
  className?: string;
}

export function BirdoBadge({
  text,
  tone = 'neutral',
  icon: Icon,
  pulseDot = false,
  className = '',
}: BirdoBadgeProps) {
  const t = TONE[tone];
  return (
    <div
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 ${className}`}
      style={{
        backgroundColor: t.bg,
        borderColor: t.border,
      }}
    >
      {pulseDot ? (
        <PulsingDot color={t.fg} />
      ) : Icon ? (
        <Icon size={14} color={t.fg} aria-hidden />
      ) : null}
      <span className="text-xs font-medium" style={{ color: t.fg }}>
        {text}
      </span>
    </div>
  );
}

interface PulsingDotProps {
  color: string;
  size?: number;
}

export function PulsingDot({ color, size = 8 }: PulsingDotProps) {
  return (
    <span
      className="relative inline-flex items-center justify-center"
      style={{ width: size, height: size }}
      aria-hidden
    >
      <motion.span
        className="absolute inset-0 rounded-full"
        style={{ backgroundColor: color }}
        initial={{ scale: 1, opacity: 0.6 }}
        animate={{ scale: 2, opacity: 0 }}
        transition={{
          duration: 1.1,
          repeat: Infinity,
          ease: 'linear',
        }}
      />
      <span
        className="relative rounded-full"
        style={{
          width: size * 0.6,
          height: size * 0.6,
          backgroundColor: color,
        }}
      />
    </span>
  );
}
