/**
 * BirdoBadge — pill-shaped status badge with optional pulsing dot.
 * Mirrors mobile's `BirdoBadge.kt` (BadgeTone enum + PulsingDot).
 */
import type { LucideIcon } from 'lucide-react';
import { RefreshCw, CircleAlert, WifiOff } from 'lucide-react';
import { accentA, brand, status, white, hairline } from '@/lib/birdo-theme';
import type { ConnectionState } from '@/store/app-store';
import { statusPill, type PillIcon } from '@/lib/vpn-display';

export type BadgeTone = 'neutral' | 'success' | 'warning' | 'danger' | 'info' | 'brand';

interface ToneStyle {
  bg: string;
  fg: string;
  border: string;
}

const TONE: Record<BadgeTone, ToneStyle> = {
  neutral: { bg: white.w05, fg: white.w80, border: hairline.soft },
  success: { bg: status.greenBg, fg: status.greenLight, border: status.greenShadow },
  warning: { bg: status.yellowBg, fg: status.yellowLight, border: 'rgba(234,179,8,0.30)' },
  danger:  { bg: status.redBg,    fg: status.red,         border: status.redBorder },
  info:    { bg: status.blueBg,   fg: status.blue,        border: 'rgba(59,130,246,0.30)' },
  brand:   { bg: brand.accentBg, fg: brand.accentSoft, border: accentA(0.3) },
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
      className={`birdo-badge inline-flex items-center gap-2 rounded-full border px-3 py-1.5 ${className}`}
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

/**
 * The ring animates a few times on mount and then stops. It used to loop forever
 * (`infinite`), which meant the compositor could never idle during the connected
 * steady state — the exact state a VPN client spends days in. The pulse exists to
 * draw the eye when the status CHANGES, and it still does that; a permanently
 * throbbing dot is just battery drain nobody looks at.
 */
export function PulsingDot({ color, size = 8 }: PulsingDotProps) {
  return (
    <span
      className="relative inline-flex items-center justify-center"
      style={{ width: size, height: size }}
      aria-hidden
    >
      <span
        className="absolute inset-0 rounded-full animate-birdo-pulse-ring-3x"
        style={{ backgroundColor: color }}
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

// ── StatusPill (VPN connection state) ─────────────────────────────────────

export interface StatusPillProps {
  state: ConnectionState;
  /** The live session is a Multi-Hop route: "Protected · Multi-Hop" (P1-parity-017). */
  multiHop?: boolean;
  className?: string;
}

const PILL_ICON: Record<Exclude<PillIcon, null>, LucideIcon> = {
  'wifi-off': WifiOff,
  sync: RefreshCw,
  alert: CircleAlert,
};

/**
 * VPN connection-state pill. Wording and tone come from `statusPill` (the
 * canonical table); announcing changes is LiveAnnouncer's job, so the pill is
 * deliberately not a live region itself (one change, one announcement).
 */
export function StatusPill({ state, multiHop = false, className = '' }: StatusPillProps) {
  const cfg = statusPill(state, multiHop);
  return (
    <div data-testid="vpn-status" className={className}>
      <BirdoBadge
        text={cfg.text}
        tone={cfg.tone}
        icon={cfg.icon ? PILL_ICON[cfg.icon] : undefined}
        pulseDot={cfg.pulse}
      />
    </div>
  );
}
