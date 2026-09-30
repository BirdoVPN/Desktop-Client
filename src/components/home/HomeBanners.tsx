/**
 * Banners above the server selector: administrator rights, DNS protection
 * degraded, and the connection error — with the one action that helps.
 *
 * The error banner used to show whatever string reached `errorMessage`, which
 * for anything Rust raised in the background (auto-reconnect giving up, a
 * failed reapply, a revoked session) was nothing: the pill read "Error" and
 * nothing said why (W2-008). It now reads the error Rust attaches to the
 * status, or the one the user's own command returned, mapped by code.
 */
import { AlertCircle, AlertTriangle, ShieldAlert, type LucideIcon } from 'lucide-react';
import { useShallow } from 'zustand/react/shallow';
import { errorCopy, giveUpMessage, type ErrorAction } from '@/lib/errors';
import { status } from '@/lib/birdo-theme';
import { useAppStore } from '@/store/app-store';

const ACTION_LABEL: Record<Exclude<ErrorAction, null | 'update' | 'sign_in'>, string> = {
  view_plans: 'View plans',
  open_settings: 'Open Settings',
  choose_server: 'Choose server',
  connect: 'Connect',
  retry: 'Try again',
};

interface HomeBannersProps {
  onAction: (action: ErrorAction) => void;
}

export function HomeBanners({ onAction }: HomeBannersProps) {
  const { isAdmin, dnsDegraded, giveUp, blocking, error } = useAppStore(
    useShallow((s) => ({
      isAdmin: s.isAdmin,
      dnsDegraded: s.dnsDegraded,
      giveUp: s.giveUp,
      blocking: s.killSwitchBlocking,
      error: s.vpnError ?? s.commandError,
    })),
  );

  let errorText: string | null = null;
  let action: ErrorAction = null;
  if (giveUp) {
    // Takes priority over the generic error, as on iOS: it is the one message
    // that says reconnecting stopped and whether traffic is still blocked.
    errorText = giveUpMessage(giveUp.kind, giveUp.attempts, blocking);
    action = blocking ? null : giveUp.kind === 'never_established' ? 'choose_server' : 'connect';
  } else if (error && error.code !== 'cancelled') {
    const copy = errorCopy(error, 'vpn');
    errorText = copy.message;
    action = copy.action;
  }
  const actionLabel = action && action !== 'update' && action !== 'sign_in' ? ACTION_LABEL[action] : null;

  return (
    <>
      {isAdmin === false && (
        <BannerRow
          icon={ShieldAlert}
          tone="warning"
          text="BirdoVPN is not running as an administrator, so it cannot connect."
        />
      )}

      {/* DNS degradation. The counterpart to the Protected pill: the Rust
          side moves every interface's DNS aside to stop the OS racing the
          ISP's resolvers against the tunnel's, and it reads back every one
          of those writes. A read-back that did not match means either an
          adapter still carrying ISP resolvers beside a live tunnel (a DNS
          leak, while this screen says Protected) or one left without
          resolvers after a disconnect. Both are invisible everywhere else,
          so the pill alone would be reassurance drawn from data nobody
          checked. Rendered on every connection state for that reason. */}
      {dnsDegraded.length > 0 && (
        <BannerRow
          icon={AlertTriangle}
          tone="warning"
          text={
            dnsDegraded.length === 1
              ? `DNS not fully protected — ${dnsDegraded[0]}`
              : `DNS not fully protected on ${dnsDegraded.length} adapters — ${dnsDegraded[0]}`
          }
        />
      )}

      {errorText && (
        <BannerRow
          icon={AlertCircle}
          tone="danger"
          text={errorText}
          actionLabel={actionLabel ?? undefined}
          onAction={action ? () => onAction(action) : undefined}
        />
      )}
    </>
  );
}

const BANNER_TONE = {
  warning: { fg: status.yellowLight, bg: 'rgba(245,158,11,0.10)', border: 'rgba(245,158,11,0.30)' },
  danger: { fg: status.red, bg: status.redBg, border: status.redBorder },
} as const;

function BannerRow({
  icon: Icon,
  tone,
  text,
  actionLabel,
  onAction,
}: {
  icon: LucideIcon;
  tone: keyof typeof BANNER_TONE;
  text: string;
  actionLabel?: string;
  onAction?: () => void;
}) {
  const t = BANNER_TONE[tone];
  return (
    <div
      className="birdo-banner mb-2.5 flex items-center gap-2.5 rounded-2xl px-3.5 py-3"
      style={{ backgroundColor: t.bg, border: `1px solid ${t.border}` }}
    >
      <Icon size={18} color={t.fg} className="shrink-0" aria-hidden />
      <p className="flex-1 text-xs leading-snug" style={{ color: t.fg }}>
        {text}
      </p>
      {actionLabel && onAction && (
        <button
          type="button"
          onClick={onAction}
          className="shrink-0 rounded-birdo-xs px-2 py-1 text-xs font-semibold hover:bg-white/10"
          style={{ color: t.fg, border: `1px solid ${t.border}` }}
        >
          {actionLabel}
        </button>
      )}
    </div>
  );
}
