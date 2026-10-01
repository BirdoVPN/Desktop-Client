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
import { useId, useState } from 'react';
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

/**
 * The DNS banner's one sentence, whatever Rust reported. Its entries are free
 * text (the IPC shape is a list of strings) and have been technical before
 * ("… SMHNR may race the tunnel" reached a user's screen), so the banner
 * never shows one as its message: they sit behind Details. Accurate for every
 * entry Rust reports today: the tunnel's resolvers could not be set, or an
 * adapter's settings an older version changed could not be put back. Either
 * way names may fail to resolve. It claims no leak, because the DNS guard
 * blocks lookups outside the tunnel while connected.
 */
export const DNS_DEGRADED_COPY = "Some DNS settings couldn't be applied, so some websites may not load.";

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

      {/* DNS degradation: what Rust read back and found wrong (the tunnel's
          resolvers not set, an adapter an older version changed not put
          back). Invisible everywhere else, so it renders on every connection
          state. One human sentence; Rust's own lines behind Details. */}
      {dnsDegraded.length > 0 && (
        <BannerRow icon={AlertTriangle} tone="warning" text={DNS_DEGRADED_COPY} details={dnsDegraded} />
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
  details,
}: {
  icon: LucideIcon;
  tone: keyof typeof BANNER_TONE;
  text: string;
  actionLabel?: string;
  onAction?: () => void;
  /** Secondary lines, collapsed behind a Details disclosure. */
  details?: string[];
}) {
  const t = BANNER_TONE[tone];
  const [open, setOpen] = useState(false);
  const detailsId = useId();
  const buttonClass = 'shrink-0 rounded-birdo-xs px-2 py-1 text-xs font-semibold hover:bg-white/10';
  return (
    <div
      className="birdo-banner mb-2.5 rounded-2xl px-3.5 py-3"
      style={{ backgroundColor: t.bg, border: `1px solid ${t.border}` }}
    >
      <div className="flex items-center gap-2.5">
        <Icon size={18} color={t.fg} className="shrink-0" aria-hidden />
        <p className="flex-1 text-xs leading-snug" style={{ color: t.fg }}>
          {text}
        </p>
        {details && details.length > 0 && (
          <button
            type="button"
            onClick={() => setOpen((o) => !o)}
            aria-expanded={open}
            aria-controls={detailsId}
            className={buttonClass}
            style={{ color: t.fg }}
          >
            {open ? 'Hide details' : 'Details'}
          </button>
        )}
        {actionLabel && onAction && (
          <button
            type="button"
            onClick={onAction}
            className={buttonClass}
            style={{ color: t.fg, border: `1px solid ${t.border}` }}
          >
            {actionLabel}
          </button>
        )}
      </div>
      {details && open && (
        <ul id={detailsId} className="mt-2 list-disc space-y-1 pl-9 text-[11px] leading-snug" style={{ color: t.fg }}>
          {details.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      )}
    </div>
  );
}
