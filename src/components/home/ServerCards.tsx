/**
 * The server selector on the Connect screen: a single card, or the Multi-Hop
 * Entry / Exit pair.
 */
import { ArrowDown, ChevronRight, Info } from 'lucide-react';
import { BirdoCard } from '@/components/birdo';
import { brand, hairline, status, white } from '@/lib/birdo-theme';
import { serverLabel, serverSubtitle, serverTitle } from '@/lib/vpn-display';
import type { LoadStatus, Server } from '@/store/app-store';
import { countryCodeToFlag } from '@/utils/helpers';

interface ServerSelectorCardProps {
  /** What Connect will dial: the chosen server, or the fastest one. */
  server: Server | null;
  /** `server` is the automatic pick, not the user's choice (W2-028). */
  isFastest: boolean;
  serversStatus: LoadStatus;
  /** A live switch is happening onto `server`. */
  switching: boolean;
  disabled: boolean;
  onClick: () => void;
}

export function ServerSelectorCard({
  server,
  isFastest,
  serversStatus,
  switching,
  disabled,
  onClick,
}: ServerSelectorCardProps) {
  // Title = the server's name, subtitle = where it is, never repeating the
  // name (`serverSubtitle`); the automatic pick names its server once, below
  // "Fastest server".
  let title: string;
  let subtitle: string;
  if (server) {
    title = isFastest ? 'Fastest server' : serverTitle(server);
    subtitle = switching ? 'Switching…' : isFastest ? serverLabel(server, ' · ') : serverSubtitle(server);
  } else if (serversStatus === 'loading' || serversStatus === 'idle') {
    title = 'Loading servers…';
    subtitle = 'Browse locations';
  } else if (serversStatus === 'error') {
    title = "Couldn't load servers";
    subtitle = 'Select to try again';
  } else {
    title = 'Choose a server';
    subtitle = 'Browse locations';
  }
  return (
    <button
      type="button"
      data-testid="server-selector"
      onClick={onClick}
      disabled={disabled}
      aria-label={`${[title, subtitle].filter(Boolean).join('. ')}. Change server`}
      className="w-full text-left transition-opacity disabled:opacity-50"
    >
      <BirdoCard cornerRadius={16} padding="0.875rem">
        <div className="flex items-center gap-3">
          <span
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full text-base"
            style={{ backgroundColor: white.w10 }}
            aria-hidden
          >
            {server ? countryCodeToFlag(server.countryCode) : '🌐'}
          </span>
          <div className="min-w-0 flex-1">
            <div className="truncate text-sm font-semibold" style={{ color: white.w100 }}>
              {title}
            </div>
            {subtitle && (
              <div
                className="truncate text-xs"
                style={{ color: serversStatus === 'error' && !server ? status.red : white.w60 }}
              >
                {subtitle}
              </div>
            )}
          </div>
          <ChevronRight size={18} color={white.w40} aria-hidden />
        </div>
      </BirdoCard>
    </button>
  );
}

/**
 * iOS MultiHopView's honest limit, verbatim (REMEDIATION-DECISIONS §2: one
 * encryption layer, two servers — "extra anonymity" overstated it).
 */
export const MULTI_HOP_EXPLANATION =
  "Your traffic enters one server and leaves from another, so sites see the exit server's " +
  'address. It is not onion routing: the entry server can see your IP address and the ' +
  'destinations you connect to.';

interface MultiHopServerPairProps {
  entry: Server | null;
  exit: Server | null;
  sameServer: boolean;
  disabled: boolean;
  /** A session is up (or coming up) on this route: it cannot change now (W2-010). */
  routeLocked: boolean;
  onPickEntry: () => void;
  onPickExit: () => void;
}

export function MultiHopServerPair({
  entry,
  exit,
  sameServer,
  disabled,
  routeLocked,
  onPickEntry,
  onPickExit,
}: MultiHopServerPairProps) {
  return (
    <div className="w-full">
      <MultiHopServerCard label="Entry server" server={entry} disabled={disabled || routeLocked} onClick={onPickEntry} />
      <div className="flex justify-center py-1.5">
        <ArrowDown size={16} color={white.w40} aria-hidden />
      </div>
      <MultiHopServerCard label="Exit server" server={exit} disabled={disabled || routeLocked} onClick={onPickExit} />
      {sameServer && (
        <p className="mt-1.5 text-[11px]" style={{ color: status.red }}>
          Entry and exit must be different servers.
        </p>
      )}
      <p className="mt-1.5 flex items-start gap-1.5 text-[11px] leading-snug" style={{ color: white.w60 }}>
        <Info size={12} color={white.w60} aria-hidden className="mt-0.5 shrink-0" />
        <span>{routeLocked ? 'Disconnect to change your route.' : MULTI_HOP_EXPLANATION}</span>
      </p>
    </div>
  );
}

function MultiHopServerCard({
  label,
  server,
  disabled,
  onClick,
}: {
  label: string;
  server: Server | null;
  disabled: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      aria-label={`${label}: ${server ? serverLabel(server) : 'not chosen'}`}
      className="w-full text-left transition-opacity disabled:opacity-60"
    >
      <BirdoCard cornerRadius={16} padding="0.75rem">
        <div className="flex items-center gap-3">
          <span
            className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl text-[20px]"
            style={{ backgroundColor: white.w05, border: `1px solid ${hairline.soft}` }}
            aria-hidden
          >
            {server ? countryCodeToFlag(server.countryCode) : '🌐'}
          </span>
          <div className="min-w-0 flex-1">
            <div className="text-[10px] font-bold uppercase tracking-wider" style={{ color: brand.accentLight }}>
              {label}
            </div>
            <div className="mt-0.5 truncate text-sm font-semibold" style={{ color: white.w100 }}>
              {server ? serverTitle(server) : 'Choose…'}
            </div>
            {server && serverSubtitle(server) && (
              <div className="truncate text-xs" style={{ color: white.w60 }}>
                {serverSubtitle(server)}
              </div>
            )}
          </div>
          <ChevronRight size={18} color={white.w40} aria-hidden />
        </div>
      </BirdoCard>
    </button>
  );
}
