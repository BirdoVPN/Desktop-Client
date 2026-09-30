/**
 * ServerSelectorSheet — modal bottom sheet for picking a server, mirroring
 * `ServerSelectorSheet.kt` from mobile / iOS ServerListView. Triggered from
 * the Connect screen's selector card and the Multi-Hop Entry / Exit cards.
 *
 * States (W2-014): loading (ghost rows), load error with Retry, empty with
 * Retry, no favourites, no search results, and the list. It used to have only
 * "No servers match", shown even when nothing had loaded, behind a card that
 * refused to open on an empty list.
 */
import { useMemo, useRef, useState, type ReactNode } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, X, Star, Gauge, ArrowRightLeft, Lock, RefreshCw, Zap } from 'lucide-react';
import type { LoadStatus, Server } from '@/store/app-store';
import { surface, white, hairline, brand, status, motion as motionTokens } from '@/lib/birdo-theme';
import { countryCodeToFlag } from '@/utils/helpers';
import { useModalRoot } from '@/lib/modal';
import { titleCasePlan } from '@/lib/plan';

// "Streaming" and "P2P" are gone on purpose. Every exit IP is a datacenter ASN,
// so streaming-unblocking is undeliverable, and Birdo does not advertise
// torrenting. These two name capabilities Birdo actually ships: a low-load
// high-throughput node, and inbound port forwarding.
type Filter = 'all' | 'favorites' | 'highSpeed' | 'portForwarding';

const FILTERS: { key: Filter; label: string; emoji?: string }[] = [
  { key: 'all',            label: 'All' },
  { key: 'favorites',      label: 'Favorites',       emoji: '★' },
  { key: 'highSpeed',      label: 'High-Speed',      emoji: '⚡' },
  { key: 'portForwarding', label: 'Port Forwarding', emoji: '⇄' },
];

export interface ServerSelectorSheetProps {
  open: boolean;
  title?: string;
  servers: Server[];
  status: LoadStatus;
  pings: Record<string, number>;
  selectedServerId?: string | null;
  /** Shown as a pinned "Fastest server" row when given (single-hop only). */
  fastestServer?: Server | null;
  favoriteServers: string[];
  onSelect: (server: Server) => void;
  /** A plan-locked row was chosen: explain and offer the upgrade (W2-015). */
  onSelectLocked: (server: Server) => void;
  onToggleFavorite: (serverId: string) => void;
  onRetry: () => void;
  onDismiss: () => void;
}

export function ServerSelectorSheet(props: ServerSelectorSheetProps) {
  return <AnimatePresence>{props.open && <SheetBody {...props} />}</AnimatePresence>;
}

function SheetBody({
  title = 'Choose a server',
  servers,
  status: loadStatus,
  pings,
  selectedServerId,
  fastestServer,
  favoriteServers,
  onSelect,
  onSelectLocked,
  onToggleFavorite,
  onRetry,
  onDismiss,
}: ServerSelectorSheetProps) {
  // Mounted per open, so search and filter always start clean — the sheet
  // used to reopen holding the previous session's text.
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<Filter>('all');
  const searchRef = useRef<HTMLInputElement>(null);
  const rootRef = useModalRoot({ onEscape: onDismiss, initialFocusRef: searchRef });

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return servers
      .filter((s) => {
        const matchesSearch =
          !q ||
          s.name.toLowerCase().includes(q) ||
          s.country.toLowerCase().includes(q) ||
          s.city.toLowerCase().includes(q);
        const matchesFilter =
          filter === 'all' ? true
          : filter === 'favorites' ? favoriteServers.includes(s.id)
          : filter === 'highSpeed' ? s.isHighSpeed
          : filter === 'portForwarding' ? s.isPortForwarding
          : true;
        return matchesSearch && matchesFilter;
      })
      .sort((a, b) => {
        const aFav = favoriteServers.includes(a.id) ? 0 : 1;
        const bFav = favoriteServers.includes(b.id) ? 0 : 1;
        if (aFav !== bFav) return aFav - bFav;
        if (a.isAccessible !== b.isAccessible) return a.isAccessible ? -1 : 1;
        if (a.isOnline !== b.isOnline) return a.isOnline ? -1 : 1;
        if (a.load !== b.load) return a.load - b.load;
        return a.name.localeCompare(b.name);
      });
  }, [servers, query, filter, favoriteServers]);

  const pick = (server: Server) => {
    onSelect(server);
    onDismiss();
  };
  const showFastest = !!fastestServer && !query.trim() && filter === 'all';

  let body: ReactNode;
  if (servers.length === 0 && (loadStatus === 'loading' || loadStatus === 'idle')) {
    body = (
      <ul className="space-y-2.5 pb-2" aria-label="Loading servers…" aria-busy="true">
        {Array.from({ length: 6 }, (_, i) => (
          <li
            key={i}
            className="h-[76px] animate-pulse rounded-xl motion-reduce:animate-none"
            style={{ backgroundColor: white.w05 }}
          />
        ))}
      </ul>
    );
  } else if (servers.length === 0) {
    body = (
      <EmptyMessage
        title={loadStatus === 'error' ? "Couldn't load servers" : 'No servers available'}
        detail="Check your connection and try again."
        onRetry={onRetry}
      />
    );
  } else if (filtered.length === 0) {
    body =
      filter === 'favorites' && !query.trim() ? (
        <EmptyMessage title="No favorite servers yet" detail="Click the ★ on any server to add it." />
      ) : (
        <EmptyMessage title={query.trim() ? `No servers match "${query.trim()}"` : 'No servers match'} />
      );
  } else {
    body = (
      <ul className="space-y-2.5 pb-2">
        {showFastest && fastestServer && (
          <li>
            <button
              type="button"
              onClick={() => pick(fastestServer)}
              className="flex w-full items-center gap-3.5 rounded-xl px-3.5 py-3.5 text-left transition-colors hover:bg-white/5"
              style={{ backgroundColor: white.w05, border: `1px solid ${hairline.soft}` }}
              aria-label={`Fastest server: ${fastestServer.name}, ${fastestServer.city}, ${fastestServer.country}`}
            >
              <span
                className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl"
                style={{ backgroundColor: brand.accentBg }}
                aria-hidden
              >
                <Zap size={20} color={brand.accentLight} />
              </span>
              <span className="min-w-0 flex-1">
                <span className="block truncate text-[15px] font-semibold" style={{ color: white.w100 }}>
                  Fastest server
                </span>
                <span className="mt-0.5 block truncate text-xs" style={{ color: white.w60 }}>
                  {fastestServer.name} · {fastestServer.city}, {fastestServer.country}
                </span>
              </span>
            </button>
          </li>
        )}
        {filtered.map((server) => (
          <ServerRow
            key={server.id}
            server={server}
            ping={pings[server.id]}
            isSelected={server.id === selectedServerId}
            isFavorite={favoriteServers.includes(server.id)}
            onSelect={() => (server.isAccessible ? (server.isOnline ? pick(server) : undefined) : onSelectLocked(server))}
            onToggleFavorite={() => onToggleFavorite(server.id)}
          />
        ))}
      </ul>
    );
  }

  return (
    <motion.div
      ref={rootRef}
      className="absolute inset-0 z-40"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: motionTokens.fast }}
    >
      {/* Scrim */}
      <div className="absolute inset-0 bg-black/80" onClick={onDismiss} aria-hidden />
      {/* Sheet */}
      <motion.div
        className="absolute inset-x-0 bottom-0 flex h-[92%] flex-col rounded-t-3xl"
        style={{
          backgroundColor: surface.s3,
          border: `1px solid ${hairline.soft}`,
          borderBottom: 'none',
        }}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        initial={{ y: '100%' }}
        animate={{ y: 0 }}
        exit={{ y: '100%' }}
        transition={{ duration: motionTokens.standard, ease: motionTokens.decel }}
      >
        {/* Drag handle */}
        <div className="flex justify-center pt-2 pb-1" aria-hidden>
          <span className="h-1 w-10 rounded-full" style={{ backgroundColor: hairline.strong }} />
        </div>

        {/* Header */}
        <div className="flex items-center justify-between gap-2 px-5 py-2">
          <div className="min-w-0 flex-1">
            <h2 className="text-lg font-semibold" style={{ color: white.w100 }}>
              {title}
            </h2>
            <p className="text-xs" style={{ color: white.w60 }}>
              {servers.length > 0 ? `${filtered.length} of ${servers.length} servers` : ' '}
            </p>
          </div>
          <button
            type="button"
            onClick={onRetry}
            aria-label="Refresh server list"
            className="flex h-9 w-9 items-center justify-center rounded-full transition-colors hover:bg-white/5"
          >
            <RefreshCw size={16} color={white.w60} aria-hidden />
          </button>
          <button
            type="button"
            onClick={onDismiss}
            aria-label="Close"
            className="flex h-9 w-9 items-center justify-center rounded-full transition-colors hover:bg-white/5"
          >
            <X size={18} color={white.w60} aria-hidden />
          </button>
        </div>

        {/* A refresh that failed while an older list is still on screen. */}
        {loadStatus === 'error' && servers.length > 0 && (
          <div
            className="mx-4 mb-1 flex items-center gap-2 rounded-xl px-3 py-2 text-xs"
            style={{ backgroundColor: status.redBg, border: `1px solid ${status.redBorder}`, color: status.red }}
          >
            <span className="flex-1">Couldn't refresh the server list.</span>
            <button type="button" onClick={onRetry} className="font-semibold underline-offset-2 hover:underline">
              Retry
            </button>
          </div>
        )}

        {/* Search */}
        <div className="px-4 py-2">
          <div className="relative">
            <Search
              size={16}
              className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2"
              color={white.w40}
              aria-hidden
            />
            <input
              ref={searchRef}
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search countries or cities"
              aria-label="Search countries or cities"
              className="w-full rounded-xl py-3 pl-9 pr-9 text-sm outline-hidden transition"
              style={{
                // Solid well (matches the login fields) — the ~5% white fill
                // let the background grid bleed through.
                backgroundColor: 'rgba(16,16,23,0.85)',
                color: white.w100,
                border: `1px solid ${hairline.strong}`,
              }}
            />
            {query && (
              <button
                type="button"
                onClick={() => setQuery('')}
                aria-label="Clear search"
                className="absolute right-2 top-1/2 flex h-6 w-6 -translate-y-1/2 items-center justify-center rounded-full hover:bg-white/5"
              >
                <X size={14} color={white.w40} aria-hidden />
              </button>
            )}
          </div>
        </div>

        {/* Filter pills: a toggle group, not tabs (there are no tab panels). */}
        <div className="flex gap-2 overflow-x-auto px-4 py-2" role="group" aria-label="Filter servers">
          {FILTERS.map((f) => {
            const active = f.key === filter;
            const favCount = f.key === 'favorites' ? favoriteServers.length : null;
            const label =
              favCount && favCount > 0 ? `${f.emoji ?? ''} ${f.label} (${favCount})`
              : f.emoji ? `${f.emoji} ${f.label}`
              : f.label;
            return (
              <button
                key={f.key}
                type="button"
                onClick={() => setFilter(f.key)}
                aria-pressed={active}
                className="birdo-toggle shrink-0 rounded-full px-3.5 py-2 text-xs font-medium transition-colors"
                style={{
                  backgroundColor: active ? 'rgba(16,185,129,0.22)' : white.w05,
                  color: active ? brand.accentSoft : white.w60,
                  border: `1px solid ${active ? 'rgba(16,185,129,0.55)' : hairline.soft}`,
                  fontWeight: active ? 600 : 500,
                }}
              >
                {label}
              </button>
            );
          })}
        </div>

        {/* List */}
        <div className="flex-1 overflow-y-auto px-3 py-2">{body}</div>
      </motion.div>
    </motion.div>
  );
}

function EmptyMessage({ title, detail, onRetry }: { title: string; detail?: string; onRetry?: () => void }) {
  return (
    <div className="flex min-h-32 flex-col items-center justify-center gap-2 px-6 py-6 text-center">
      <p className="text-sm" style={{ color: white.w80 }}>
        {title}
      </p>
      {detail && (
        <p className="text-xs" style={{ color: white.w60 }}>
          {detail}
        </p>
      )}
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-1 rounded-birdo-sm px-3.5 py-2 text-[13px] font-semibold"
          style={{ backgroundColor: brand.accentBg, color: brand.accentSoft }}
        >
          Retry
        </button>
      )}
    </div>
  );
}

// ── Row ───────────────────────────────────────────────────────────────────

interface ServerRowProps {
  server: Server;
  ping: number | undefined;
  isSelected: boolean;
  isFavorite: boolean;
  onSelect: () => void;
  onToggleFavorite: () => void;
}

function ServerRow({ server, ping, isSelected, isFavorite, onSelect, onToggleFavorite }: ServerRowProps) {
  const hasPing = ping != null && Number.isFinite(ping) && ping >= 0;
  const locked = !server.isAccessible;
  const offline = !server.isOnline;
  const place = [server.city, server.country].filter(Boolean).join(', ');

  // A row that cannot be picked still has to say WHY, to a screen reader as
  // much as to the eye. `minPlan` is the node's own requirement, so the copy
  // stays right if the owner re-tiers a node.
  const lockedReason = locked
    ? server.minPlan
      ? `Locked — requires the ${titleCasePlan(server.minPlan)} plan`
      : 'Locked — requires a higher plan'
    : offline
      ? 'Offline'
      : null;
  const rowLabel = lockedReason
    ? `${server.name}, ${place} — ${lockedReason}`
    : `Connect to ${server.name}, ${place}`;

  // The star is a SIBLING of the row button, not a child: nested interactive
  // content is invalid, a doubled tab stop, and was inert exactly where it
  // mattered (you could not favourite a location you were thinking of
  // upgrading for). Locked rows are aria-disabled rather than disabled, so they
  // stay focusable and a click can explain the upgrade (W2-015).
  return (
    <li
      className="birdo-server-row flex items-center gap-1 rounded-xl pr-1"
      data-selected={isSelected || undefined}
      style={{
        backgroundColor: isSelected ? 'rgba(16,185,129,0.12)' : white.w05,
        border: `1px solid ${isSelected ? 'rgba(16,185,129,0.45)' : hairline.soft}`,
      }}
    >
      <button
        type="button"
        onClick={onSelect}
        aria-disabled={locked || offline || undefined}
        aria-current={isSelected || undefined}
        aria-label={rowLabel}
        className={`flex min-w-0 flex-1 items-center gap-3.5 rounded-xl px-3.5 py-4 text-left transition-opacity ${
          locked || offline ? 'cursor-not-allowed opacity-60' : ''
        }`}
      >
        <span
          className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl text-2xl"
          style={{ backgroundColor: white.w10 }}
          aria-hidden
        >
          {countryCodeToFlag(server.countryCode)}
        </span>

        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-1.5">
            <span className="truncate text-[15px] font-semibold" style={{ color: white.w100 }}>
              {server.name || server.city}
            </span>
            {server.isHighSpeed && <Gauge size={12} color={brand.accent} role="img" aria-label="High-speed" />}
            {server.isPortForwarding && (
              <ArrowRightLeft size={12} color={status.blue} role="img" aria-label="Port forwarding" />
            )}
          </span>
          <span className="mt-0.5 block truncate text-xs" style={{ color: white.w60 }}>
            {place}
          </span>
        </span>

        <span className="flex shrink-0 items-center gap-2.5 text-xs">
          {locked ? (
            <span className="flex items-center gap-1" style={{ color: white.w60 }}>
              <Lock size={11} aria-hidden />
              Locked
            </span>
          ) : offline ? (
            <span style={{ color: white.w60 }}>Offline</span>
          ) : null}
          {/* Shown for locked rows too — latency is a reason to care about a
              location you don't have yet. Hidden, not zero, when unmeasured. */}
          {hasPing && <span style={{ color: white.w60 }}>{ping}ms</span>}
        </span>
      </button>

      <button
        type="button"
        aria-label={isFavorite ? `Remove ${server.name} from favorites` : `Add ${server.name} to favorites`}
        aria-pressed={isFavorite}
        onClick={onToggleFavorite}
        className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition-colors hover:bg-white/10"
      >
        <Star
          size={14}
          color={isFavorite ? status.yellowLight : white.w55}
          fill={isFavorite ? status.yellowLight : 'none'}
          aria-hidden
        />
      </button>
    </li>
  );
}
