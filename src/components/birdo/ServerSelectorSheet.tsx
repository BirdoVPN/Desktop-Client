/**
 * ServerSelectorSheet — modal bottom sheet for picking a server, mirroring
 * `ServerSelectorSheet.kt` from mobile. Triggered from the Connect screen's
 * server selector card. Replaces the standalone Servers tab.
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, X, Star, Film, Download, Signal, Lock } from 'lucide-react';
import type { Server } from '@/store/app-store';
import { surface, white, hairline, brand, status } from '@/lib/birdo-theme';
import { countryCodeToFlag } from '@/utils/helpers';

type Filter = 'all' | 'favorites' | 'streaming' | 'p2p';

const FILTERS: { key: Filter; label: string; emoji?: string }[] = [
  { key: 'all',        label: 'All' },
  { key: 'favorites',  label: 'Favorites', emoji: '★' },
  { key: 'streaming',  label: 'Streaming', emoji: '🎬' },
  { key: 'p2p',        label: 'P2P',       emoji: '⇅' },
];

export interface ServerSelectorSheetProps {
  open: boolean;
  servers: Server[];
  selectedServerId?: string | null;
  favoriteServers: string[];
  onSelect: (server: Server) => void;
  onToggleFavorite: (serverId: string) => void;
  onDismiss: () => void;
}

export function ServerSelectorSheet({
  open,
  servers,
  selectedServerId,
  favoriteServers,
  onSelect,
  onToggleFavorite,
  onDismiss,
}: ServerSelectorSheetProps) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<Filter>('all');
  const searchRef = useRef<HTMLInputElement>(null);

  // Reset + focus on open. The component stays mounted, so without this the sheet
  // reopens holding the previous session's search text and filter — and the user
  // has to click into the box before typing, in the app's most-used flow.
  useEffect(() => {
    if (!open) return;
    setQuery('');
    setFilter('all');
    const id = requestAnimationFrame(() => searchRef.current?.focus());
    return () => cancelAnimationFrame(id);
  }, [open]);

  // Escape closes, like every other dialog convention.
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        onDismiss();
      }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [open, onDismiss]);

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
          : filter === 'streaming' ? s.isStreaming
          : filter === 'p2p' ? s.isP2p
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

  return (
    <AnimatePresence>
      {open && (
        <>
          {/* Scrim */}
          <motion.div
            className="absolute inset-0 z-40 bg-black/80"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={onDismiss}
            aria-hidden
          />
          {/* Sheet */}
          <motion.div
            className="absolute inset-x-0 bottom-0 z-50 flex h-[92%] flex-col rounded-t-3xl"
            style={{
              backgroundColor: surface.s3,
              border: `1px solid ${hairline.soft}`,
              borderBottom: 'none',
            }}
            role="dialog"
            aria-label="Choose a server"
            initial={{ y: '100%' }}
            animate={{ y: 0 }}
            exit={{ y: '100%' }}
            transition={{ type: 'spring', damping: 28, stiffness: 280 }}
          >
            {/* Drag handle */}
            <div className="flex justify-center pt-2 pb-1">
              <span
                className="h-1 w-10 rounded-full"
                style={{ backgroundColor: hairline.strong }}
              />
            </div>

            {/* Header */}
            <div className="flex items-center justify-between px-5 py-2">
              <div className="min-w-0">
                <h2 className="text-lg font-semibold" style={{ color: white.w100 }}>
                  Choose a server
                </h2>
                <p className="text-xs" style={{ color: white.w60 }}>
                  {filtered.length} of {servers.length} servers
                </p>
              </div>
              <button
                type="button"
                onClick={onDismiss}
                aria-label="Close"
                className="flex h-9 w-9 items-center justify-center rounded-full transition-colors hover:bg-white/5"
              >
                <X size={18} color={white.w60} />
              </button>
            </div>

            {/* Search */}
            <div className="px-4 py-2">
              <div className="relative">
                <Search
                  size={16}
                  className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2"
                  color={white.w40}
                />
                <input
                  ref={searchRef}
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search by country or city"
                  aria-label="Search servers"
                  className="w-full rounded-xl py-3 pl-9 pr-9 text-sm outline-none transition"
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
                    <X size={14} color={white.w40} />
                  </button>
                )}
              </div>
            </div>

            {/* Filter pills */}
            <div className="flex gap-2 overflow-x-auto px-4 py-2">
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
                    role="tab"
                    aria-selected={active}
                    className="shrink-0 rounded-full px-3.5 py-2 text-xs font-medium transition-colors"
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
            <div className="flex-1 overflow-y-auto px-3 py-2">
              {filtered.length === 0 ? (
                <div className="flex h-32 flex-col items-center justify-center gap-2 text-center">
                  <p className="text-sm" style={{ color: white.w60 }}>
                    No servers match
                  </p>
                  <p className="text-xs" style={{ color: white.w40 }}>
                    {filter === 'favorites'
                      ? 'Star some servers to see them here'
                      : 'Try a different search or filter'}
                  </p>
                </div>
              ) : (
                <ul className="space-y-2.5 pb-2">
                  {filtered.map((server) => (
                    <ServerRow
                      key={server.id}
                      server={server}
                      isSelected={server.id === selectedServerId}
                      isFavorite={favoriteServers.includes(server.id)}
                      onSelect={() => {
                        onSelect(server);
                        onDismiss();
                      }}
                      onToggleFavorite={() => onToggleFavorite(server.id)}
                    />
                  ))}
                </ul>
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}

// ── Row ───────────────────────────────────────────────────────────────────

interface ServerRowProps {
  server: Server;
  isSelected: boolean;
  isFavorite: boolean;
  onSelect: () => void;
  onToggleFavorite: () => void;
}

function ServerRow({
  server,
  isSelected,
  isFavorite,
  onSelect,
  onToggleFavorite,
}: ServerRowProps) {
  const loadColor =
    server.load < 50 ? status.greenLight : server.load < 80 ? status.yellowLight : status.red;

  const selectable = server.isOnline && server.isAccessible;
  const hasPing =
    server.ping != null && Number.isFinite(server.ping) && server.ping >= 0;

  // The star is a SIBLING of the row button, not a child of it. It used to be a
  // span[role=button] nested inside the row <button> — invalid HTML, a doubled
  // tab stop, and, because the row is disabled for offline/plan-locked servers,
  // completely inert exactly where it mattered most: you could not favourite the
  // premium location you were thinking of upgrading for.
  return (
    <li
      className="flex items-center gap-1 rounded-xl pr-1"
      style={{
        backgroundColor: isSelected ? 'rgba(16,185,129,0.12)' : white.w05,
        border: `1px solid ${isSelected ? 'rgba(16,185,129,0.45)' : hairline.soft}`,
      }}
    >
      <button
        type="button"
        onClick={onSelect}
        disabled={!selectable}
        aria-label={`Connect to ${server.city}, ${server.country}`}
        className="flex min-w-0 flex-1 items-center gap-3.5 rounded-xl px-3.5 py-4 text-left transition-opacity disabled:cursor-not-allowed disabled:opacity-50"
      >
        <span
          className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl text-2xl"
          style={{ backgroundColor: white.w10 }}
          title={server.country}
        >
          {countryCodeToFlag(server.countryCode)}
        </span>

        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-1.5">
            <span
              className="truncate text-[15px] font-semibold"
              style={{ color: white.w100 }}
            >
              {server.city}
            </span>
            {server.isStreaming && <Film size={12} color={brand.accent} />}
            {server.isP2p && <Download size={12} color={status.blue} />}
          </span>
          <span className="mt-0.5 block truncate text-xs" style={{ color: white.w60 }}>
            {server.country}
          </span>
        </span>

        <span className="flex shrink-0 items-center gap-2.5 text-xs">
          {!server.isAccessible && (
            <span className="flex items-center gap-1" style={{ color: white.w55 }}>
              <Lock size={11} />
              Locked
            </span>
          )}
          {/* Shown for locked rows too — latency is the whole reason to care
              about a location you don't have access to yet. */}
          {hasPing && (
            <span style={{ color: server.isAccessible ? white.w60 : white.w55 }}>
              {server.ping}ms
            </span>
          )}
          <span className="flex items-center gap-1" style={{ color: loadColor }}>
            <Signal size={11} />
            {server.load}%
          </span>
        </span>
      </button>

      <button
        type="button"
        aria-label={
          isFavorite
            ? `Remove ${server.city} from favorites`
            : `Add ${server.city} to favorites`
        }
        aria-pressed={isFavorite}
        onClick={onToggleFavorite}
        className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg transition-colors hover:bg-white/10"
      >
        <Star
          size={14}
          color={isFavorite ? status.yellowLight : white.w55}
          fill={isFavorite ? status.yellowLight : 'none'}
        />
      </button>
    </li>
  );
}
