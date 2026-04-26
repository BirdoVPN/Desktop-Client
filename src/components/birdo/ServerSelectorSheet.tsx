/**
 * ServerSelectorSheet — modal bottom sheet for picking a server, mirroring
 * `ServerSelectorSheet.kt` from mobile. Triggered from the Connect screen's
 * server selector card. Replaces the standalone Servers tab.
 */
import { useMemo, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, X, Star, Film, Download, Signal } from 'lucide-react';
import type { Server } from '@/store/app-store';
import { surface, white, hairline, brand } from '@/lib/birdo-theme';
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
            className="absolute inset-0 z-40 bg-black/60 backdrop-blur-sm"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={onDismiss}
            aria-hidden
          />
          {/* Sheet */}
          <motion.div
            className="absolute inset-x-0 bottom-0 z-50 flex max-h-[88%] flex-col rounded-t-3xl"
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
            <div className="flex items-center justify-between px-5 py-1">
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
                  type="text"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  placeholder="Search by country or city"
                  aria-label="Search servers"
                  className="w-full rounded-xl py-2.5 pl-9 pr-9 text-sm outline-none transition focus:ring-1"
                  style={{
                    backgroundColor: white.w05,
                    color: white.w100,
                    border: `1px solid ${hairline.soft}`,
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
            <div className="flex gap-2 overflow-x-auto px-4 py-1">
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
                      backgroundColor: active ? 'rgba(168,85,247,0.22)' : white.w05,
                      color: active ? brand.purpleSoft : white.w60,
                      border: `1px solid ${active ? 'rgba(168,85,247,0.55)' : hairline.soft}`,
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
                <ul className="space-y-1.5">
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
    server.load < 50 ? '#4ADE80' : server.load < 80 ? '#FACC15' : '#F87171';

  return (
    <li>
      <button
        type="button"
        onClick={onSelect}
        disabled={!server.isOnline}
        aria-label={`Connect to ${server.city}, ${server.country}`}
        className="flex w-full items-center gap-3 rounded-xl px-3 py-2.5 text-left transition-colors disabled:opacity-50"
        style={{
          backgroundColor: isSelected ? 'rgba(168,85,247,0.12)' : white.w05,
          border: `1px solid ${isSelected ? 'rgba(168,85,247,0.45)' : hairline.soft}`,
        }}
      >
        <span
          className="flex h-8 w-8 shrink-0 items-center justify-center rounded text-base"
          style={{ backgroundColor: white.w10 }}
          title={server.country}
        >
          {countryCodeToFlag(server.countryCode)}
        </span>

        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-1.5">
            <span
              className="truncate text-sm font-medium"
              style={{ color: white.w100 }}
            >
              {server.city}
            </span>
            {server.isStreaming && <Film size={11} color={brand.purple} />}
            {server.isP2p && <Download size={11} color="#3B82F6" />}
          </span>
          <span className="block truncate text-xs" style={{ color: white.w60 }}>
            {server.country}
          </span>
        </span>

        <span className="flex shrink-0 items-center gap-2.5 text-xs">
          {server.ping != null && (
            <span style={{ color: white.w60 }}>{server.ping}ms</span>
          )}
          <span className="flex items-center gap-1" style={{ color: loadColor }}>
            <Signal size={11} />
            {server.load}%
          </span>
        </span>

        <span
          role="button"
          tabIndex={0}
          aria-label={isFavorite ? 'Remove favorite' : 'Add favorite'}
          onClick={(e) => {
            e.stopPropagation();
            onToggleFavorite();
          }}
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault();
              e.stopPropagation();
              onToggleFavorite();
            }
          }}
          className="ml-1 flex h-7 w-7 shrink-0 items-center justify-center rounded hover:bg-white/5"
        >
          <Star
            size={14}
            color={isFavorite ? '#FACC15' : white.w40}
            fill={isFavorite ? '#FACC15' : 'none'}
          />
        </span>
      </button>
    </li>
  );
}
