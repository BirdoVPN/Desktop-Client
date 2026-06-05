/**
 * ServerListScreen — pushed sub-screen mirroring mobile's `ServerListScreen.kt`.
 *
 * Layout:
 *  - BirdoTopBar (title "Servers", subtitle "N of M servers", back → popRoute,
 *    Refresh BirdoIconAction)
 *  - BirdoTextField search (leading Search icon, clear trailing)
 *  - Horizontal filter pills: All / Favorites / Streaming / P2P
 *    (rounded-20, active = purpleBg fill + purpleSoft border + purple text)
 *  - Loading bar (indeterminate) while refreshing
 *  - Scrollable list of reused ServerCard rows (sorted: favorites → online →
 *    load → name). Offline rows are dimmed + non-interactive (handled by card).
 *  - BirdoEmptyState for empty results, with a Retry when no servers loaded.
 *
 * Selecting an online server invokes connect_vpn { serverId } then setTab('home').
 * Servers/favorites read from the store; favorite toggles store.favoriteServers.
 * Server load + ping fetched via get_servers / ping_server exactly like Dashboard.
 */
import { useState, useMemo, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useShallow } from 'zustand/react/shallow';
import { Search, X, RefreshCw, Server as ServerIcon } from 'lucide-react';
import { useAppStore, ConnectionState, type Server } from '@/store/app-store';
import {
  BirdoTopBar,
  BirdoIconAction,
  BirdoTextField,
  BirdoEmptyState,
  BirdoButton,
  ServerCard,
} from '@/components/birdo';
import { brand, white } from '@/lib/birdo-theme';
import { friendlyVpnError } from '@/utils/helpers';

// Shape returned by the Rust `get_servers` command (mixed casing tolerated).
interface RustServer {
  id: string;
  name: string;
  country: string;
  country_code?: string;
  countryCode?: string;
  city: string;
  hostname?: string;
  ip_address?: string;
  ipAddress?: string;
  port?: number;
  load?: number;
  is_premium?: boolean;
  is_streaming?: boolean;
  is_p2p?: boolean;
  is_online?: boolean;
  accessible?: boolean;
}

type FilterId = 'all' | 'favorites' | 'streaming' | 'p2p';

interface FilterDef {
  id: FilterId;
  label: string;
  marker: string; // ★ / 🎬 / ⬇ — empty for All
}

const FILTERS: FilterDef[] = [
  { id: 'all', label: 'All', marker: '' },
  { id: 'favorites', label: 'Favorites', marker: '★' },
  { id: 'streaming', label: 'Streaming', marker: '🎬' },
  { id: 'p2p', label: 'P2P', marker: '⬇' },
];

export function ServerListScreen() {
  const {
    servers,
    favoriteServers,
    currentServer,
    setServers,
    setServerPing,
    toggleFavorite,
    setConnectionState,
    setCurrentServer,
    setErrorMessage,
    setVpnIp,
    setTab,
    popRoute,
  } = useAppStore(
    useShallow((s) => ({
      servers: s.servers,
      favoriteServers: s.favoriteServers,
      currentServer: s.currentServer,
      setServers: s.setServers,
      setServerPing: s.setServerPing,
      toggleFavorite: s.toggleFavorite,
      setConnectionState: s.setConnectionState,
      setCurrentServer: s.setCurrentServer,
      setErrorMessage: s.setErrorMessage,
      setVpnIp: s.setVpnIp,
      setTab: s.setTab,
      popRoute: s.popRoute,
    }))
  );

  const [searchQuery, setSearchQuery] = useState('');
  const [activeFilter, setActiveFilter] = useState<FilterId>('all');
  const [isLoading, setIsLoading] = useState(false);

  const favoriteSet = useMemo(() => new Set(favoriteServers), [favoriteServers]);

  // ── Load servers + ping (mirrors Dashboard's get_servers / ping_server) ──
  const loadServers = useCallback(async () => {
    setIsLoading(true);
    try {
      const raw = await invoke<RustServer[]>('get_servers');
      const mapped: Server[] = raw.map((s) => ({
        id: s.id,
        name: s.name,
        country: s.country,
        countryCode: s.country_code || s.countryCode || '',
        city: s.city,
        hostname: s.hostname,
        ipAddress: s.ip_address || s.ipAddress,
        port: s.port,
        load: s.load ?? 0,
        ping: undefined,
        isPremium: s.is_premium ?? false,
        isStreaming: s.is_streaming ?? false,
        isP2p: s.is_p2p ?? false,
        isOnline: s.is_online ?? true,
        isAccessible: s.accessible ?? true,
      }));
      setServers(mapped);

      const PING_BATCH = 5;
      const pingable = mapped.filter((srv) => srv.hostname || srv.ipAddress);
      for (let i = 0; i < pingable.length; i += PING_BATCH) {
        const batch = pingable.slice(i, i + PING_BATCH);
        await Promise.allSettled(
          batch.map((srv) =>
            invoke<number | null>('ping_server', {
              hostname: srv.hostname || srv.ipAddress,
              port: srv.port ?? 51820,
            }).then((p) => {
              if (p != null) setServerPing(srv.id, p);
            })
          )
        );
      }
    } catch {
      /* silent — the empty state offers a manual retry */
    } finally {
      setIsLoading(false);
    }
  }, [setServers, setServerPing]);

  // Fetch on mount only if the store has no servers yet (Dashboard usually
  // pre-populates them); the Refresh action always re-fetches.
  useEffect(() => {
    if (servers.length === 0) {
      void loadServers();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // ── Filter + sort (favorites → online → load → name) ─────────────────────
  const filteredServers = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return servers
      .filter((server) => {
        const matchesSearch =
          q === '' ||
          server.name.toLowerCase().includes(q) ||
          server.country.toLowerCase().includes(q) ||
          server.city.toLowerCase().includes(q);

        const matchesFilter =
          activeFilter === 'all'
            ? true
            : activeFilter === 'favorites'
            ? favoriteSet.has(server.id)
            : activeFilter === 'streaming'
            ? server.isStreaming
            : /* p2p */ server.isP2p;

        return matchesSearch && matchesFilter;
      })
      .sort((a, b) => {
        const favA = favoriteSet.has(a.id) ? 1 : 0;
        const favB = favoriteSet.has(b.id) ? 1 : 0;
        if (favA !== favB) return favB - favA;
        const onA = a.isOnline ? 0 : 1;
        const onB = b.isOnline ? 0 : 1;
        if (onA !== onB) return onA - onB;
        if (a.load !== b.load) return a.load - b.load;
        return a.name.localeCompare(b.name);
      });
  }, [servers, searchQuery, activeFilter, favoriteSet]);

  // ── Select an online server → connect → jump home ────────────────────────
  const handleSelect = useCallback(
    async (server: Server) => {
      if (!server.isOnline) return;
      setConnectionState('connecting' as ConnectionState);
      setCurrentServer(server);
      setErrorMessage(null);
      setTab('home');
      try {
        await invoke<boolean>('connect_vpn', { serverId: server.id });
        setConnectionState('connected' as ConnectionState);
      } catch (err) {
        setErrorMessage(friendlyVpnError(err));
        setConnectionState('error' as ConnectionState);
        setCurrentServer(null);
        setVpnIp(null);
      }
    },
    [setConnectionState, setCurrentServer, setErrorMessage, setVpnIp, setTab]
  );

  const emptyTitle =
    activeFilter === 'favorites'
      ? 'No favorite servers'
      : searchQuery.trim()
      ? `No servers match "${searchQuery.trim()}"`
      : 'No servers available';

  const emptyDescription =
    activeFilter === 'favorites'
      ? 'Tap the star on a server to add it here.'
      : servers.length === 0
      ? 'Pull to refresh or tap retry.'
      : undefined;

  const showRetry = servers.length === 0 && !isLoading;

  return (
    <div className="flex h-full flex-col">
      {/* ── Header ── */}
      <BirdoTopBar
        title="Servers"
        subtitle={`${filteredServers.length} of ${servers.length} servers`}
        onBack={popRoute}
        actions={
          <BirdoIconAction
            icon={RefreshCw}
            contentDescription="Refresh servers"
            onClick={() => void loadServers()}
            disabled={isLoading}
          />
        }
      />

      {/* ── Search ── */}
      <BirdoTextField
        value={searchQuery}
        onChange={setSearchQuery}
        placeholder="Search servers..."
        ariaLabel="Search servers"
        leadingIcon={Search}
        className="px-4 py-2.5"
        trailing={
          searchQuery ? (
            <button
              type="button"
              onClick={() => setSearchQuery('')}
              aria-label="Clear search"
              className="flex h-6 w-6 items-center justify-center rounded-full transition-colors hover:bg-white/5"
            >
              <X size={16} color={white.w40} aria-hidden />
            </button>
          ) : undefined
        }
      />

      {/* ── Filter pills ── */}
      <div className="flex gap-2 overflow-x-auto px-4 py-1">
        {FILTERS.map((filter) => {
          const isActive = filter.id === activeFilter;
          const favCount =
            filter.id === 'favorites' ? favoriteServers.length : null;
          const text =
            (filter.marker ? `${filter.marker} ` : '') +
            filter.label +
            (favCount != null && favCount > 0 ? ` (${favCount})` : '');
          return (
            <button
              key={filter.id}
              type="button"
              role="tab"
              aria-selected={isActive}
              onClick={() => setActiveFilter(filter.id)}
              className="shrink-0 whitespace-nowrap px-3.5 py-2 text-xs transition-colors"
              style={{
                borderRadius: 20,
                backgroundColor: isActive ? brand.purpleBg : white.w05,
                border: `1px solid ${isActive ? brand.purpleSoft : 'rgba(255,255,255,0.08)'}`,
                color: isActive ? brand.purpleLight : white.w60,
                fontWeight: isActive ? 600 : 500,
              }}
            >
              {text}
            </button>
          );
        })}
      </div>

      {/* ── Loading bar ── */}
      <div className="h-0.5 w-full overflow-hidden" style={{ backgroundColor: white.w05 }}>
        {isLoading && (
          <div
            className="h-full w-full animate-pulse"
            style={{ backgroundColor: brand.purpleSoft }}
          />
        )}
      </div>

      {/* ── Server list ── */}
      <div className="flex-1 space-y-1.5 overflow-y-auto px-4 py-2">
        {filteredServers.map((server) => (
          <ServerCard
            key={server.id}
            server={server}
            selected={server.id === currentServer?.id}
            isFavorite={favoriteSet.has(server.id)}
            onSelect={() => void handleSelect(server)}
            onToggleFavorite={() => toggleFavorite(server.id)}
          />
        ))}

        {/* ── Empty state ── */}
        {filteredServers.length === 0 && !isLoading && (
          <BirdoEmptyState
            icon={ServerIcon}
            title={emptyTitle}
            description={emptyDescription}
            className="pt-8"
            action={
              showRetry ? (
                <BirdoButton
                  text="Retry"
                  variant="secondary"
                  icon={RefreshCw}
                  onClick={() => void loadServers()}
                />
              ) : undefined
            }
          />
        )}
      </div>
    </div>
  );
}
