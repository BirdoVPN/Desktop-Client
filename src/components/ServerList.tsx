import { useState, useMemo } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { useAppStore, Server } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';
import { Search, Star, Zap, Film, Download, Signal, Server as ServerIcon } from 'lucide-react';
import { countryCodeToFlag } from '@/utils/helpers';

export function ServerList() {
  const [searchQuery, setSearchQuery] = useState('');
  const [filter, setFilter] = useState<'all' | 'favorites' | 'streaming' | 'p2p'>('all');
  const {
    servers,
    favoriteServers,
    currentServer,
    toggleFavorite,
    setCurrentServer,
    setConnectionState,
    setErrorMessage,
  } = useAppStore(
    useShallow((s) => ({
      servers: s.servers,
      favoriteServers: s.favoriteServers,
      currentServer: s.currentServer,
      toggleFavorite: s.toggleFavorite,
      setCurrentServer: s.setCurrentServer,
      setConnectionState: s.setConnectionState,
      setErrorMessage: s.setErrorMessage,
    }))
  );

  const filteredServers = useMemo(() => {
    let result = servers;

    // Apply search
    if (searchQuery) {
      const query = searchQuery.toLowerCase();
      result = result.filter(
        (s) =>
          s.name.toLowerCase().includes(query) ||
          s.country.toLowerCase().includes(query) ||
          s.city.toLowerCase().includes(query)
      );
    }

    // Apply filter
    switch (filter) {
      case 'favorites':
        result = result.filter((s) => favoriteServers.includes(s.id));
        break;
      case 'streaming':
        result = result.filter((s) => s.isStreaming);
        break;
      case 'p2p':
        result = result.filter((s) => s.isP2p);
        break;
    }

    // Sort: favorites first → online → lowest load → alphabetical
    // Matches Android ServerListScreen.kt sorting
    return [...result].sort((a, b) => {
      // Favorites first
      const aFav = favoriteServers.includes(a.id) ? 0 : 1;
      const bFav = favoriteServers.includes(b.id) ? 0 : 1;
      if (aFav !== bFav) return aFav - bFav;

      // Online servers before offline
      if (a.isOnline !== b.isOnline) return a.isOnline ? -1 : 1;

      // Lowest load first
      if (a.load !== b.load) return a.load - b.load;

      // Alphabetical by country, then city
      const countryCompare = a.country.localeCompare(b.country);
      if (countryCompare !== 0) return countryCompare;
      return a.city.localeCompare(b.city);
    });
  }, [servers, searchQuery, filter, favoriteServers]);

  const handleConnect = async (server: Server) => {
    if (!server.isOnline) return;
    const state = useAppStore.getState().connectionState;
    if (state === 'connecting' || state === 'connected' || state === 'disconnecting') return;

    setConnectionState('connecting');
    setCurrentServer(server);
    setErrorMessage(null);

    try {
      await invoke('connect_vpn', { serverId: server.id });
      setConnectionState('connected');
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      setErrorMessage(msg);
      setConnectionState('error');
      setCurrentServer(null);
    }
  };

  const getLoadColor = (load: number) => {
    if (load < 50) return 'text-green-400';
    if (load < 80) return 'text-yellow-400';
    return 'text-red-400';
  };

  return (
    <div className="flex h-full flex-col">
      {/* Search bar */}
      <div className="border-b border-white/5 p-4">
        <div className="relative">
          <Search
            size={18}
            className="absolute left-3 top-1/2 -translate-y-1/2 text-white/40"
          />
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder="Search servers..."
            className="w-full rounded-lg glass-input py-2 pl-10 pr-4 text-sm text-white placeholder-white/30 outline-none"
          />
        </div>

        {/* Filter tabs */}
        <div className="mt-3 flex gap-2">
          {[
            { key: 'all', label: 'All' },
            { key: 'favorites', label: 'Favorites', icon: Star },
            { key: 'streaming', label: 'Streaming', icon: Film },
            { key: 'p2p', label: 'P2P', icon: Download },
          ].map(({ key, label, icon: Icon }) => (
            <button
              key={key}
              onClick={() => setFilter(key as any)}
              className={`flex items-center gap-1 rounded-full px-3 py-1 text-xs transition ${
                filter === key
                  ? 'bg-white/10 text-white border border-white/20'
                  : 'text-white/60 hover:text-white'
              }`}
            >
              {Icon && <Icon size={12} />}
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Server list */}
      <div className="flex-1 overflow-y-auto">
        {filteredServers.length === 0 ? (
          <div className="flex h-full flex-col items-center justify-center gap-3 text-white/60">
            <ServerIcon size={48} className="text-white/20" />
            <p>No servers found</p>
            <p className="text-xs text-white/60">
              {filter === 'favorites'
                ? 'Star some servers to see them here'
                : 'Try refreshing or check your connection'}
            </p>
          </div>
        ) : (
          <div className="p-2 space-y-2">
            {filteredServers.map((server) => (
              <div
                key={server.id}
                role="button"
                tabIndex={0}
                aria-label={`Connect to ${server.city}, ${server.country}${server.isPremium ? ' (Premium)' : ''}`}
                className={`server-item flex cursor-pointer items-center gap-3 px-4 py-3 rounded-xl glass-card focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/50 ${
                  currentServer?.id === server.id
                    ? 'ring-1 ring-white/20'
                    : ''
                } ${!server.isOnline ? 'opacity-50' : ''}`}
                onClick={() => handleConnect(server)}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); handleConnect(server); } }}
              >
                {/* Country Flag */}
                <span className="flex h-8 w-8 items-center justify-center rounded bg-white/10 text-base" title={server.country}>
                  {countryCodeToFlag(server.countryCode)}
                </span>

                {/* Info */}
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-white">{server.city}</span>
                    {server.isPremium && (
                      <Zap size={12} className="text-yellow-400" />
                    )}
                    {server.isStreaming && (
                      <Film size={12} className="text-purple-400" />
                    )}
                    {server.isP2p && (
                      <Download size={12} className="text-blue-400" />
                    )}
                  </div>
                  <span className="text-xs text-white/60">{server.country}</span>
                </div>

                {/* Load & ping */}
                <div className="flex items-center gap-3 text-xs">
                  {server.ping && (
                    <span className="text-white/60">{server.ping}ms</span>
                  )}
                  <div className="flex items-center gap-1">
                    <Signal size={12} className={getLoadColor(server.load)} />
                    <span className={getLoadColor(server.load)}>{server.load}%</span>
                  </div>
                </div>

                {/* Favorite button */}
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    toggleFavorite(server.id);
                  }}
                  aria-label={favoriteServers.includes(server.id) ? `Remove ${server.city} from favorites` : `Add ${server.city} to favorites`}
                  className="p-1 rounded focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-white/50"
                >
                  <Star
                    size={16}
                    className={`transition ${
                      favoriteServers.includes(server.id)
                        ? 'fill-yellow-400 text-yellow-400'
                        : 'text-white/30 hover:text-yellow-400'
                    }`}
                  />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
