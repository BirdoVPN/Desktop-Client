/**
 * ServerCard — reusable server row, mirroring mobile's `ServerCard` in
 * `ServerListScreen.kt`. Solid colors only (no per-row gradient brushes) so a
 * long list stays cheap to render. Offline rows are dimmed and non-interactive.
 */
import { Star } from 'lucide-react';
import type { Server } from '@/store/app-store';
import { surface, white, status, brand, hairline } from '@/lib/birdo-theme';
import { countryCodeToFlag } from '@/utils/helpers';

export interface ServerCardProps {
  server: Server;
  selected?: boolean;
  onSelect: () => void;
  onToggleFavorite: () => void;
  isFavorite: boolean;
}

function loadColor(load: number): string {
  return load < 50 ? status.greenLight : load < 80 ? status.yellowLight : status.red;
}

export function ServerCard({
  server,
  selected = false,
  onSelect,
  onToggleFavorite,
  isFavorite,
}: ServerCardProps) {
  const isOnline = server.isOnline;
  const loadFraction = Math.min(Math.max(server.load / 100, 0), 1);
  const loadCol = loadColor(server.load);
  const flag = countryCodeToFlag(server.countryCode);
  const location = server.city ? `${server.city}, ${server.country}` : server.country;

  return (
    <div
      role="button"
      tabIndex={isOnline ? 0 : -1}
      onClick={isOnline ? onSelect : undefined}
      onKeyDown={(e) => {
        if (isOnline && (e.key === 'Enter' || e.key === ' ')) {
          e.preventDefault();
          onSelect();
        }
      }}
      className="flex w-full items-center px-3 py-2.5"
      style={{
        borderRadius: 14,
        backgroundColor: selected ? surface.s2 : surface.s1,
        border: selected
          ? `1.5px solid ${brand.purpleSoft}`
          : `1px solid ${hairline.soft}`,
        opacity: isOnline ? 1 : 0.5,
        cursor: isOnline ? 'pointer' : 'default',
      }}
    >
      {/* Country flag badge */}
      <span
        className="flex h-10 w-10 shrink-0 items-center justify-center text-xl"
        style={{ borderRadius: 10, backgroundColor: white.w05 }}
        title={server.country}
      >
        {flag}
      </span>

      {/* Server info */}
      <div className="ml-3 min-w-0 flex-1">
        <div
          className="truncate text-sm font-semibold"
          style={{ color: isOnline ? white.w100 : white.w40 }}
        >
          {server.name}
        </div>
        <div className="truncate text-xs" style={{ color: white.w60 }}>
          {location}
        </div>
      </div>

      {/* Load indicator */}
      <div className="ml-2 flex shrink-0 flex-col items-end">
        <span
          className="font-mono text-[11px] font-semibold"
          style={{ color: loadCol }}
        >
          {server.load}%
        </span>
        <span
          className="mt-[3px] block h-1 w-9 overflow-hidden"
          style={{ borderRadius: 2, backgroundColor: white.w10 }}
        >
          <span
            className="block h-full"
            style={{ width: `${loadFraction * 100}%`, backgroundColor: loadCol }}
          />
        </span>
      </div>

      {/* Favorite star */}
      <button
        type="button"
        aria-label={isFavorite ? 'Remove favorite' : 'Add favorite'}
        onClick={(e) => {
          e.stopPropagation();
          onToggleFavorite();
        }}
        className="ml-1.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-full transition-colors hover:bg-white/5"
      >
        <Star
          size={18}
          color={isFavorite ? status.yellowLight : white.w40}
          fill={isFavorite ? status.yellowLight : 'none'}
        />
      </button>
    </div>
  );
}
