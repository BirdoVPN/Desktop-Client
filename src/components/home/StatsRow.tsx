/**
 * Four tiles: Duration, Ping, Download, Upload (the canonical labels; Ping is
 * the desktop extra). Each tile keeps a VISIBLE caption: Download vs Upload
 * used to differ only by arrow direction and tint, which is no signal for a
 * colour-blind user glancing at two byte counts.
 *
 * Subscribes to `liveStats` alone, so the 2 s counter tick re-renders this row
 * and nothing else on the screen (W2-037).
 */
import { ArrowDown, ArrowUp, Clock, Gauge, type LucideIcon } from 'lucide-react';
import { BirdoCard } from '@/components/birdo';
import { brand, status, white } from '@/lib/birdo-theme';
import { useAppStore } from '@/store/app-store';
import { formatBytes, formatUptime } from '@/utils/helpers';

export function StatsRow() {
  const stats = useAppStore((s) => s.liveStats);
  const latency = stats?.latencyMs;
  return (
    <div className="grid grid-cols-4 gap-2">
      <StatTile
        icon={Clock}
        tint={brand.accentSoft}
        label="Duration"
        value={stats ? formatUptime(stats.uptimeSeconds) : '—'}
      />
      <StatTile
        icon={Gauge}
        tint={
          latency == null ? white.w60
          : latency < 80 ? status.greenLight
          : latency < 160 ? status.yellowLight
          : status.red
        }
        label="Ping"
        value={latency != null ? `${Math.round(latency)}ms` : '—'}
      />
      <StatTile
        icon={ArrowDown}
        tint={status.greenLight}
        label="Download"
        value={stats ? formatBytes(stats.bytesIn) : '—'}
      />
      <StatTile
        icon={ArrowUp}
        tint={status.blue}
        label="Upload"
        value={stats ? formatBytes(stats.bytesOut) : '—'}
      />
    </div>
  );
}

function StatTile({ icon: Icon, tint, label, value }: { icon: LucideIcon; tint: string; label: string; value: string }) {
  return (
    <BirdoCard cornerRadius={12} padding="0.4rem 0.35rem">
      <div className="flex flex-col items-center gap-0.5">
        <div className="flex items-center gap-1">
          <Icon size={12} color={tint} aria-hidden />
          <span className="truncate text-xs font-semibold tabular-nums" style={{ color: white.w100 }}>
            {value}
          </span>
        </div>
        <span className="text-[9px] font-medium uppercase tracking-wide" style={{ color: white.w55 }}>
          {label}
        </span>
      </div>
    </BirdoCard>
  );
}
