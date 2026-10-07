/**
 * Limit — the usage tab (P1-parity-009), a port of iOS LimitView / Android
 * LimitScreen. Shown to every plan: capped (Free) plans get a meter of their
 * monthly allowance, uncapped plans the "Unlimited data" state.
 *
 * It replaces Profile's "Data this month" card, which rendered NOTHING while
 * loading or after an error, had no refresh and no warning before the cap.
 *
 * Data honesty (iOS rule): never present a frozen number as live — the
 * freshness line under the meter is mandatory, and a node that has never
 * synced says "awaiting first sync" rather than showing 0.
 */
import { useEffect } from 'react';
import { useShallow } from 'zustand/react/shallow';
import { CircleAlert, Gauge, RefreshCw, Zap } from 'lucide-react';
import { BirdoButton, BirdoCard } from '@/components/birdo';
import { accentA, brand, hairline, status, surface, white } from '@/lib/birdo-theme';
import { planName } from '@/lib/plan';
import { loadUsage } from '@/session/session-data';
import { useAppStore } from '@/store/app-store';

/** "10", not "10.0", for the allowance. */
const wholeGb = (v: number) => (Number.isInteger(v) ? String(v) : v.toFixed(1));
/** ≥10 GB → integer; else up to two decimals (iOS `formatGb`). */
const formatGb = (v: number) => {
  const safe = Math.max(0, v);
  return safe >= 10 ? `${Math.round(safe)} GB` : `${Number(safe.toFixed(2))} GB`;
};

/** "Jul 31" in local time; null on anything unparseable. */
function formatResetDate(iso: string | null): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return null;
  return new Intl.DateTimeFormat('en-US', { month: 'short', day: 'numeric' }).format(d);
}

/** "just now" / "3 min ago" / "2 h ago" / "4 d ago". */
export function relativeAgo(iso: string | null, now = Date.now()): string | null {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  const secs = Math.max(0, Math.floor((now - t) / 1000));
  if (secs < 60) return 'just now';
  if (secs < 3600) return `${Math.floor(secs / 60)} min ago`;
  if (secs < 86400) return `${Math.floor(secs / 3600)} h ago`;
  return `${Math.floor(secs / 86400)} d ago`;
}

export function Limit() {
  const { usage, usageStatus, plan, pushRoute } = useAppStore(
    useShallow((s) => ({
      usage: s.usage,
      usageStatus: s.usageStatus,
      plan: s.account.plan,
      pushRoute: s.pushRoute,
    })),
  );

  // The user opened their usage on purpose: always ask for a fresh number.
  useEffect(() => {
    void loadUsage();
  }, []);

  const limitGb = usage?.bandwidthLimitGb ?? 0;
  const hasCap = limitGb > 0;
  const usedGb = Math.max(0, usage?.bandwidthUsedGb ?? 0);
  const fraction = hasCap ? Math.min(Math.max(usedGb / limitGb, 0), 1) : 0;
  const meterColor = fraction >= 0.9 ? status.red : fraction >= 0.75 ? status.yellow : brand.accent;
  const planLabel = plan ?? usage?.plan ?? null;

  return (
    <div className="h-full overflow-y-auto">
      <div className="px-5 pb-2 pt-6">
        <h1 className="text-[22px] font-semibold" style={{ color: '#FFFFFF' }}>
          Limit
        </h1>
      </div>

      <div className="flex flex-col gap-3 px-5 pb-12 pt-2">
        {/* Plan header */}
        <div>
          <div className="pl-1 text-[11px] font-semibold uppercase tracking-[1.4px]" style={{ color: white.w60 }}>
            Your plan
          </div>
          <div className="mt-1 flex items-center">
            <span className="flex-1 text-[22px] font-bold text-white">
              {planLabel ? `${planName(planLabel)} plan` : 'Checking your plan…'}
            </span>
            {usage && (
              <span
                className="rounded-full px-2.5 py-1 text-[12px] font-semibold"
                style={{ backgroundColor: accentA(0.16), color: brand.accentSoft }}
              >
                {hasCap ? `${wholeGb(limitGb)} GB / month` : 'Unlimited'}
              </span>
            )}
          </div>
        </div>

        {usageStatus === 'error' && (
          <div
            role="alert"
            className="flex items-center gap-2.5 rounded-2xl px-3.5 py-3"
            style={{ backgroundColor: status.redBg, border: `1px solid ${status.redBorder}` }}
          >
            <CircleAlert size={18} color={status.red} aria-hidden className="shrink-0" />
            <p className="flex-1 text-xs" style={{ color: status.red }}>
              {usage ? "Couldn't refresh your usage. Showing the last reading." : "Couldn't load your usage."}
            </p>
            <button
              type="button"
              onClick={() => void loadUsage()}
              className="shrink-0 rounded-birdo-xs px-2 py-1 text-xs font-semibold"
              style={{ color: status.red, border: `1px solid ${status.redBorder}` }}
            >
              Retry
            </button>
          </div>
        )}

        <BirdoCard cornerRadius={20} padding="18px">
          {!usage ? (
            <div className="flex flex-col items-center gap-3 py-10" aria-busy={usageStatus === 'loading'}>
              {usageStatus === 'error' ? (
                <Gauge size={28} color={white.w60} aria-hidden />
              ) : (
                <span
                  className="h-7 w-7 animate-spin rounded-full border-2 motion-reduce:animate-none"
                  style={{ borderColor: brand.accent, borderTopColor: 'transparent' }}
                  aria-hidden
                />
              )}
              <p className="text-[13px]" style={{ color: white.w60 }}>
                {usageStatus === 'error' ? 'Usage is unavailable right now.' : 'Loading your usage…'}
              </p>
            </div>
          ) : !hasCap ? (
            <div className="flex flex-col items-center gap-3 py-5 text-center">
              <span
                className="flex h-14 w-14 items-center justify-center rounded-full"
                style={{ backgroundColor: accentA(0.14) }}
              >
                <Gauge size={28} color={brand.accent} aria-hidden />
              </span>
              <p className="text-[18px] font-semibold text-white">Unlimited data</p>
              <p className="text-[13px]" style={{ color: white.w60 }}>
                Your plan has no data cap — use as much as you like.
              </p>
            </div>
          ) : (
            <CappedMeter
              usedGb={usedGb}
              limitGb={limitGb}
              fraction={fraction}
              color={meterColor}
              periodEnd={usage.bandwidthPeriodEnd}
              lastSyncAt={usage.bandwidthLastSyncAt}
              isFresh={usage.bandwidthIsFresh === true}
              refreshing={usageStatus === 'loading'}
            />
          )}
        </BirdoCard>

        {usage && hasCap && (
          <BirdoCard cornerRadius={20} padding="18px">
            <div className="flex flex-col gap-2.5">
              <div className="flex items-center gap-2.5">
                <span
                  className="flex h-[34px] w-[34px] items-center justify-center rounded-[9px]"
                  style={{ backgroundColor: accentA(0.14) }}
                >
                  <Zap size={18} color={brand.accent} aria-hidden />
                </span>
                <span className="text-[15px] font-semibold text-white">
                  {fraction >= 0.9 ? "You're almost out of data" : 'Need more data?'}
                </span>
              </div>
              <p className="text-[13px]" style={{ color: white.w60 }}>
                Free accounts include {wholeGb(limitGb)} GB per month. Paid plans include unlimited
                data on every server.
              </p>
              <BirdoButton text="View plans" variant="secondary" fullWidth onClick={() => pushRoute('pricing')} />
            </div>
          </BirdoCard>
        )}
      </div>
    </div>
  );
}

function CappedMeter({
  usedGb,
  limitGb,
  fraction,
  color,
  periodEnd,
  lastSyncAt,
  isFresh,
  refreshing,
}: {
  usedGb: number;
  limitGb: number;
  fraction: number;
  color: string;
  periodEnd: string | null;
  lastSyncAt: string | null;
  isFresh: boolean;
  refreshing: boolean;
}) {
  const ago = relativeAgo(lastSyncAt);
  const freshness = !lastSyncAt
    ? 'Awaiting first sync — connect to start counting'
    : isFresh
      ? ago ? `Updated ${ago}` : 'Up to date'
      : ago ? `Last update ${ago}` : 'May be delayed';
  const pct = Math.round(fraction * 100);

  return (
    <div className="flex flex-col">
      <div className="flex items-baseline justify-between">
        <span className="text-[26px] font-bold text-white tabular-nums">{formatGb(usedGb)}</span>
        <span className="text-[12px]" style={{ color: white.w60 }}>
          of {wholeGb(limitGb)} GB used · {pct}%
        </span>
      </div>
      <div
        role="meter"
        aria-label="Data used this month"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={pct}
        aria-valuetext={`${formatGb(usedGb)} of ${wholeGb(limitGb)} GB`}
        className="birdo-meter mt-3 h-2.5 w-full overflow-hidden rounded-full"
        style={{ backgroundColor: surface.s2 }}
      >
        <div className="h-full rounded-full transition-all" style={{ width: `${pct}%`, backgroundColor: color }} />
      </div>

      <div className="mt-3 flex items-center gap-1.5">
        <span
          className="h-[7px] w-[7px] rounded-full"
          style={{ backgroundColor: isFresh ? brand.accent : white.w40 }}
          aria-hidden
        />
        <span className="text-[12px]" style={{ color: white.w60 }}>
          {freshness}
        </span>
      </div>

      <button
        type="button"
        onClick={() => void loadUsage()}
        disabled={refreshing}
        className="mt-3 flex items-center gap-2 self-center rounded-full px-4 py-2 text-[13px] font-semibold disabled:opacity-60"
        style={{ backgroundColor: accentA(0.14), color: brand.accentSoft }}
      >
        <RefreshCw size={15} aria-hidden className={refreshing ? 'animate-spin motion-reduce:animate-none' : ''} />
        Refresh usage
      </button>

      <div className="my-3.5 h-px" style={{ backgroundColor: hairline.soft }} />

      <div className="grid grid-cols-3 text-center">
        <Stat label="Used" value={formatGb(usedGb)} color={color} />
        <Stat label="Left" value={formatGb(Math.max(0, limitGb - usedGb))} />
        <Stat label="Resets" value={formatResetDate(periodEnd) ?? 'Monthly'} />
      </div>

      <p className="mt-3.5 text-center text-[11px]" style={{ color: white.w55 }}>
        Counts uploads and downloads · Updates about every minute
      </p>
    </div>
  );
}

function Stat({ label, value, color = '#FFFFFF' }: { label: string; value: string; color?: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] font-semibold uppercase tracking-[1.2px]" style={{ color: white.w60 }}>
        {label}
      </span>
      <span className="text-[15px] font-semibold tabular-nums" style={{ color }}>
        {value}
      </span>
    </div>
  );
}
