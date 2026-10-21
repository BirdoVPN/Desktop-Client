/**
 * Limit — the usage tab, laid out as Android `LimitScreen.kt` / iOS
 * `LimitView.swift` (owner, 2026-10-21: the whole Limit tab as on mobile, with
 * the speedometer gauge). Shown to every plan: capped (Free) plans get the
 * speed-dial gauge of their monthly allowance, uncapped plans the "Unlimited
 * data" state. The dial's geometry and figures live in `lib/usage-gauge.ts`.
 *
 * It replaces Profile's "Data this month" card, which rendered NOTHING while
 * loading or after an error, had no refresh and no warning before the cap.
 *
 * Data honesty (iOS rule): never present a frozen number as live — the
 * freshness line under the gauge is mandatory, and a node that has never
 * synced says "awaiting first sync" rather than showing 0.
 *
 * Units: `/vpn/stats` reports gigabytes (`bandwidthUsedGb`,
 * `bandwidthLimitGb`), not the bytes `/auth/me` carries, so nothing here
 * converts.
 */
import { useEffect } from 'react';
import { useShallow } from 'zustand/react/shallow';
import { Gauge, RefreshCw, Zap } from 'lucide-react';
import { BirdoButton, BirdoCard } from '@/components/birdo';
import { accentA, brand, hairline, status, surface, white } from '@/lib/birdo-theme';
import { planName, resolvePlanPrices, type PlanId, type PlanPrice } from '@/lib/plan';
import {
  GAUGE_KNOB_INNER,
  GAUGE_KNOB_OUTER,
  GAUGE_SIZE,
  GAUGE_STROKE,
  dialArcPath,
  formatGbFigure,
  gaugeFillDashOffset,
  gaugeKnobDashOffset,
  gaugePercent,
  gaugeTone,
  gaugeValue,
  hasDataCap,
  usageFraction,
  wholeGb,
  type GaugeTone,
} from '@/lib/usage-gauge';
import { loadUsage } from '@/session/session-data';
import { useAppStore } from '@/store/app-store';

const TONE_COLOR: Record<GaugeTone, string> = {
  accent: brand.accent,
  yellow: status.yellow,
  red: status.red,
};

/** Android draws the track in onSurface at 14 % on dark. */
const TRACK_COLOR = 'rgba(255,255,255,0.14)';
const DIAL_PATH = dialArcPath();

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

/**
 * The cheapest paid plan whose data is unlimited, read from the server's plan
 * table rather than assumed (MR-2030): mobile's "Upgrade to Operative for
 * unlimited data" is only said while Operative really is uncapped.
 */
function unlimitedPlan(prices: Record<PlanId, PlanPrice>): PlanId | null {
  if (prices.OPERATIVE.bandwidthLimitGb === null) return 'OPERATIVE';
  if (prices.SOVEREIGN.bandwidthLimitGb === null) return 'SOVEREIGN';
  return null;
}

export function Limit() {
  const { usage, usageStatus, plan, planPrices, pushRoute } = useAppStore(
    useShallow((s) => ({
      usage: s.usage,
      usageStatus: s.usageStatus,
      plan: s.account.plan,
      planPrices: s.planPrices,
      pushRoute: s.pushRoute,
    })),
  );

  // The user opened their usage on purpose: always ask for a fresh number.
  useEffect(() => {
    void loadUsage();
  }, []);
  const refresh = () => void loadUsage();

  const limitGb = usage?.bandwidthLimitGb ?? null;
  const hasCap = hasDataCap(limitGb);
  const usedGb = Math.max(0, usage?.bandwidthUsedGb ?? 0);
  const fraction = usageFraction(usedGb, limitGb);
  const meterColor = TONE_COLOR[gaugeTone(fraction)];
  const planLabel = plan ?? usage?.plan ?? null;

  return (
    <div className="h-full overflow-y-auto">
      <div className="flex flex-col gap-3 px-5 py-6">
        {/* Mobile's tab has no title bar; the heading stays for screen readers. */}
        <h1 className="sr-only">Limit</h1>

        {/* Plan header: name on the left, allowance pill on the right */}
        <div>
          <h2
            className="pb-1.5 pl-1 text-[11px] font-semibold uppercase tracking-[1.5px]"
            style={{ color: white.w60 }}
          >
            Your plan
          </h2>
          <div className="flex items-center">
            <span className="min-w-0 flex-1 text-[22px] font-bold text-white">
              {planLabel ? `${planName(planLabel)} plan` : 'Checking your plan…'}
            </span>
            {usage && (
              <span
                className="ml-2 shrink-0 rounded-full px-2.5 py-[5px] text-[12px] font-semibold"
                style={{ backgroundColor: accentA(0.16), color: brand.accent }}
              >
                {hasCap ? `${wholeGb(limitGb)} GB / month` : 'Unlimited'}
              </span>
            )}
          </div>
        </div>

        {usage && usageStatus === 'error' && (
          // The held reading stays below; the reason sits here.
          <p role="alert" className="text-[12px]" style={{ color: status.red }}>
            Couldn&apos;t refresh your usage. Showing the last reading.
          </p>
        )}

        <BirdoCard>
          {!usage && usageStatus === 'error' ? (
            <LoadFailedState onRetry={refresh} />
          ) : !usage ? (
            <LoadingState />
          ) : !hasCap ? (
            <UnlimitedState />
          ) : (
            <CappedUsage
              usedGb={usedGb}
              limitGb={limitGb}
              fraction={fraction}
              color={meterColor}
              periodEnd={usage.bandwidthPeriodEnd}
              lastSyncAt={usage.bandwidthLastSyncAt}
              isFresh={usage.bandwidthIsFresh === true}
              // A fetch in flight: the held reading stays, the pill says so.
              refreshing={usageStatus === 'loading'}
              onRefresh={refresh}
            />
          )}
        </BirdoCard>

        {usage && hasCap && (
          <UpgradeCard
            limitGb={limitGb}
            almostOut={fraction >= 0.9}
            unlimitedOn={unlimitedPlan(resolvePlanPrices(planPrices))}
            onUpgrade={() => pushRoute('pricing')}
          />
        )}
      </div>
    </div>
  );
}

function LoadingState() {
  return (
    <div className="flex flex-col items-center gap-3 py-12" aria-busy>
      <span
        className="h-8 w-8 animate-spin rounded-full border-[3px] motion-reduce:animate-none"
        style={{ borderColor: brand.accent, borderTopColor: 'transparent' }}
        aria-hidden
      />
      <p className="text-[13px]" style={{ color: white.w60 }}>
        Loading your usage…
      </p>
    </div>
  );
}

/** No figure to show and the fetch failed: say so and offer the way out. */
function LoadFailedState({ onRetry }: { onRetry: () => void }) {
  return (
    <div className="flex flex-col items-center gap-3 py-8">
      <p role="alert" className="text-center text-[13px]" style={{ color: white.w60 }}>
        Couldn&apos;t load your usage.
      </p>
      <BirdoButton text="Retry" variant="secondary" icon={RefreshCw} onClick={onRetry} />
    </div>
  );
}

function UnlimitedState() {
  return (
    <div className="flex flex-col items-center gap-2 py-5 text-center">
      <span
        className="flex h-14 w-14 items-center justify-center rounded-full"
        style={{ backgroundColor: accentA(0.14) }}
      >
        <Gauge size={30} color={brand.accent} aria-hidden />
      </span>
      <p className="pt-1 text-[18px] font-semibold text-white">Unlimited data</p>
      <p className="text-[13px]" style={{ color: white.w60 }}>
        Your plan has no data cap — use as much as you like.
      </p>
    </div>
  );
}

function CappedUsage({
  usedGb,
  limitGb,
  fraction,
  color,
  periodEnd,
  lastSyncAt,
  isFresh,
  refreshing,
  onRefresh,
}: {
  usedGb: number;
  limitGb: number;
  fraction: number;
  color: string;
  periodEnd: string | null;
  lastSyncAt: string | null;
  isFresh: boolean;
  refreshing: boolean;
  onRefresh: () => void;
}) {
  const ago = relativeAgo(lastSyncAt);
  const freshness = !lastSyncAt
    ? 'Awaiting first sync — connect to start counting'
    : isFresh
      ? ago ? `Updated ${ago}` : 'Up to date'
      : ago ? `Last update ${ago}` : 'May be delayed';

  return (
    <div className="flex flex-col items-center">
      <SpeedDialGauge fraction={fraction} usedGb={usedGb} limitGb={limitGb} color={color} />

      {/* Freshness — the gauge is only as honest as the last sync. */}
      <div className="flex items-center gap-1.5">
        <span
          className="h-[7px] w-[7px] shrink-0 rounded-full"
          style={{ backgroundColor: isFresh ? brand.accent : white.w40 }}
          aria-hidden
        />
        <span className="text-[12px]" style={{ color: white.w60 }}>
          {freshness}
        </span>
      </div>

      {/* Prominent refresh: a tonal accent pill, unmistakably a button. */}
      <button
        type="button"
        onClick={onRefresh}
        disabled={refreshing}
        className="mt-2.5 flex min-h-12 items-center gap-[7px] rounded-full px-4 py-[9px] text-[13px] font-semibold disabled:cursor-default"
        style={{ backgroundColor: accentA(0.14), color: brand.accent }}
      >
        {refreshing ? (
          <span
            className="h-4 w-4 animate-spin rounded-full border-2 motion-reduce:animate-none"
            style={{ borderColor: brand.accent, borderTopColor: 'transparent' }}
            aria-hidden
          />
        ) : (
          <RefreshCw size={16} aria-hidden />
        )}
        {refreshing ? 'Updating…' : 'Refresh usage'}
      </button>

      <div className="my-3.5 h-px w-full" style={{ backgroundColor: hairline.soft }} />

      {/* Used / Left / Resets — equal columns with hairline separators. */}
      <div className="flex w-full items-center">
        <StatCell label="Used" value={formatGbFigure(usedGb)} color={color} />
        <StatDivider />
        <StatCell label="Left" value={formatGbFigure(limitGb - usedGb)} />
        <StatDivider />
        <StatCell label="Resets" value={formatResetDate(periodEnd) ?? 'Monthly'} />
      </div>

      <p className="mt-3.5 w-full text-center text-[11px]" style={{ color: white.w55 }}>
        Counts uploads and downloads · Updates about every minute
      </p>
    </div>
  );
}

/**
 * Speedometer arc: 270° with the gap at the bottom, a clean track, the used
 * share in the gauge colour and a knob at the current position; the
 * percentage sits in the bottom gap so the centre stays uncluttered. The fill
 * sweeps in and glides between readings (`.birdo-gauge__*` in globals.css),
 * instantly under reduced motion.
 */
function SpeedDialGauge({
  fraction,
  usedGb,
  limitGb,
  color,
}: {
  fraction: number;
  usedGb: number;
  limitGb: number;
  color: string;
}) {
  const value = gaugeValue(usedGb);
  const limitLine = `of ${wholeGb(limitGb)} GB used`;
  const percent = gaugePercent(fraction);
  const knobOffset = gaugeKnobDashOffset(fraction);

  return (
    <div
      role="meter"
      aria-label="Data used this month"
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={Math.round(fraction * 100)}
      aria-valuetext={`${value} ${limitLine}, ${percent}`}
      className="birdo-gauge relative mt-1 shrink-0"
      style={{ width: GAUGE_SIZE, height: GAUGE_SIZE }}
    >
      <svg
        width={GAUGE_SIZE}
        height={GAUGE_SIZE}
        viewBox={`0 0 ${GAUGE_SIZE} ${GAUGE_SIZE}`}
        className="absolute inset-0"
        aria-hidden
        focusable="false"
      >
        <path
          className="birdo-gauge__track"
          d={DIAL_PATH}
          fill="none"
          stroke={TRACK_COLOR}
          strokeWidth={GAUGE_STROKE}
          strokeLinecap="round"
        />
        {/* The same arc, dashed to the used share: pathLength 1 makes the
            dash the fraction itself. The gap is 2, not 1: a 1-long gap put
            the next dash's round cap on the arc's end as a dot at 0 %. */}
        <path
          className="birdo-gauge__fill"
          d={DIAL_PATH}
          fill="none"
          stroke={color}
          strokeWidth={GAUGE_STROKE}
          strokeLinecap="round"
          pathLength={1}
          strokeDasharray="1 2"
          style={{ strokeDashoffset: gaugeFillDashOffset(fraction) }}
        />
        {/* Knob: a zero-length dash with round caps is a dot as wide as the
            stroke, so the knob is the same arc again, dashed to a single
            point at the reading. It moves along the arc on the same property
            and timing as the fill, so the two cannot drift apart mid-sweep
            (a CSS rotate of the knob ran on another clock and lagged). */}
        <path
          className="birdo-gauge__knob"
          d={DIAL_PATH}
          fill="none"
          stroke={color}
          strokeWidth={GAUGE_KNOB_OUTER * 2}
          strokeLinecap="round"
          pathLength={1}
          strokeDasharray="0 2"
          style={{ strokeDashoffset: knobOffset }}
        />
        <path
          className="birdo-gauge__knob birdo-gauge__core"
          d={DIAL_PATH}
          fill="none"
          stroke={surface.s1}
          strokeWidth={GAUGE_KNOB_INNER * 2}
          strokeLinecap="round"
          pathLength={1}
          strokeDasharray="0 2"
          style={{ strokeDashoffset: knobOffset }}
        />
      </svg>

      {/* Centre readout: the number is the hero, the unit line supports it. */}
      <div className="absolute inset-0 flex flex-col items-center justify-center px-9" aria-hidden>
        <span className="whitespace-nowrap font-mono text-[40px] font-bold leading-tight text-white">{value}</span>
        <span className="mt-0.5 whitespace-nowrap text-[13px]" style={{ color: white.w60 }}>
          {limitLine}
        </span>
      </div>

      {/* Percentage in the bottom gap of the arc. */}
      <span
        className="absolute inset-x-0 bottom-0.5 text-center font-mono text-[13px] font-semibold"
        style={{ color: white.w60 }}
        aria-hidden
      >
        {percent}
      </span>
    </div>
  );
}

function StatCell({ label, value, color = '#FFFFFF' }: { label: string; value: string; color?: string }) {
  return (
    <div className="flex min-w-0 flex-1 flex-col items-center">
      <span className="text-[10px] font-semibold uppercase tracking-[1.2px]" style={{ color: white.w60 }}>
        {label}
      </span>
      <span className="mt-[3px] text-[15px] font-semibold tabular-nums" style={{ color }}>
        {value}
      </span>
    </div>
  );
}

function StatDivider() {
  return <div className="h-[30px] w-px shrink-0" style={{ backgroundColor: hairline.soft }} aria-hidden />;
}

function UpgradeCard({
  limitGb,
  almostOut,
  unlimitedOn,
  onUpgrade,
}: {
  limitGb: number;
  almostOut: boolean;
  unlimitedOn: PlanId | null;
  onUpgrade: () => void;
}) {
  const offer = unlimitedOn
    ? `Upgrade to ${planName(unlimitedOn)} for unlimited data on every server.`
    : 'Paid plans include more data.';
  return (
    <BirdoCard>
      <div className="flex flex-col gap-2.5">
        <div className="flex items-center gap-2.5">
          <span
            className="flex h-[34px] w-[34px] shrink-0 items-center justify-center rounded-[9px]"
            style={{ backgroundColor: accentA(0.14) }}
          >
            <Zap size={19} color={brand.accent} fill={brand.accent} aria-hidden />
          </span>
          <span className="text-[15px] font-semibold text-white">
            {almostOut ? "You're almost out of data" : 'Need more data?'}
          </span>
        </div>
        <p className="text-[13px] leading-[18px]" style={{ color: white.w60 }}>
          Free accounts include {wholeGb(limitGb)} GB per month. {offer}
        </p>
        <BirdoButton
          text={unlimitedOn ? 'Upgrade for unlimited' : 'View plans'}
          variant="primary"
          fullWidth
          onClick={onUpgrade}
        />
      </div>
    </BirdoCard>
  );
}
