/**
 * The terms-change notices `GET /auth/me` names for this account (MR-2199,
 * birdo-web #808). An anonymous account has no address to be e-mailed at, so
 * the app is where it hears of a change.
 *
 * On the Connect tab only, in the bottom panel with the other Home banners
 * (`HomeBanners`). Above every tab, at 380x640, two notices took a third of
 * every screen and the scroll cap cut the second off mid-sentence (owner,
 * smoke test of 1.4.51, 7 November 2026).
 *
 * One compact row: the text clamped to two lines (all of it is the row's
 * tooltip and what a screen reader reads), Details for the website's list of
 * every change, and Dismiss. With more than one in force the first shows with
 * "+N more": two stacked rows need about 115 px, and at 380x520 while
 * connected the Connect panel has about 65 to grow into before the status pill.
 *
 * The rules are otherwise the web banner's: in the server's order, `text`
 * exactly as sent, gone once the time reaches `effectiveAt` with the app left
 * open and no new fetch, a link only to a plain same-site path, neutral tone.
 * Dismissing one keeps its `version` on this device (`dismissedTermsNotices`,
 * persisted with the local preferences), so it stays gone after a restart and
 * a new version shows again. Nothing is sent: no acknowledgement, no analytics.
 */
import { useEffect, useId, useState } from 'react';
import { Info, X } from 'lucide-react';
import { useShallow } from 'zustand/react/shallow';
import { hairline, surface, white } from '@/lib/birdo-theme';
import { openWebsite, websiteUrl } from '@/lib/links';
import { useAppStore, type TermsNotice } from '@/store/app-store';

/**
 * The longest this waits before reading the clock again. One timer set for the
 * date would not do: `setTimeout` fires AT ONCE past 2^31 ms, under 25 days,
 * and does not count while the machine sleeps, so a laptop woken after the date
 * would keep showing a notice that has ended.
 */
export const TERMS_NOTICE_TICK_MS = 60_000;

/** `Date.parse` alone also takes "2099" and "5 Dec 2099", and would show a broken date for years. */
const ISO_INSTANT = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/** When a notice ends. `NaN` for a date it cannot read, which is never after now, so it is not shown. */
function noticeEnd(notice: TermsNotice): number {
  return ISO_INSTANT.test(notice.effectiveAt) ? Date.parse(notice.effectiveAt) : NaN;
}

export function TermsNoticeBanners() {
  const { notices, dismissed, dismiss } = useAppStore(
    useShallow((s) => ({
      notices: s.account.termsNotices,
      dismissed: s.dismissedTermsNotices,
      dismiss: s.dismissTermsNotice,
    })),
  );
  const [now, setNow] = useState(Date.now);
  const textId = useId();
  const live = notices.filter(
    (notice) => notice.text.trim() && noticeEnd(notice) > now && !dismissed.includes(notice.version),
  );
  const nextEnd = live.length > 0 ? Math.min(...live.map(noticeEnd)) : null;

  useEffect(() => {
    if (nextEnd === null) return;
    const timer = setTimeout(() => setNow(Date.now()), Math.min(nextEnd - now, TERMS_NOTICE_TICK_MS));
    return () => clearTimeout(timer);
  }, [nextEnd, now]);

  if (live.length === 0) return null;

  const [notice, ...more] = live;
  const url = websiteUrl(notice.path);
  // The list of changes covers every notice; the server names the same page for each.
  const moreUrl = more.map((n) => websiteUrl(n.path)).find((u) => u !== null) ?? url;
  const moreLabel = `+${more.length} more`;
  const buttonClass = 'shrink-0 rounded-birdo-xs text-[11px] font-semibold hover:bg-white/10';

  return (
    <div
      className="birdo-banner mb-2.5 flex items-start gap-2 rounded-2xl px-3 py-2"
      style={{ backgroundColor: surface.s3, border: `1px solid ${hairline.strong}` }}
    >
      <Info size={14} color={white.w80} className="mt-0.5 shrink-0" aria-hidden />
      {/* Two lines at most, cut with an ellipsis: never a scroll box that ends mid-sentence. */}
      <p
        id={textId}
        title={notice.text}
        className="line-clamp-2 min-w-0 flex-1 text-[11px] leading-snug"
        style={{ color: white.w80 }}
      >
        {notice.text}
      </p>
      <div className="flex shrink-0 flex-col items-end gap-0.5">
        <div className="flex items-center gap-1">
          {url && (
            <button
              type="button"
              onClick={() => openWebsite(url)}
              aria-describedby={textId}
              className={`${buttonClass} px-2 py-0.5`}
              style={{ color: white.w80, border: `1px solid ${hairline.strong}` }}
            >
              Details
            </button>
          )}
          <button
            type="button"
            aria-label="Dismiss"
            aria-describedby={textId}
            onClick={() => dismiss(notice.version)}
            className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full hover:bg-white/10"
          >
            <X size={14} color={white.w60} aria-hidden />
          </button>
        </div>
        {more.length > 0 &&
          (moreUrl ? (
            <button
              type="button"
              onClick={() => openWebsite(moreUrl)}
              className={`${buttonClass} px-1`}
              style={{ color: white.w60 }}
            >
              {moreLabel}
            </button>
          ) : (
            <span className="px-1 text-[11px] font-semibold" style={{ color: white.w60 }}>
              {moreLabel}
            </span>
          ))}
      </div>
    </div>
  );
}
