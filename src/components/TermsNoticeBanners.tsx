/**
 * The terms-change notices `GET /auth/me` names for this account (MR-2199,
 * birdo-web #808). An anonymous account has no address to be e-mailed at, so
 * the app is where it hears of a change.
 *
 * One row per entry, in the server's order, `text` exactly as sent. The web
 * banner's rule: not dismissible, and gone once the time reaches `effectiveAt`,
 * with the app left open and no new fetch. Nothing is recorded: no
 * acknowledgement, no analytics, nothing kept beyond the in-memory profile.
 */
import { useEffect, useState } from 'react';
import { Info } from 'lucide-react';
import { BannerRow } from '@/components/home/HomeBanners';
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
  const notices = useAppStore((s) => s.account.termsNotices);
  const [now, setNow] = useState(Date.now);
  const live = notices.filter((notice) => notice.text.trim() && noticeEnd(notice) > now);
  const nextEnd = live.length > 0 ? Math.min(...live.map(noticeEnd)) : null;

  useEffect(() => {
    if (nextEnd === null) return;
    const timer = setTimeout(() => setNow(Date.now()), Math.min(nextEnd - now, TERMS_NOTICE_TICK_MS));
    return () => clearTimeout(timer);
  }, [nextEnd, now]);

  if (live.length === 0) return null;

  return (
    // Capped: at the window's smallest size two long sentences would otherwise
    // take the screen from the tab under them. Past this they scroll.
    <div className="max-h-[35%] shrink-0 overflow-y-auto px-5 pt-3">
      {live.map((notice) => {
        const url = websiteUrl(notice.path);
        return (
          <BannerRow
            key={notice.version}
            icon={Info}
            tone="neutral"
            text={notice.text}
            actionLabel={url ? 'See every change' : undefined}
            onAction={url ? () => openWebsite(url) : undefined}
            actionBelow
          />
        );
      })}
    </div>
  );
}
