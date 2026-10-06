/**
 * NoticeHost — renders the store's single transient notice (W2-013): failed
 * settings saves, a live reapply that failed, upsells with a "View plans"
 * action, deep-link refusals. A polite live region, so a screen reader hears
 * it without losing its place (W2-016), and `data-modal-exempt` so it stays
 * readable and clickable while a dialog makes the rest of the app inert.
 */
import { useEffect } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { X } from 'lucide-react';
import { useAppStore } from '@/store/app-store';
import { brand, hairline, motion as motionTokens, status, surface, white } from '@/lib/birdo-theme';
import { ResetSettingsDialog } from '@/components/ResetSettingsDialog';

export const NOTICE_MS = 4_500;
/** Long enough to reach the button without hurrying. */
export const NOTICE_WITH_ACTION_MS = 8_000;

export function NoticeHost() {
  const notice = useAppStore((s) => s.notice);
  const dismissNotice = useAppStore((s) => s.dismissNotice);

  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(
      () => dismissNotice(notice.id),
      notice.onAction ? NOTICE_WITH_ACTION_MS : NOTICE_MS,
    );
    return () => clearTimeout(t);
  }, [notice, dismissNotice]);

  return (
    <>
      {/* The confirmation a notice's "Reset settings" opens. */}
      <ResetSettingsDialog />
      <div
        role="status"
        aria-live="polite"
        data-modal-exempt
        className="pointer-events-none absolute inset-x-0 bottom-20 z-[60] flex justify-center px-5"
      >
        <AnimatePresence>
          {notice && (
            <motion.div
              key={notice.id}
              className="birdo-notice pointer-events-auto flex max-w-sm items-center gap-3 rounded-birdo-md px-4 py-3 text-xs font-medium shadow-lg"
              style={{
                backgroundColor: surface.s3,
                border: `1px solid ${notice.tone === 'danger' ? status.redBorder : hairline.strong}`,
                color: white.w100,
              }}
              initial={{ opacity: 0, y: 12 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 12 }}
              transition={{ duration: motionTokens.fast, ease: motionTokens.ease }}
            >
              <span className="flex-1 leading-snug">{notice.text}</span>
              {notice.actionLabel && notice.onAction && (
                <button
                  type="button"
                  onClick={() => {
                    notice.onAction?.();
                    dismissNotice(notice.id);
                  }}
                  className="shrink-0 rounded-birdo-xs px-2 py-1 text-xs font-semibold hover:bg-white/10"
                  style={{ color: brand.accentSoft }}
                >
                  {notice.actionLabel}
                </button>
              )}
              <button
                type="button"
                aria-label="Dismiss"
                onClick={() => dismissNotice(notice.id)}
                className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full hover:bg-white/10"
              >
                <X size={14} color={white.w60} aria-hidden />
              </button>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </>
  );
}
