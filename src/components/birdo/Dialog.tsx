/**
 * BirdoDialog — the one confirm/dialog shell (W2-017, W2-038). Replaces six
 * hand-rolled copies that each got a different subset of modal behaviour
 * right. Mirrors iOS `BirdoConfirmDialog`: title with an icon, body, actions.
 *
 * Behaviour comes from `useModal`: focus moves in, Tab is trapped, Escape and a
 * click on the scrim close it (unless `busy`), the background is inert, and
 * focus returns to the trigger.
 *
 * Rendered through a portal into App's `#birdo-modal-root` (the content area
 * under the title bar), so a dialog declared inside a card or a scroller is
 * never clipped by it and always covers the whole screen.
 */
import { useId, type ReactNode, type RefObject } from 'react';
import { createPortal } from 'react-dom';
import { AnimatePresence, motion } from 'framer-motion';
import type { LucideIcon } from 'lucide-react';
import { useModalRoot } from '@/lib/modal';
import { gradient, motion as motionTokens, surface } from '@/lib/birdo-theme';

export interface BirdoDialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  icon?: LucideIcon;
  iconColor?: string;
  titleColor?: string;
  /** While true, Escape and the scrim do nothing (a request is in flight). */
  busy?: boolean;
  initialFocusRef?: RefObject<HTMLElement | null>;
  children: ReactNode;
}

export const MODAL_ROOT_ID = 'birdo-modal-root';

export function BirdoDialog(props: BirdoDialogProps) {
  const target = document.getElementById(MODAL_ROOT_ID) ?? document.body;
  return createPortal(
    <AnimatePresence>{props.open && <DialogPanel {...props} />}</AnimatePresence>,
    target,
  );
}

function DialogPanel({
  onClose,
  title,
  icon: Icon,
  iconColor,
  titleColor = '#FFFFFF',
  busy = false,
  initialFocusRef,
  children,
}: BirdoDialogProps) {
  const titleId = useId();
  const rootRef = useModalRoot({ onEscape: busy ? undefined : onClose, initialFocusRef });

  return (
    <motion.div
      ref={rootRef}
      className="pointer-events-auto absolute inset-0 z-50 flex items-center justify-center p-5"
      style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: motionTokens.fast, ease: motionTokens.ease }}
      onClick={() => {
        if (!busy) onClose();
      }}
    >
      <motion.div
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        className="birdo-dialog w-full max-w-[360px] overflow-hidden rounded-birdo-lg"
        style={{
          background: `linear-gradient(${surface.s3}, ${surface.s3}) padding-box, ${gradient.glassStroke} border-box`,
          border: '1px solid transparent',
        }}
        initial={{ scale: 0.94, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.94, opacity: 0 }}
        transition={{ duration: motionTokens.standard, ease: motionTokens.ease }}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex flex-col gap-4 p-5">
          <div className="flex items-center gap-2">
            {Icon && <Icon size={20} color={iconColor} aria-hidden />}
            <h2 id={titleId} className="text-[16px] font-bold" style={{ color: titleColor }}>
              {title}
            </h2>
          </div>
          {children}
        </div>
      </motion.div>
    </motion.div>
  );
}
