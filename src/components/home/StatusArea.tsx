/**
 * The pill and the chips under it: kill switch (blocking / arms once
 * connected) and Stealth. Chips are information, not errors — Stealth is never
 * red (P1-parity: "brand/info, never red").
 */
import { AnimatePresence, motion } from 'framer-motion';
import { EyeOff, Shield, ShieldOff, type LucideIcon } from 'lucide-react';
import { useShallow } from 'zustand/react/shallow';
import { StatusPill } from '@/components/birdo';
import { brand, hairline, motion as motionTokens, status, white } from '@/lib/birdo-theme';
import {
  KILL_SWITCH_BLOCKING_TEXT,
  KILL_SWITCH_PENDING_TEXT,
  killSwitchChip,
} from '@/lib/vpn-display';
import { useAppStore } from '@/store/app-store';
import { selectDisplayState } from '@/store/selectors';

export function StatusArea() {
  const { state, multiHop, blocking, killSwitchEnabled, stealth } = useAppStore(
    useShallow((s) => ({
      state: selectDisplayState(s),
      multiHop: s.liveMultiHop !== null,
      blocking: s.killSwitchBlocking,
      killSwitchEnabled: s.settings.killSwitchEnabled,
      stealth: s.stealthActive,
    })),
  );
  const chip = killSwitchChip(state, blocking, killSwitchEnabled);
  const showStealth = state === 'connected' && stealth;

  return (
    <>
      <div className="relative z-10 mt-3 flex justify-center">
        <StatusPill state={state} multiHop={multiHop && state === 'connected'} />
      </div>
      <AnimatePresence>
        {(chip || showStealth) && (
          <motion.div
            className="relative z-10 mt-2 flex flex-wrap justify-center gap-2 px-4"
            initial={{ opacity: 0, y: -4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: motionTokens.fast }}
          >
            {chip === 'blocking' && (
              <Chip icon={ShieldOff} label={KILL_SWITCH_BLOCKING_TEXT} tone="danger" />
            )}
            {chip === 'pending' && <Chip icon={Shield} label={KILL_SWITCH_PENDING_TEXT} tone="neutral" />}
            {showStealth && <Chip icon={EyeOff} label="Stealth" tone="brand" />}
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

const CHIP_TONE = {
  danger: { bg: status.redBg, fg: status.red, border: status.redBorder },
  neutral: { bg: white.w05, fg: white.w80, border: hairline.soft },
  brand: { bg: brand.accentBg, fg: brand.accentLight, border: hairline.soft },
} as const;

function Chip({ icon: Icon, label, tone }: { icon: LucideIcon; label: string; tone: keyof typeof CHIP_TONE }) {
  const t = CHIP_TONE[tone];
  return (
    <div
      className="birdo-badge flex items-center gap-1.5 rounded-full px-2.5 py-1"
      style={{ backgroundColor: t.bg, border: `1px solid ${t.border}` }}
    >
      <Icon size={12} color={t.fg} className="shrink-0" aria-hidden />
      <span className="text-[11px] font-medium" style={{ color: t.fg }}>
        {label}
      </span>
    </div>
  );
}
