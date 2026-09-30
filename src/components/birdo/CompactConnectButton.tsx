/**
 * CompactConnectButton — the full-width 60px Connect / Disconnect pill under
 * the server selector. Presentational: what it says and does per connection
 * state is decided by `connectCta` (lib/vpn-display.ts).
 *
 * BUSY IS NOT DISABLED. It used to be: a spinner meant a dead button, so the
 * way out of a connect or a reconnect loop was the tray (which ignored it) or
 * quitting. Now a busy button shows the spinner and stays pressable whenever
 * `connectCta` says it has an action (Cancel / Disconnect).
 *
 * LOOKS (the iOS green budget — luminance, not hue, separates the states):
 *   idle            deep emerald fill                 (iOS connectIdle)
 *   busy            mint→emerald wash + spinner        (connectBusy)
 *   connected       luminous mint + glow, shield icon  (connectConnected)
 *   multiHopReady   emerald                            (connectMultiHop)
 *   multiHopBlocked flat white-10, dimmed, disabled
 *   stop            dark fill, red outline — Disconnect while the kill switch
 *                   holds the block with no tunnel; never green, because
 *                   nothing is protected
 */
import { motion } from 'framer-motion';
import { Power, ShieldCheck, ShieldOff } from 'lucide-react';
import { white, status, gradient, motion as motionTokens } from '@/lib/birdo-theme';
import type { ConnectLook } from '@/lib/vpn-display';

export type ConnectButtonState = ConnectLook;

export interface CompactConnectButtonProps {
  state: ConnectButtonState;
  label: string;
  onClick: () => void;
  busy: boolean;
  disabled?: boolean;
}

/** Neutral drop shadow — every non-connected state. Only connected glows green. */
const NEUTRAL_SHADOW = 'rgba(0,0,0,0.45)';

export function CompactConnectButton({
  state,
  label,
  onClick,
  busy,
  disabled = false,
}: CompactConnectButtonProps) {
  const backgroundImage =
    state === 'connected' ? gradient.connectGreen
    : state === 'busy' ? gradient.connectBusy
    : state === 'multiHopReady' ? gradient.connectMultiHop
    : state === 'multiHopBlocked' ? `linear-gradient(${white.w10}, ${white.w10})`
    : state === 'stop' ? `linear-gradient(${status.redBg}, ${status.redBg})`
    : gradient.connectIdle;

  const borderColor = state === 'stop' ? status.redBorder : 'rgba(255,255,255,0.16)';
  const shadowColor = state === 'connected' ? status.greenShadow : NEUTRAL_SHADOW;
  const Icon = state === 'connected' ? ShieldCheck : state === 'stop' ? ShieldOff : Power;
  const interactive = !disabled;

  return (
    <motion.button
      type="button"
      data-testid="connect-button"
      data-look={state}
      onClick={onClick}
      disabled={disabled}
      aria-busy={busy || undefined}
      whileHover={interactive ? { y: -1, boxShadow: `0 18px 44px -10px ${shadowColor}` } : undefined}
      whileTap={interactive ? { scale: 0.98, y: 0 } : undefined}
      transition={{ duration: motionTokens.fast, ease: motionTokens.ease }}
      className="birdo-cta relative flex h-[60px] w-full items-center justify-center gap-2.5 rounded-2xl transition-opacity disabled:cursor-not-allowed"
      style={{
        backgroundImage,
        border: `1px solid ${borderColor}`,
        boxShadow: `0 14px 32px -10px ${shadowColor}`,
        // A disabled button (multi-hop incomplete, disconnect already running)
        // is dimmed so it reads as clearly non-interactive.
        opacity: disabled ? 0.55 : 1,
      }}
    >
      {busy ? (
        <span
          className="h-[20px] w-[20px] animate-spin rounded-full border-[2.4px] border-white/25 border-t-white"
          aria-hidden
        />
      ) : (
        <Icon size={22} color={state === 'stop' ? status.red : '#FFFFFF'} aria-hidden />
      )}
      <span
        className="text-base font-semibold"
        style={{ color: state === 'stop' ? status.red : '#FFFFFF' }}
      >
        {label}
      </span>
    </motion.button>
  );
}
