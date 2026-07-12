/**
 * CompactConnectButton — pill-style connect/disconnect action. Full-width 60px
 * pill that stacks under the globe alongside the server selector.
 *
 * Connection state is owned by the caller (derived from get_vpn_status); this
 * primitive is presentational and only reflects the `state`/`busy` props.
 *
 * STATE LEGIBILITY. Since the 2026-07 emerald rebrand the brand accent is green,
 * so fill colour alone can no longer carry the connected signal. Each state gets
 * a distinct fill + border + shadow triple, and connected additionally swaps the
 * icon (Power → ShieldCheck):
 *   idle          neutral glass fill, EMERALD outline,  neutral shadow
 *   busy          translucent emerald wash,             spinner, neutral shadow
 *   connected     opaque green fill (the only one),     green glow, shield icon
 *   multiHopReady teal fill,                            teal glow
 *   multiHopBlocked flat white-10, no glow, disabled
 */
import { motion } from 'framer-motion';
import { Power, ShieldCheck } from 'lucide-react';
import {
  white,
  status,
  gradient,
  accentA,
  motion as motionTokens,
} from '@/lib/birdo-theme';

export type ConnectButtonState =
  | 'idle'
  | 'connected'
  | 'busy'
  | 'multiHopReady'
  | 'multiHopBlocked';

export interface CompactConnectButtonProps {
  state: ConnectButtonState;
  label: string;
  onClick: () => void;
  busy: boolean;
}

/** Neutral drop shadow — every non-connected state. Only connected glows green. */
const NEUTRAL_SHADOW = 'rgba(0,0,0,0.45)';

export function CompactConnectButton({
  state,
  label,
  onClick,
  busy,
}: CompactConnectButtonProps) {
  const backgroundImage =
    state === 'connected'     ? gradient.connectGreen
    : busy                    ? gradient.connectBusy
    : state === 'multiHopReady' ? gradient.connectMultiHop
    : state === 'multiHopBlocked' ? `linear-gradient(${white.w10}, ${white.w10})`
    : gradient.connectIdle;

  // Idle is the only state whose emerald shows in the border rather than the fill.
  const borderColor =
    state === 'idle' ? accentA(0.55) : 'rgba(255,255,255,0.16)';

  const shadowColor =
    state === 'connected' ? status.greenShadow
    : state === 'multiHopReady' ? 'rgba(13,148,136,0.40)'
    : NEUTRAL_SHADOW;

  const Icon = state === 'connected' ? ShieldCheck : Power;

  return (
    <motion.button
      type="button"
      data-testid="connect-button"
      onClick={onClick}
      disabled={busy || state === 'multiHopBlocked'}
      whileHover={
        !busy && state !== 'multiHopBlocked'
          ? { y: -1, boxShadow: `0 18px 44px -10px ${shadowColor}` }
          : undefined
      }
      whileTap={!busy && state !== 'multiHopBlocked' ? { scale: 0.98, y: 0 } : undefined}
      transition={{ duration: motionTokens.fast, ease: motionTokens.ease }}
      className="relative flex h-[60px] w-full items-center justify-center gap-2.5 rounded-2xl transition-opacity disabled:cursor-not-allowed"
      style={{
        backgroundImage,
        border: `1px solid ${borderColor}`,
        boxShadow: `0 14px 32px -10px ${shadowColor}`,
        // multiHopBlocked is dimmed so it reads as clearly non-interactive next
        // to the idle state (both are pale fills; without the dim they look alike).
        opacity: state === 'multiHopBlocked' ? 0.5 : busy ? 0.85 : 1,
      }}
    >
      {busy ? (
        <span
          className="h-[20px] w-[20px] animate-spin rounded-full border-[2.4px] border-white/25 border-t-white"
          aria-hidden
        />
      ) : (
        <Icon size={22} color="#FFFFFF" aria-hidden />
      )}
      <span className="text-base font-semibold text-white">{label}</span>
    </motion.button>
  );
}
