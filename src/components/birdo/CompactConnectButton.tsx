/**
 * CompactConnectButton — pill-style connect/disconnect action, mirroring
 * mobile's `CompactConnectButton` in `HomeScreen.kt`. Full-width 60px pill that
 * stacks under the globe alongside the server selector.
 *
 * Connection state is owned by the caller (derived from polling get_vpn_status);
 * this primitive is presentational and only reflects the `state`/`busy` props.
 */
import { motion } from 'framer-motion';
import { Power } from 'lucide-react';
import { white, status, gradient, motion as motionTokens } from '@/lib/birdo-theme';

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

  const shadowColor =
    state === 'connected' ? status.greenShadow : 'rgba(168,85,247,0.45)';

  return (
    <motion.button
      type="button"
      data-testid="connect-button"
      onClick={onClick}
      disabled={busy || state === 'multiHopBlocked'}
      whileTap={!busy ? { scale: 0.98 } : undefined}
      transition={{ duration: motionTokens.fast, ease: motionTokens.ease }}
      className="relative flex h-[60px] w-full items-center justify-center gap-2.5 rounded-2xl transition-opacity disabled:cursor-not-allowed"
      style={{
        backgroundImage,
        border: '1px solid rgba(255,255,255,0.16)',
        boxShadow: `0 14px 32px -10px ${shadowColor}`,
        opacity: busy ? 0.85 : 1,
      }}
    >
      {busy ? (
        <span
          className="h-[20px] w-[20px] animate-spin rounded-full border-[2.4px] border-white/25 border-t-white"
          aria-hidden
        />
      ) : (
        <Power size={22} color="#FFFFFF" aria-hidden />
      )}
      <span className="text-base font-semibold text-white">{label}</span>
    </motion.button>
  );
}
