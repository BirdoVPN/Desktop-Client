/**
 * The Connect screen's top bar: the Multi-Hop toggle (left), the signed-in
 * identity and Sign out (right).
 */
import { Lock, LogOut, Route as AltRoute } from 'lucide-react';
import { BirdoIconAction } from '@/components/birdo';
import { brand, hairline, white } from '@/lib/birdo-theme';
import { displayableEmail } from '@/utils/helpers';

interface HomeTopBarProps {
  userEmail: string | null;
  /** `resolveAnonymousAccount`: `/auth/me`'s `isAnonymous` (item 86, MR-918). */
  anonymous: boolean;
  multiHopArmed: boolean;
  /** `null` = plan not known yet: no lock badge, no upsell (W2-011). */
  multiHopUnlocked: boolean | null;
  /** The plan Multi-Hop comes with, for the locked label (MR-1517). */
  multiHopPlan?: string;
  /** On a live session the route cannot change (W2-010). */
  multiHopLocked: boolean;
  onToggleMultiHop: () => void;
  onSignOut: () => void;
}

export function HomeTopBar({
  userEmail,
  anonymous,
  multiHopArmed,
  multiHopUnlocked,
  multiHopPlan = 'Sovereign',
  multiHopLocked,
  onToggleMultiHop,
  onSignOut,
}: HomeTopBarProps) {
  // Never an anonymous account's email: its synthetic address carries the
  // account's only credential, on the screen people screenshot most
  // (P1-parity-007). iOS shows the same words. MR-2014: nor the synthetic
  // address before `/auth/me` has said the account is anonymous (an
  // email-form sign-in with it): nothing is shown until then.
  const identity = anonymous ? 'Anonymous account' : displayableEmail(userEmail);
  return (
    <div
      className="relative z-20 flex items-center gap-2 px-4 pt-3 pb-2"
      // No backdrop-filter blur (smears the animating globe into vertical
      // streaks on WebView2 GPUs); a near-opaque fill reads the same.
      style={{ backgroundColor: 'rgba(11,11,16,0.92)' }}
    >
      <MultiHopTopAction
        armed={multiHopArmed}
        unlocked={multiHopUnlocked}
        plan={multiHopPlan}
        routeLocked={multiHopLocked}
        onClick={onToggleMultiHop}
      />
      <div className="flex-1" />
      {identity && (
        <span className="max-w-[160px] truncate text-xs" style={{ color: white.w60 }}>
          {identity}
        </span>
      )}
      <BirdoIconAction icon={LogOut} contentDescription="Sign out" onClick={onSignOut} tint={white.w60} />
    </div>
  );
}

function MultiHopTopAction({
  armed,
  unlocked,
  plan,
  routeLocked,
  onClick,
}: {
  armed: boolean;
  unlocked: boolean | null;
  plan: string;
  routeLocked: boolean;
  onClick: () => void;
}) {
  const active = armed && unlocked === true;
  const tint = unlocked === false ? white.w40 : active ? brand.accent : white.w80;
  const label =
    unlocked === false
      ? `Multi-Hop (${plan} plan)`
      : routeLocked
        ? 'Multi-Hop (disconnect to change your route)'
        : 'Multi-Hop';
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      aria-pressed={active}
      className="birdo-toggle relative flex h-10 w-10 shrink-0 items-center justify-center rounded-xl transition-colors"
      style={{
        backgroundColor: active ? brand.accentBg : white.w05,
        border: `1px solid ${active ? 'rgba(16,185,129,0.55)' : hairline.soft}`,
      }}
    >
      <AltRoute size={20} color={tint} aria-hidden />
      {unlocked === false && (
        <span
          className="absolute bottom-0.5 right-0.5 flex h-3.5 w-3.5 items-center justify-center rounded-full"
          style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}
        >
          <Lock size={9} color="#FFFFFF" aria-hidden />
        </span>
      )}
    </button>
  );
}
