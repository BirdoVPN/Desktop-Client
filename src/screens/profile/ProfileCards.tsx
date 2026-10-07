/**
 * The Profile tab's cards: identity (with the connection status row), the
 * anonymous account number, and the subscription summary.
 */
import { useState } from 'react';
import { CircleAlert, Check, Copy, Eye, EyeOff, KeyRound, Shield, ShieldAlert, Star } from 'lucide-react';
import { useShallow } from 'zustand/react/shallow';
import { BirdoCard } from '@/components/birdo';
import { brand, hairline, status as statusTokens, surface, white } from '@/lib/birdo-theme';
import { planGradient, planName, planRank } from '@/lib/plan';
import { findLiveServer } from '@/session/vpn-actions';
import { useAppStore, type LoadStatus } from '@/store/app-store';
import { selectDisplayState } from '@/store/selectors';
import { formatAccountNumber, formatDate, maskAccountNumber } from '@/utils/helpers';

// ── Identity ────────────────────────────────────────────────────────────────

export function IdentityCard({ email, plan, isAnon }: { email: string | null; plan: string | null; isAnon: boolean }) {
  // Three distinct states — a real email, a genuinely anonymous account, and an
  // identity we could not load yet. Falling back to "Anonymous" for a null
  // email told users with a real, verified address that they had no account.
  let name: string;
  let subtitle: string;
  if (isAnon) {
    name = 'Anonymous account';
    subtitle = 'No email — private account';
  } else if (!email) {
    name = 'Signed in';
    subtitle = 'Loading your account…';
  } else {
    name = (email.split('@')[0] || email).trim();
    subtitle = email;
  }
  const initial = isAnon || !email ? '·' : (name.charAt(0) || '?').toUpperCase();

  return (
    <BirdoCard cornerRadius={22} padding="20px">
      <div className="flex items-center">
        {/* The user's initial on the plan colour (slate while unknown). */}
        <div
          className="flex h-14 w-14 shrink-0 items-center justify-center rounded-birdo-lg text-[22px] font-bold text-white"
          style={{
            backgroundImage: planGradient(plan ?? 'RECON'),
            boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.18)',
          }}
          aria-hidden
        >
          {initial}
        </div>
        <div className="ml-3.5 min-w-0 flex-1">
          <div className="truncate text-[18px] font-semibold" style={{ color: '#FFFFFF' }}>
            {name}
          </div>
          <div className="truncate text-[13px]" style={{ color: white.w60 }}>
            {subtitle}
          </div>
        </div>
        {plan && (
          <span
            className="shrink-0 rounded-full px-2.5 py-1 text-[10px] font-bold text-white"
            style={{ backgroundImage: planGradient(plan) }}
          >
            {plan.toUpperCase()}
          </span>
        )}
      </div>
      <ConnectionStatusRow />
    </BirdoCard>
  );
}

/** "Protected / Not connected" with the server (iOS ProfileView, P1-parity-033). */
function ConnectionStatusRow() {
  const { protectedNow, serverName } = useAppStore(
    useShallow((s) => {
      const live = s.liveMultiHop
        ? `${s.liveMultiHop.entryName} → ${s.liveMultiHop.exitName}`
        : findLiveServer(s.servers, s.liveServerId, s.liveServerName)?.name ?? s.liveServerName;
      return { protectedNow: selectDisplayState(s) === 'connected', serverName: live };
    }),
  );
  const tint = protectedNow ? statusTokens.green : white.w40;
  return (
    <div
      className="mt-4 flex items-center gap-2.5 rounded-birdo-md px-3.5 py-2.5"
      style={{ backgroundColor: surface.s2 }}
    >
      <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: tint }} aria-hidden />
      <div className="min-w-0 flex-1">
        <div className="text-[13px] font-semibold" style={{ color: white.w100 }}>
          {protectedNow ? 'Protected' : 'Not connected'}
        </div>
        <div className="truncate text-[11px]" style={{ color: white.w60 }}>
          {protectedNow ? (serverName ? `Connected · ${serverName}` : 'Connected') : 'Click Connect to start'}
        </div>
      </div>
      <Shield size={20} color={tint} aria-hidden />
    </div>
  );
}

// ── Anonymous account number (recovery credential) ─────────────────────────
//
// The 24-digit number is the ONLY way back into an anonymous account. Grouped
// in fours with spaces (canonical), copied as digits only — the old copy
// inserted pipes the sign-in field then had to strip — and MASKED until the
// user asks to see it (Account API contract item 86): this tab is on screen
// whenever the window is, and screenshots and screen shares are how a
// credential that is shown in full gets lost.
//
// `null`: an anonymous account whose number the server did not send. The card
// says so instead of showing an empty or made-up number.

export function AccountNumberCard({ accountNumber }: { accountNumber: string | null }) {
  return (
    <BirdoCard cornerRadius={20} padding="16px">
      <div className="flex items-center gap-2">
        <KeyRound size={16} color={brand.accent} aria-hidden />
        <span className="text-[11px] font-bold uppercase tracking-wide" style={{ color: white.w60 }}>
          Account number
        </span>
      </div>
      {accountNumber ? (
        <AccountNumberRow accountNumber={accountNumber} />
      ) : (
        <p className="mt-2 text-[12px]" style={{ color: white.w60 }}>
          Your account number was shown once, when this account was created, and can&apos;t be shown
          here. If you saved it, keep it safe: it is the only way back into this account.
        </p>
      )}
    </BirdoCard>
  );
}

function AccountNumberRow({ accountNumber }: { accountNumber: string }) {
  const [copied, setCopied] = useState(false);
  const [revealed, setRevealed] = useState(false);
  const pretty = revealed ? formatAccountNumber(accountNumber) : maskAccountNumber(accountNumber);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(accountNumber.replace(/\D/g, ''));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable — the number is still visible to copy manually */
    }
  };

  return (
    <>
      <div
        className="mt-2.5 flex w-full items-center gap-2 rounded-birdo-sm px-3 py-1.5"
        style={{ backgroundColor: surface.s2, border: `1px solid ${hairline.soft}` }}
      >
        <span
          className="min-w-0 flex-1 truncate font-mono text-[13px] tracking-wide"
          style={{ color: '#FFFFFF' }}
          data-testid="account-number"
        >
          {pretty}
        </span>
        <button
          type="button"
          onClick={() => setRevealed((r) => !r)}
          aria-pressed={revealed}
          aria-label={revealed ? 'Hide account number' : 'Show account number'}
          className="rounded-birdo-xs p-1.5 transition-colors hover:bg-white/5"
        >
          {revealed ? (
            <EyeOff size={16} color={white.w60} aria-hidden />
          ) : (
            <Eye size={16} color={white.w60} aria-hidden />
          )}
        </button>
        <button
          type="button"
          onClick={copy}
          aria-label="Copy account number"
          className="rounded-birdo-xs p-1.5 transition-colors hover:bg-white/5"
        >
          {copied ? (
            <Check size={16} color={brand.accentLight} aria-hidden />
          ) : (
            <Copy size={16} color={white.w60} aria-hidden />
          )}
        </button>
      </div>
      <p className="mt-2 flex items-start gap-1.5 text-[12px]" style={{ color: white.w60 }}>
        <ShieldAlert size={14} color={statusTokens.yellow} aria-hidden className="mt-0.5 shrink-0" />
        <span>
          This is your <strong style={{ color: white.w80 }}>only</strong> way to recover this account.
          Save it somewhere safe — we can&apos;t reset it.
        </span>
      </p>
    </>
  );
}

// ── Subscription summary ─────────────────────────────────────────────────

interface SubscriptionCardProps {
  plan: string | null;
  planStatus: LoadStatus;
  accountStatus: 'active' | 'expired' | 'cancelled' | 'unknown';
  expiresAt: string | null;
  maxDevices: number;
  bandwidthLimit: number;
  onRetry: () => void;
}

export function SubscriptionCard({
  plan,
  planStatus,
  accountStatus,
  expiresAt,
  maxDevices,
  bandwidthLimit,
  onRetry,
}: SubscriptionCardProps) {
  // Unknown is NOT Free (W2-011): no "Free plan", no "0 devices", no
  // "INACTIVE" — say it is loading, or that it failed, and offer Retry.
  if (plan === null) {
    return (
      <BirdoCard cornerRadius={20} padding="18px">
        {planStatus === 'error' ? (
          <div className="flex items-center gap-3">
            <CircleAlert size={20} color={statusTokens.red} aria-hidden className="shrink-0" />
            <p className="flex-1 text-[13px]" style={{ color: white.w80 }}>
              Couldn't load your plan.
            </p>
            <button
              type="button"
              onClick={onRetry}
              className="shrink-0 rounded-birdo-sm px-3 py-1.5 text-[13px] font-semibold"
              style={{ backgroundColor: brand.accentBg, color: brand.accentSoft }}
            >
              Retry
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-3" aria-busy="true">
            <span
              className="h-12 w-12 shrink-0 animate-pulse rounded-birdo-md motion-reduce:animate-none"
              style={{ backgroundColor: surface.s2 }}
              aria-hidden
            />
            <p className="text-[13px]" style={{ color: white.w60 }}>
              Loading your plan…
            </p>
          </div>
        )}
      </BirdoCard>
    );
  }

  const isActive = accountStatus === 'active';
  const ends = formatDate(expiresAt);
  const paid = (planRank(plan) ?? 0) >= 1;

  // Three-way (mirrors mobile): only an ACTIVE sub "Renews"; a cancelled or
  // expired one with an end date shows "Access until" (calling it "Renews"
  // would be a lie).
  const subtitle =
    ends && isActive
      ? `Renews ${ends}`
      : ends
        ? `Access until ${ends}`
        : isActive
          ? paid ? 'Active subscription' : 'Free tier — upgrade for premium'
          : 'Free tier — upgrade for premium';

  const chips = [
    `${maxDevices} device${maxDevices === 1 ? '' : 's'}`,
    bandwidthLimit > 0 ? `${bandwidthLimit} GB / month` : 'Unlimited data',
    ...(paid ? ['Premium servers'] : []),
  ];

  return (
    <BirdoCard cornerRadius={20} padding="18px">
      <div className="flex flex-col gap-3.5">
        <div className="flex items-center">
          <div
            className="flex h-12 w-12 shrink-0 items-center justify-center rounded-birdo-md"
            style={{ backgroundImage: planGradient(plan) }}
          >
            <Star size={20} color="#FFFFFF" aria-hidden />
          </div>
          <div className="ml-3.5 min-w-0 flex-1">
            <div className="truncate text-[16px] font-semibold" style={{ color: '#FFFFFF' }}>
              {planName(plan)} plan
            </div>
            <div className="truncate text-[12px]" style={{ color: white.w60 }}>
              {subtitle}
            </div>
          </div>
          <span
            className="birdo-badge shrink-0 rounded-full px-2.5 py-1 text-[10px] font-bold"
            style={{
              backgroundColor: isActive ? statusTokens.greenBg : surface.s2,
              color: isActive ? statusTokens.green : white.w60,
            }}
          >
            {isActive ? 'ACTIVE' : 'INACTIVE'}
          </span>
        </div>

        <div className="flex flex-wrap gap-2">
          {chips.map((label) => (
            <span
              key={label}
              className="rounded-birdo-sm px-2.5 py-1.5 text-[11px] font-medium"
              style={{ backgroundColor: surface.s2, border: `1px solid ${hairline.soft}`, color: white.w60 }}
            >
              {label}
            </span>
          ))}
        </div>
      </div>
    </BirdoCard>
  );
}
