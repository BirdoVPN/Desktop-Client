/**
 * Profile — top-level tab root.
 *
 * Identity card (avatar + name/email + plan), a subscription summary, and the
 * few account actions kept IN-APP: redeem voucher + sign out. Everything else —
 * managing the subscription, deleting the account, exporting data, and the
 * legal links — lives on the web (dashboard.birdo.app), so it's intentionally
 * NOT duplicated here.
 *
 * IPC (unchanged contracts):
 *   get_subscription_status (snake_case fields), disconnect_vpn, logout,
 *   redeem_voucher.
 */
import { useCallback, useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { motion, AnimatePresence } from 'framer-motion';
import { useShallow } from 'zustand/react/shallow';
import { Star, Gift, LogOut, CheckCircle2 } from 'lucide-react';
import { useAppStore } from '@/store/app-store';
import {
  BirdoCard,
  BirdoSectionHeader,
  BirdoNavRow,
  BirdoButton,
  BirdoTextField,
} from '@/components/birdo';
import {
  brand,
  status as statusTokens,
  surface,
  white,
  hairline,
  gradient,
  motion as motionTokens,
} from '@/lib/birdo-theme';

/** Subscription status as returned by the Rust `get_subscription_status` command. */
interface RustSubscription {
  plan: string;
  status: string;
  expires_at: string | null;
  devices_used: number;
  devices_limit: number;
  bandwidth_limit: number | null;
}

/** Per-plan gradient stops — mirrors mobile's `planGradient`. */
function planGradient(plan: string): string {
  switch (plan.toUpperCase()) {
    case 'SOVEREIGN':
      return 'linear-gradient(135deg, #7C3AED 0%, #4C1D95 100%)';
    case 'OPERATIVE':
      return 'linear-gradient(135deg, #6366F1 0%, #4338CA 100%)';
    default:
      return 'linear-gradient(135deg, #475569 0%, #334155 100%)';
  }
}

/** Backend renewal date → plain `yyyy-MM-dd` (mirrors mobile's `formatRenewalDate`). */
function formatRenewalDate(raw: string | null): string | null {
  const v = (raw ?? '').trim();
  if (!v) return null;
  const datePart = v.split('T')[0];
  if (/^\d{4}-\d{2}-\d{2}$/.test(datePart)) return datePart;
  const parsed = new Date(v);
  if (Number.isNaN(parsed.getTime())) return null;
  const yyyy = parsed.getFullYear();
  const mm = String(parsed.getMonth() + 1).padStart(2, '0');
  const dd = String(parsed.getDate()).padStart(2, '0');
  return `${yyyy}-${mm}-${dd}`;
}

export function Profile() {
  const { account, userEmail, setAccount, logout, setAuthenticated } = useAppStore(
    useShallow((s) => ({
      account: s.account,
      userEmail: s.userEmail,
      setAccount: s.setAccount,
      logout: s.logout,
      setAuthenticated: s.setAuthenticated,
    }))
  );
  // The signed-in email is mirrored in both `account.email` and the top-level
  // `userEmail` (set at login). Fall back to userEmail so the identity card can
  // never render "Anonymous" for a logged-in user even if one source is null.
  const resolvedEmail = account.email ?? userEmail ?? null;

  const [showVoucherDialog, setShowVoucherDialog] = useState(false);

  // Hydrate subscription details (devices / bandwidth / renewal) the same way
  // the Dashboard does. Extracted so a successful voucher redemption can refresh
  // the card in place.
  const hydrateSubscription = useCallback(() => {
    invoke<RustSubscription>('get_subscription_status')
      .then((sub) => {
        setAccount({
          plan: sub.plan?.toUpperCase() || 'RECON',
          status: (['active', 'expired', 'cancelled'] as const).includes(
            sub.status as 'active'
          )
            ? (sub.status as 'active' | 'expired' | 'cancelled')
            : 'unknown',
          expiresAt: sub.expires_at ?? null,
          activeDevices: sub.devices_used ?? 0,
          maxDevices: sub.devices_limit ?? 1,
          // Backend no longer reports bandwidth usage (always 0).
          bandwidthUsed: 0,
          bandwidthLimit: sub.bandwidth_limit ?? 0,
        });
      })
      .catch(() => {
        /* silent — Dashboard also fetches this; offline is non-fatal */
      });
  }, [setAccount]);

  useEffect(() => {
    hydrateSubscription();
  }, [hydrateSubscription]);

  const handleLogout = async () => {
    const cur = useAppStore.getState().connectionState;
    if (cur === 'connected' || cur === 'connecting' || cur === 'reconnecting') {
      try {
        await invoke('disconnect_vpn');
      } catch {
        /* best effort */
      }
    }
    try {
      await invoke('logout');
    } catch {
      /* best effort */
    }
    logout();
    setAuthenticated(false);
  };

  return (
    // Transparent so the App-level PixelCanvas backdrop shows through.
    <div className="h-full overflow-y-auto">
      {/* Tab-root header (no back button) */}
      <div className="px-5 pb-2 pt-6">
        <h1 className="text-[22px] font-semibold" style={{ color: '#FFFFFF' }}>
          Profile
        </h1>
        <p className="mt-0.5 text-[13px]" style={{ color: white.w60 }}>
          Identity, subscription &amp; account
        </p>
      </div>

      <div className="flex flex-col gap-3 px-5 pb-12 pt-2">
        <IdentityCard email={resolvedEmail} plan={account.plan} />

        <SubscriptionCard
          plan={account.plan}
          accountStatus={account.status}
          expiresAt={account.expiresAt}
          maxDevices={account.maxDevices}
          bandwidthLimit={account.bandwidthLimit}
        />

        {/* ── ACCOUNT ─────────────────────────────────────────────────── */}
        <div className="mt-1">
          <BirdoSectionHeader title="Account" />
          <BirdoCard padding="0.25rem">
            <BirdoNavRow
              title="Redeem voucher"
              subtitle="Activate a 30 / 90-day code"
              leadingIcon={Gift}
              leadingTint={brand.purpleSoft}
              onClick={() => setShowVoucherDialog(true)}
            />
          </BirdoCard>
        </div>

        {/* ── SESSION ─────────────────────────────────────────────────── */}
        <div className="mt-1">
          <BirdoSectionHeader title="Session" />
          <BirdoCard padding="0.25rem">
            <BirdoNavRow
              title="Sign out"
              subtitle={resolvedEmail ?? 'Sign out of this device'}
              leadingIcon={LogOut}
              leadingTint={statusTokens.red}
              onClick={handleLogout}
            />
          </BirdoCard>
        </div>
      </div>

      <AnimatePresence>
        {showVoucherDialog && (
          <VoucherRedeemDialog
            onDismiss={() => setShowVoucherDialog(false)}
            onRedeemed={hydrateSubscription}
          />
        )}
      </AnimatePresence>
    </div>
  );
}

// ── Identity card ───────────────────────────────────────────────────────────

interface IdentityCardProps {
  email: string | null;
  plan: string | null;
}

function IdentityCard({ email, plan }: IdentityCardProps) {
  const displayEmail = email ?? 'Anonymous';
  const name = (email?.split('@')[0] || displayEmail).trim();
  const planLabel = plan ?? 'RECON';
  const initial = (name.charAt(0) || '?').toUpperCase();

  return (
    <BirdoCard cornerRadius={22} padding="20px">
      <div className="flex items-center">
        {/* User avatar — initial on the plan-tinted gradient (the brand mark is
            the window's title bar; this slot represents the signed-in user). */}
        <div
          className="flex h-14 w-14 shrink-0 items-center justify-center rounded-[18px] text-[22px] font-bold text-white"
          style={{
            backgroundImage: planGradient(planLabel),
            boxShadow: 'inset 0 1px 0 rgba(255,255,255,0.18)',
          }}
          aria-hidden
        >
          {initial}
        </div>
        <div className="ml-3.5 min-w-0 flex-1">
          <div
            className="truncate text-[18px] font-semibold"
            style={{ color: '#FFFFFF' }}
          >
            {name}
          </div>
          <div className="truncate text-[13px]" style={{ color: white.w60 }}>
            {displayEmail}
          </div>
        </div>
        <PlanPill plan={planLabel} />
      </div>
    </BirdoCard>
  );
}

// ── Subscription card ─────────────────────────────────────────────────────

interface SubscriptionCardProps {
  plan: string | null;
  accountStatus: 'active' | 'expired' | 'cancelled' | 'unknown';
  expiresAt: string | null;
  maxDevices: number;
  bandwidthLimit: number;
}

function SubscriptionCard({
  plan,
  accountStatus,
  expiresAt,
  maxDevices,
  bandwidthLimit,
}: SubscriptionCardProps) {
  const planLabel = plan ?? 'RECON';
  const isActive = accountStatus === 'active';
  const endsAtFormatted = formatRenewalDate(expiresAt);

  const subtitle = endsAtFormatted
    ? `Renews ${endsAtFormatted}`
    : isActive
    ? 'Active subscription'
    : 'Free tier — upgrade for premium';

  return (
    <BirdoCard cornerRadius={20} padding="18px">
      <div className="flex flex-col gap-3.5">
        <div className="flex items-center">
          <div
            className="flex h-12 w-12 shrink-0 items-center justify-center rounded-birdo-md"
            style={{ backgroundImage: planGradient(planLabel) }}
          >
            <Star size={20} color="#FFFFFF" aria-hidden />
          </div>
          <div className="ml-3.5 min-w-0 flex-1">
            <div
              className="truncate text-[16px] font-semibold"
              style={{ color: '#FFFFFF' }}
            >
              {planLabel} plan
            </div>
            <div className="truncate text-[12px]" style={{ color: white.w60 }}>
              {subtitle}
            </div>
          </div>
          <StatusPillSmall active={isActive} />
        </div>

        {/* Benefit chips */}
        <div className="flex flex-wrap gap-2">
          <BenefitChip label={`${maxDevices} device${maxDevices === 1 ? '' : 's'}`} />
          <BenefitChip
            label={bandwidthLimit > 0 ? `${bandwidthLimit} GB / mo` : 'Unlimited'}
          />
        </div>
      </div>
    </BirdoCard>
  );
}

function StatusPillSmall({ active }: { active: boolean }) {
  return (
    <span
      className="shrink-0 rounded-full px-2.5 py-1 text-[10px] font-bold"
      style={{
        backgroundColor: active ? statusTokens.greenBg : surface.s2,
        color: active ? statusTokens.green : white.w60,
      }}
    >
      {active ? 'ACTIVE' : 'INACTIVE'}
    </span>
  );
}

function BenefitChip({ label }: { label: string }) {
  return (
    <span
      className="rounded-birdo-sm px-2.5 py-1.5 text-[11px] font-medium"
      style={{
        backgroundColor: surface.s2,
        border: `1px solid ${hairline.soft}`,
        color: white.w60,
      }}
    >
      {label}
    </span>
  );
}

function PlanPill({ plan }: { plan: string }) {
  return (
    <span
      className="shrink-0 rounded-full px-2.5 py-1 text-[10px] font-bold text-white"
      style={{ backgroundImage: planGradient(plan) }}
    >
      {plan.toUpperCase()}
    </span>
  );
}

// ── Voucher redemption dialog ───────────────────────────────────────────────
//
// In-app parity with mobile's VoucherRedeemDialog. Calls the Rust
// `redeem_voucher` command (→ POST /vouchers/redeem). On success it shows the
// days added / new plan and refreshes the subscription card via `onRedeemed`.

function VoucherRedeemDialog({
  onDismiss,
  onRedeemed,
}: {
  onDismiss: () => void;
  onRedeemed: () => void;
}) {
  const [code, setCode] = useState('');
  const [redeeming, setRedeeming] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<{ plan: string; days: number } | null>(null);

  // Escape closes the modal (standard desktop affordance), but not mid-redeem.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !redeeming) onDismiss();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [redeeming, onDismiss]);

  const canSubmit = code.trim().length > 0 && !redeeming && !success;

  const handleConfirm = async () => {
    if (!canSubmit) return;
    setRedeeming(true);
    setError(null);
    try {
      const res = await invoke<{
        ok: boolean;
        plan: string;
        durationDays: number;
        extended: boolean;
      }>('redeem_voucher', { code: code.trim() });
      setSuccess({ plan: res.plan, days: res.durationDays });
      // Refresh the subscription card so the new plan/expiry shows immediately.
      onRedeemed();
    } catch (e: unknown) {
      const message =
        typeof e === 'string'
          ? e
          : e instanceof Error
            ? e.message
            : typeof e === 'object' &&
                e !== null &&
                typeof (e as { message?: unknown }).message === 'string'
              ? (e as { message: string }).message
              : 'Could not redeem that voucher.';
      setError(message);
      setRedeeming(false);
    }
  };

  return (
    <motion.div
      className="absolute inset-0 z-50 flex items-center justify-center p-5"
      style={{ backgroundColor: 'rgba(0,0,0,0.6)' }}
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: motionTokens.fast, ease: motionTokens.ease }}
      onClick={() => !redeeming && onDismiss()}
    >
      <motion.div
        role="dialog"
        aria-modal="true"
        aria-label="Redeem voucher"
        className="w-full max-w-[360px] overflow-hidden rounded-birdo-lg"
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
            {success ? (
              <CheckCircle2 size={22} color={statusTokens.green} aria-hidden />
            ) : (
              <Gift size={22} color={brand.purple} aria-hidden />
            )}
            <h2
              className="text-[16px] font-bold"
              style={{ color: success ? statusTokens.green : '#FFFFFF' }}
            >
              {success ? 'Voucher redeemed' : 'Redeem voucher'}
            </h2>
          </div>

          {success ? (
            <p className="text-[13px]" style={{ color: white.w60 }}>
              {success.days > 0
                ? `${success.days} days added to your ${success.plan} plan.`
                : `Your ${success.plan} plan has been updated.`}
            </p>
          ) : (
            <>
              <p className="text-[13px]" style={{ color: white.w60 }}>
                Enter a 30 or 90-day voucher code to extend your subscription.
                Payments are handled on the web — vouchers add time to your plan.
              </p>
              <BirdoTextField
                value={code}
                onChange={(v) => {
                  // Codes are case-insensitive; uppercase for display + matching.
                  setCode(v.toUpperCase());
                  if (error) setError(null);
                }}
                label="Voucher code"
                type="text"
                placeholder="BIRD-XXXX-XXXX-XXXX"
                error={error != null}
                disabled={redeeming}
                autoComplete="off"
              />
              {error && (
                <p className="text-[12px]" style={{ color: statusTokens.red }}>
                  {error}
                </p>
              )}
            </>
          )}

          <div className="flex gap-2.5">
            {success ? (
              <BirdoButton text="Done" variant="primary" fullWidth onClick={onDismiss} />
            ) : (
              <>
                <BirdoButton
                  text="Cancel"
                  variant="secondary"
                  fullWidth
                  disabled={redeeming}
                  onClick={onDismiss}
                />
                <BirdoButton
                  text={redeeming ? 'Redeeming…' : 'Redeem'}
                  variant="primary"
                  fullWidth
                  isLoading={redeeming}
                  disabled={!canSubmit}
                  onClick={handleConfirm}
                />
              </>
            )}
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}
