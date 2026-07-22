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
import { open } from '@tauri-apps/plugin-shell';
import { motion, AnimatePresence } from 'framer-motion';
import { useShallow } from 'zustand/react/shallow';
import {
  Star,
  Gift,
  LogOut,
  CheckCircle2,
  Copy,
  Check,
  Trash2,
  Download,
  KeyRound,
  ShieldAlert,
  Gauge,
  CreditCard,
} from 'lucide-react';
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
      return 'linear-gradient(135deg, #059669 0%, #064E3B 100%)';
    case 'OPERATIVE':
      return 'linear-gradient(135deg, #6366F1 0%, #4338CA 100%)';
    default:
      return 'linear-gradient(135deg, #475569 0%, #334155 100%)';
  }
}

/**
 * Anonymous accounts carry a synthetic email `anon_<24-digit-id>@anonymous.local`.
 * The 24-digit id is the account's ONLY recovery credential. Extract it so the
 * UI can surface it cleanly + copyably (mirrors mobile) instead of leaking the
 * raw synthetic email — which reads as a bug.
 */
const ANON_EMAIL_RE = /^anon_(\d{24})@anonymous\.local$/i;
function anonAccountNumber(email: string | null): string | null {
  if (!email) return null;
  const m = ANON_EMAIL_RE.exec(email.trim());
  return m ? m[1] : null;
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
  const { account, userEmail, setAccount, logout, setAuthenticated, pushRoute } = useAppStore(
    useShallow((s) => ({
      account: s.account,
      userEmail: s.userEmail,
      setAccount: s.setAccount,
      logout: s.logout,
      setAuthenticated: s.setAuthenticated,
      pushRoute: s.pushRoute,
    }))
  );
  const isFreeTier = (account.plan ?? 'RECON').toUpperCase() === 'RECON';
  // The signed-in email is mirrored in both `account.email` and the top-level
  // `userEmail` (set at login). Fall back to userEmail so the identity card can
  // never render "Anonymous" for a logged-in user even if one source is null.
  const resolvedEmail = account.email ?? userEmail ?? null;
  // Anonymous accounts have no real email; derive the 24-digit recovery id from
  // the synthetic address so we can surface it cleanly (and never render the raw
  // `anon_…@anonymous.local` string, which reads as a bug).
  const accountNumber = anonAccountNumber(resolvedEmail);
  const isAnon = accountNumber != null;

  const [showVoucherDialog, setShowVoucherDialog] = useState(false);
  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [exportState, setExportState] = useState<'idle' | 'working' | 'done' | 'error'>('idle');

  // GDPR data export (Art. 20). The backend command returns the full JSON blob;
  // save it via a webview download so the user gets a file with no extra plugin.
  const handleExportData = useCallback(async () => {
    if (exportState === 'working') return;
    setExportState('working');
    try {
      const data = await invoke<unknown>('export_user_data');
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'birdo-account-data.json';
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      setExportState('done');
      setTimeout(() => setExportState('idle'), 2500);
    } catch {
      setExportState('error');
      setTimeout(() => setExportState('idle'), 3000);
    }
  }, [exportState]);

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
          // Live monthly usage is sourced separately by <UsageMeter/> from
          // get_usage_stats (/vpn/stats); this summary card only needs the cap.
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
      </div>

      <div className="flex flex-col gap-3 px-5 pb-12 pt-2">
        <IdentityCard email={resolvedEmail} plan={account.plan} isAnon={isAnon} />

        {isAnon && accountNumber && <AccountNumberCard accountNumber={accountNumber} />}

        <SubscriptionCard
          plan={account.plan}
          accountStatus={account.status}
          expiresAt={account.expiresAt}
          maxDevices={account.maxDevices}
          bandwidthLimit={account.bandwidthLimit}
        />

        <UsageMeter />

        {/* ── ACCOUNT ─────────────────────────────────────────────────── */}
        <div className="mt-1">
          <BirdoSectionHeader title="Account" />
          <BirdoCard padding="0.25rem">
            <BirdoNavRow
              title={isFreeTier ? 'View plans & pricing' : 'Manage subscription'}
              leadingIcon={CreditCard}
              leadingTint={brand.accent}
              onClick={
                isFreeTier
                  ? () => pushRoute('pricing')
                  : () => {
                      void open('https://dashboard.birdo.app/billing').catch(() => {});
                    }
              }
            />
            <BirdoNavRow
              title="Redeem voucher"
              leadingIcon={Gift}
              leadingTint={brand.accentSoft}
              onClick={() => setShowVoucherDialog(true)}
            />
            <BirdoNavRow
              title="Export my data"
              subtitle={
                exportState === 'working'
                  ? 'Preparing your data…'
                  : exportState === 'done'
                    ? 'Saved to your downloads'
                    : exportState === 'error'
                      ? 'Export failed — try again'
                      : undefined
              }
              leadingIcon={Download}
              leadingTint={statusTokens.blue}
              onClick={handleExportData}
            />
            <BirdoNavRow
              title="Delete account"
              leadingIcon={Trash2}
              leadingTint={statusTokens.red}
              onClick={() => setShowDeleteDialog(true)}
            />
          </BirdoCard>
        </div>

        {/* ── SESSION ─────────────────────────────────────────────────── */}
        <div className="mt-1">
          <BirdoSectionHeader title="Session" />
          <BirdoCard padding="0.25rem">
            <BirdoNavRow
              title="Sign out"
              subtitle={isAnon ? 'Anonymous account' : (resolvedEmail ?? undefined)}
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
        {showDeleteDialog && (
          <DeleteAccountDialog
            // Authoritative from /auth/me, and deliberately NOT combined with
            // `isAnon`: an anonymous user who set a password on the website
            // still has one, and the backend will demand it.
            hasPassword={account.hasPassword}
            onDismiss={() => setShowDeleteDialog(false)}
            onDeleted={async () => {
              try {
                await invoke('logout');
              } catch {
                /* best effort — account is already gone server-side */
              }
              logout();
              setAuthenticated(false);
            }}
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
  isAnon: boolean;
}

function IdentityCard({ email, plan, isAnon }: IdentityCardProps) {
  const planLabel = plan ?? 'RECON';
  // Three distinct states — a real email, a genuinely anonymous account, and an
  // identity we simply could not load. They must never be conflated: falling
  // back to the word "Anonymous" for a null email told users with a real,
  // verified email address that they had no account, which is a false statement
  // about their identity, not a cosmetic glitch. When the email is unknown, say
  // it is unknown.
  // Written as a branch rather than nested ternaries so TypeScript narrows
  // `email` to a string in the final case — no non-null assertions needed.
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
  const identityUnknown = !isAnon && !email;
  const initial = isAnon || identityUnknown ? '·' : (name.charAt(0) || '?').toUpperCase();

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
            {subtitle}
          </div>
        </div>
        <PlanPill plan={planLabel} />
      </div>
    </BirdoCard>
  );
}

// ── Anonymous account-number card (recovery credential) ──────────────────────
//
// The 24-digit id is the ONLY way back into an anonymous account. Surface it
// prominently and copyably (mirrors mobile), with an explicit "save this" note.

function AccountNumberCard({ accountNumber }: { accountNumber: string }) {
  const [copied, setCopied] = useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(accountNumber);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable — the number is still visible to copy manually */
    }
  };

  return (
    <BirdoCard cornerRadius={20} padding="16px">
      <div className="flex items-center gap-2">
        <KeyRound size={16} color={brand.accent} aria-hidden />
        <span className="text-[11px] font-bold uppercase tracking-wide" style={{ color: white.w60 }}>
          Account number
        </span>
      </div>
      <button
        type="button"
        onClick={copy}
        className="mt-2.5 flex w-full items-center gap-3 rounded-birdo-sm px-3 py-2.5 text-left transition-colors hover:bg-white/5"
        style={{ backgroundColor: surface.s2, border: `1px solid ${hairline.soft}` }}
        aria-label="Copy account number"
      >
        <span
          className="min-w-0 flex-1 truncate font-mono text-[13px] tracking-wide"
          style={{ color: '#FFFFFF' }}
        >
          {accountNumber}
        </span>
        {copied ? (
          <Check size={16} color={statusTokens.green} aria-hidden />
        ) : (
          <Copy size={16} color={white.w60} aria-hidden />
        )}
      </button>
      <p className="mt-2 flex items-start gap-1.5 text-[12px]" style={{ color: white.w60 }}>
        <ShieldAlert size={14} color={statusTokens.yellow} aria-hidden className="mt-0.5 shrink-0" />
        <span>
          This is your <strong style={{ color: white.w80 }}>only</strong> way to recover this account.
          Save it somewhere safe — we can&apos;t reset it.
        </span>
      </p>
    </BirdoCard>
  );
}

// ── Data / Limit section ─────────────────────────────────────────────────────
//
// The desktop equivalent of mobile's LimitScreen: shown for EVERY user type.
// Free (capped) plans get a Used / Left / Resets meter of their monthly cap;
// paid (uncapped) plans get the "Unlimited" state. Sources live per-user usage
// from `get_usage_stats` (/vpn/stats) and honours the freshness flag so a
// never-synced node shows "awaiting first sync" rather than a misleading 0.

interface RustUsageStats {
  plan: string | null;
  bandwidthLimitGb: number | null;
  bandwidthUsedGb: number | null;
  bandwidthPeriodEnd: string | null;
  bandwidthLastSyncAt: string | null;
  bandwidthIsFresh: boolean | null;
}

function UsageMeter() {
  const [usage, setUsage] = useState<RustUsageStats | null>(null);

  useEffect(() => {
    let alive = true;
    invoke<RustUsageStats>('get_usage_stats')
      .then((u) => {
        if (alive) setUsage(u);
      })
      .catch(() => {
        /* offline / non-fatal — the section simply doesn't render yet */
      });
    return () => {
      alive = false;
    };
  }, []);

  // Still loading (or offline) — nothing to show yet.
  if (!usage) return null;

  const limit = usage.bandwidthLimitGb;
  const hasCap = limit != null && limit > 0;
  const limitGb = limit ?? 0;
  const fresh = usage.bandwidthIsFresh === true;
  const used = fresh ? Math.max(0, usage.bandwidthUsedGb ?? 0) : 0;
  const pct = limitGb > 0 ? Math.max(0, Math.min(100, (used / limitGb) * 100)) : 0;
  const left = Math.max(0, limitGb - used);
  const resets = formatRenewalDate(usage.bandwidthPeriodEnd ?? null);
  const nearCap = pct >= 90;

  return (
    <BirdoCard cornerRadius={20} padding="18px">
      <div className="flex items-center gap-2">
        <Gauge size={16} color={brand.accent} aria-hidden />
        <span className="text-[11px] font-bold uppercase tracking-wide" style={{ color: white.w60 }}>
          Data this month
        </span>
      </div>

      {!hasCap ? (
        // Paid / uncapped plan — mobile shows the "Unlimited" state for everyone.
        <div className="mt-2.5 flex items-baseline gap-2">
          <span className="text-[18px] font-semibold" style={{ color: brand.accent }}>
            Unlimited
          </span>
          <span className="text-[12px]" style={{ color: white.w60 }}>
            data on your plan
          </span>
        </div>
      ) : fresh ? (
        <>
          <div className="mt-2.5 flex items-baseline justify-between">
            <span className="text-[16px] font-semibold" style={{ color: '#FFFFFF' }}>
              {used.toFixed(1)} GB
            </span>
            <span className="text-[12px]" style={{ color: white.w60 }}>
              of {limitGb} GB
            </span>
          </div>
          <div className="mt-2 h-2 w-full overflow-hidden rounded-full" style={{ backgroundColor: surface.s2 }}>
            <div
              className="h-full rounded-full transition-all"
              style={{
                width: `${pct}%`,
                backgroundColor: nearCap ? statusTokens.red : brand.accent,
              }}
            />
          </div>
          <div className="mt-2 flex items-center justify-between text-[12px]" style={{ color: white.w60 }}>
            <span>{left.toFixed(1)} GB left</span>
            {resets && <span>Resets {resets}</span>}
          </div>
        </>
      ) : (
        <p className="mt-2 text-[13px]" style={{ color: white.w60 }}>
          Connect to start counting your {limitGb} GB monthly allowance.
        </p>
      )}
    </BirdoCard>
  );
}

// ── Delete-account dialog (GDPR Art.17) ──────────────────────────────────────
//
// Accounts WITH a password re-confirm with it (defense-in-depth against a
// compromised webview). Accounts without one — anonymous, and SSO accounts that
// sign in through Google/GitHub — type "DELETE" instead. Grouping SSO with
// email here used to trap SSO users: the dialog demanded a password they had
// never set, so Delete stayed disabled and they could not exercise erasure at
// all. Backend: delete_account.

function DeleteAccountDialog({
  hasPassword,
  onDismiss,
  onDeleted,
}: {
  hasPassword: boolean;
  onDismiss: () => void;
  onDeleted: () => void;
}) {
  const [password, setPassword] = useState('');
  const [confirmText, setConfirmText] = useState('');
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !deleting) onDismiss();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [deleting, onDismiss]);

  const canSubmit =
    !deleting && (hasPassword ? password.length > 0 : confirmText.trim().toUpperCase() === 'DELETE');

  const handleConfirm = async () => {
    if (!canSubmit) return;
    setDeleting(true);
    setError(null);
    try {
      // Password-less accounts (anonymous and SSO) send the typed confirmation
      // token: the server skips the password check for them entirely, and the
      // Tauri command's request type is non-optional, so a non-empty value
      // keeps the contract satisfied without inventing a fake secret.
      await invoke('delete_account', { request: { password: hasPassword ? password : confirmText.trim() } });
      onDeleted();
    } catch (e: unknown) {
      const message =
        typeof e === 'string' ? e : e instanceof Error ? e.message : 'Could not delete the account.';
      setError(message);
      setDeleting(false);
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
      onClick={() => !deleting && onDismiss()}
    >
      <motion.div
        role="dialog"
        aria-modal="true"
        aria-label="Delete account"
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
            <ShieldAlert size={22} color={statusTokens.red} aria-hidden />
            <h2 className="text-[16px] font-bold" style={{ color: statusTokens.red }}>
              Delete account
            </h2>
          </div>
          <p className="text-[13px]" style={{ color: white.w60 }}>
            This permanently erases your account and all associated data. This
            cannot be undone.
            {hasPassword
              ? ' Enter your password to confirm.'
              : ' Type DELETE below to confirm.'}
          </p>
          {!hasPassword ? (
            <BirdoTextField
              value={confirmText}
              onChange={(v) => {
                setConfirmText(v);
                if (error) setError(null);
              }}
              label="Type DELETE to confirm"
              type="text"
              placeholder="DELETE"
              error={error != null}
              disabled={deleting}
              autoComplete="off"
            />
          ) : (
            <BirdoTextField
              value={password}
              onChange={(v) => {
                setPassword(v);
                if (error) setError(null);
              }}
              label="Password"
              type="password"
              placeholder="••••••••"
              error={error != null}
              disabled={deleting}
              autoComplete="current-password"
            />
          )}
          {error && (
            <p className="text-[12px]" style={{ color: statusTokens.red }}>
              {error}
            </p>
          )}
          <div className="flex gap-2.5">
            <BirdoButton
              text="Cancel"
              variant="secondary"
              fullWidth
              disabled={deleting}
              onClick={onDismiss}
            />
            <BirdoButton
              text={deleting ? 'Deleting…' : 'Delete forever'}
              variant="danger"
              fullWidth
              isLoading={deleting}
              disabled={!canSubmit}
              onClick={handleConfirm}
            />
          </div>
        </div>
      </motion.div>
    </motion.div>
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
  // Friendly display name — mobile shows "Free" for RECON, not the raw code.
  const planDisplay =
    planLabel.toUpperCase() === 'RECON'
      ? 'Free'
      : planLabel.charAt(0).toUpperCase() + planLabel.slice(1).toLowerCase();
  const isActive = accountStatus === 'active';
  const endsAtFormatted = formatRenewalDate(expiresAt);

  // Three-way (mirrors mobile): only an ACTIVE sub "Renews"; a cancelled/expired
  // sub with an end date shows "Access until" (calling it "Renews" would be a lie).
  const subtitle =
    endsAtFormatted && isActive
      ? `Renews ${endsAtFormatted}`
      : endsAtFormatted
        ? `Access until ${endsAtFormatted}`
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
              {planDisplay} plan
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
              <Gift size={22} color={brand.accent} aria-hidden />
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
