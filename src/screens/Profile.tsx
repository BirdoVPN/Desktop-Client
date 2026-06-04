/**
 * Profile — mobile-parity top-level tab root.
 *
 * Mirrors mobile's `ProfileScreen.kt`: identity card, subscription summary, and
 * all Account actions (subscription, voucher, privacy, terms, sign out, delete
 * account). As a TAB ROOT it renders its own header/title area — NOT a pushed
 * BirdoTopBar with a back button.
 *
 * IPC (unchanged contracts):
 *   get_subscription_status (snake_case fields), export_user_data,
 *   disconnect_vpn, logout, delete_account { request: { password } }.
 * Web links open via @tauri-apps/plugin-shell `open()`.
 */
import { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open as openExternal } from '@tauri-apps/plugin-shell';
import { motion, AnimatePresence } from 'framer-motion';
import { useShallow } from 'zustand/react/shallow';
import {
  Shield,
  Star,
  CreditCard,
  ChevronRight,
  Gift,
  ExternalLink,
  ShieldCheck,
  FileText,
  Download,
  LogOut,
  Trash2,
  AlertTriangle,
  Loader2,
} from 'lucide-react';
import { useAppStore } from '@/store/app-store';
import {
  BirdoCard,
  BirdoSectionHeader,
  BirdoNavRow,
  BirdoButton,
  BirdoTextField,
  AppIconMark,
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

const DASHBOARD_URL = 'https://dashboard.birdo.app';
const PRIVACY_URL = 'https://birdo.app/privacy';
const TERMS_URL = 'https://birdo.app/terms';

/** Subscription status as returned by the Rust `get_subscription_status` command. */
interface RustSubscription {
  plan: string;
  status: string;
  expires_at: string | null;
  devices_used: number;
  devices_limit: number;
  bandwidth_used: number;
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
  const { account, connectionState, vpnIp, setAccount, logout, setAuthenticated } =
    useAppStore(
      useShallow((s) => ({
        account: s.account,
        connectionState: s.connectionState,
        vpnIp: s.vpnIp,
        setAccount: s.setAccount,
        logout: s.logout,
        setAuthenticated: s.setAuthenticated,
      }))
    );
  const pushRoute = useAppStore((s) => s.pushRoute);

  const [showDeleteDialog, setShowDeleteDialog] = useState(false);
  const [exportState, setExportState] = useState<'idle' | 'loading' | 'done'>('idle');

  const isConnected = connectionState === 'connected';

  // Hydrate subscription details (devices / bandwidth / renewal) the same way
  // the Dashboard does — the mobile ProfileScreen renders the same fields.
  useEffect(() => {
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
          bandwidthUsed: sub.bandwidth_used ?? 0,
          bandwidthLimit: sub.bandwidth_limit ?? 0,
        });
      })
      .catch(() => {
        /* silent — Dashboard also fetches this; offline is non-fatal */
      });
  }, [setAccount]);

  const handleExport = async () => {
    setExportState('loading');
    try {
      const data = await invoke<Record<string, unknown>>('export_user_data');
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `birdo-data-export-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      setExportState('done');
    } catch {
      setExportState('idle');
    }
  };

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
        <IdentityCard
          email={account.email}
          plan={account.plan}
          isConnected={isConnected}
          publicIp={vpnIp}
        />

        <SubscriptionCard
          plan={account.plan}
          accountStatus={account.status}
          expiresAt={account.expiresAt}
          maxDevices={account.maxDevices}
          bandwidthLimit={account.bandwidthLimit}
          onManage={() => pushRoute('subscription')}
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
              onClick={() => openExternal(DASHBOARD_URL)}
            />
            <BirdoNavRow
              title="Manage on web"
              subtitle="Open dashboard.birdo.app in browser"
              leadingIcon={ExternalLink}
              leadingTint={brand.purpleSoft}
              onClick={() => openExternal(DASHBOARD_URL)}
            />
            <BirdoNavRow
              title="Privacy Policy"
              subtitle="birdo.app/privacy"
              leadingIcon={ShieldCheck}
              leadingTint={brand.purpleSoft}
              onClick={() => openExternal(PRIVACY_URL)}
            />
            <BirdoNavRow
              title="Terms of Service"
              subtitle="birdo.app/terms"
              leadingIcon={FileText}
              leadingTint={brand.purpleSoft}
              onClick={() => openExternal(TERMS_URL)}
            />
            <BirdoNavRow
              title={exportState === 'done' ? 'Data exported' : 'Export my data'}
              subtitle="Download a GDPR copy of your account data"
              leadingIcon={exportState === 'loading' ? Loader2 : Download}
              leadingTint={brand.purpleSoft}
              enabled={exportState !== 'loading'}
              onClick={handleExport}
            />
          </BirdoCard>
        </div>

        {/* ── SESSION ─────────────────────────────────────────────────── */}
        <div className="mt-1">
          <BirdoSectionHeader title="Session" />
          <BirdoCard padding="0.25rem">
            <BirdoNavRow
              title="Sign out"
              subtitle={account.email ?? 'Sign out of this device'}
              leadingIcon={LogOut}
              leadingTint={statusTokens.red}
              onClick={handleLogout}
            />
            <BirdoNavRow
              title="Delete account"
              subtitle="Permanently delete your account and all data"
              leadingIcon={Trash2}
              leadingTint={statusTokens.red}
              onClick={() => setShowDeleteDialog(true)}
            />
          </BirdoCard>
        </div>
      </div>

      <AnimatePresence>
        {showDeleteDialog && (
          <DeleteAccountDialog onDismiss={() => setShowDeleteDialog(false)} />
        )}
      </AnimatePresence>
    </div>
  );
}

// ── Identity card ───────────────────────────────────────────────────────────

interface IdentityCardProps {
  email: string | null;
  plan: string | null;
  isConnected: boolean;
  publicIp: string | null;
}

function IdentityCard({ email, plan, isConnected, publicIp }: IdentityCardProps) {
  const displayEmail = email ?? 'Anonymous';
  const name = (email?.split('@')[0] || displayEmail).trim();
  const planLabel = plan ?? 'RECON';

  return (
    <BirdoCard cornerRadius={22} padding="20px">
      <div className="flex flex-col gap-3.5">
        <div className="flex items-center">
          <AppIconMark size={56} style={{ borderRadius: 18 }} />
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

        {/* Connection / public-IP row */}
        <div
          className="flex items-center rounded-birdo-md px-3.5 py-2.5"
          style={{ backgroundColor: surface.s2 }}
        >
          <span
            className="h-2.5 w-2.5 shrink-0 rounded-full"
            style={{ backgroundColor: isConnected ? statusTokens.green : white.w40 }}
          />
          <div className="ml-2.5 min-w-0 flex-1">
            <div
              className="truncate text-[13px] font-semibold"
              style={{ color: '#FFFFFF' }}
            >
              {isConnected ? 'Protected' : 'Not connected'}
            </div>
            <div className="truncate text-[11px]" style={{ color: white.w60 }}>
              {isConnected && publicIp
                ? `Public IP · ${publicIp}`
                : 'Tap Connect to reveal'}
            </div>
          </div>
          <Shield
            size={20}
            color={isConnected ? statusTokens.green : white.w40}
            aria-hidden
          />
        </div>
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
  onManage: () => void;
}

function SubscriptionCard({
  plan,
  accountStatus,
  expiresAt,
  maxDevices,
  bandwidthLimit,
  onManage,
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

        {/* CTA → pushes the subscription sub-screen */}
        <button
          type="button"
          onClick={onManage}
          className="flex items-center rounded-birdo-sub px-3.5 py-3 transition-opacity hover:opacity-90"
          style={{ backgroundImage: planGradient(planLabel) }}
        >
          <CreditCard size={18} color="#FFFFFF" aria-hidden />
          <span className="ml-2.5 flex-1 text-left text-[14px] font-semibold text-white">
            {isActive ? 'Manage subscription' : 'Upgrade plan'}
          </span>
          <ChevronRight size={20} color="#FFFFFF" aria-hidden />
        </button>
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

// ── Delete-account dialog ──────────────────────────────────────────────────

function DeleteAccountDialog({ onDismiss }: { onDismiss: () => void }) {
  const [password, setPassword] = useState('');
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleConfirm = async () => {
    if (!password.trim() || deleting) return;
    setDeleting(true);
    setError(null);
    try {
      await invoke('delete_account', { request: { password } });
      // Account deleted — force reload to return to the login screen.
      window.location.reload();
    } catch (e: unknown) {
      setError(typeof e === 'string' ? e : 'Deletion failed');
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
            <AlertTriangle size={22} color={statusTokens.red} aria-hidden />
            <h2 className="text-[16px] font-bold" style={{ color: statusTokens.red }}>
              Delete account
            </h2>
          </div>
          <p className="text-[13px]" style={{ color: white.w60 }}>
            This will permanently delete your account, VPN configurations, and all
            associated data. This action cannot be undone. Enter your password to
            confirm.
          </p>
          <BirdoTextField
            value={password}
            onChange={(v) => {
              setPassword(v);
              if (error) setError(null);
            }}
            label="Password"
            type="password"
            error={error != null}
            disabled={deleting}
            autoComplete="current-password"
          />
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
              disabled={!password.trim()}
              onClick={handleConfirm}
            />
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}
