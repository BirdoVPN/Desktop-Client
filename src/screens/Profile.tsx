/**
 * Profile — top-level tab root.
 *
 * Identity card (with the connection status row), the anonymous account
 * number, the subscription summary, and the account actions kept IN-APP:
 * redeem voucher, export data, delete account and sign out. Managing a paid
 * subscription and the legal links live on the web (dashboard.birdo.app).
 * Usage moved to the Limit tab (P1-parity-009).
 */
import { useCallback, useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-shell';
import { useShallow } from 'zustand/react/shallow';
import { Gift, LogOut, Trash2, Download, CreditCard } from 'lucide-react';
import { useAppStore } from '@/store/app-store';
import { BirdoCard, BirdoSectionHeader, BirdoNavRow } from '@/components/birdo';
import { brand, status as statusTokens } from '@/lib/birdo-theme';
import { planRank } from '@/lib/plan';
import { anonAccountNumber } from '@/utils/helpers';
import { loadSubscription } from '@/session/session-data';
import { signOut } from '@/session/session';
import { AccountNumberCard, IdentityCard, SubscriptionCard } from './profile/ProfileCards';
import { DeleteAccountDialog } from './profile/DeleteAccountDialog';
import { VoucherRedeemDialog } from './profile/VoucherRedeemDialog';

export {
  PREFLIGHT_WEB_CANCELLED,
  STORE_BILLING_WARNING,
  preflightStoreWarning,
  type DeleteAccountResult,
  type DeletionPreflight,
} from './profile/DeleteAccountDialog';

export function Profile() {
  const { account, planStatus, userEmail, logout, pushRoute } = useAppStore(
    useShallow((s) => ({
      account: s.account,
      planStatus: s.planStatus,
      userEmail: s.userEmail,
      logout: s.logout,
      pushRoute: s.pushRoute,
    })),
  );
  // Unknown (null) is not free: offer "View plans" only when the plan is KNOWN
  // to be the free one, "Manage Subscription" when known to be paid.
  const rank = planRank(account.plan);
  const isFreeTier = rank === 0;
  // The email is mirrored in both `account.email` and `userEmail` (set at
  // sign-in); fall back so the card never reads "Anonymous" for a real user.
  const resolvedEmail = account.email ?? userEmail ?? null;
  // Never render the synthetic `anon_…@anonymous.local`; show the number.
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

  return (
    // Transparent so the App-level PixelCanvas backdrop shows through.
    <div className="h-full overflow-y-auto">
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
          planStatus={planStatus}
          accountStatus={account.status}
          expiresAt={account.expiresAt}
          maxDevices={account.maxDevices}
          bandwidthLimit={account.bandwidthLimit}
          onRetry={() => void loadSubscription(true)}
        />

        {/* ── ACCOUNT ─────────────────────────────────────────────────── */}
        <div className="mt-1">
          <BirdoSectionHeader title="Account" />
          <BirdoCard padding="0.25rem">
            <BirdoNavRow
              title={rank === null || isFreeTier ? 'View plans' : 'Manage Subscription'}
              leadingIcon={CreditCard}
              leadingTint={brand.accent}
              onClick={
                rank === null || isFreeTier
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
              title="Delete Account"
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
              onClick={() => void signOut()}
            />
          </BirdoCard>
        </div>
      </div>

      <VoucherRedeemDialog
        open={showVoucherDialog}
        onDismiss={() => setShowVoucherDialog(false)}
        onRedeemed={() => void loadSubscription(true)}
      />
      {showDeleteDialog && (
        <DeleteAccountDialog
          open
          // Authoritative from /auth/me, and deliberately NOT combined with
          // `isAnon`: an anonymous user who set a password on the website
          // still has one, and the backend will demand it.
          hasPassword={account.hasPassword}
          onDismiss={() => setShowDeleteDialog(false)}
          onDeleted={async () => {
            try {
              await invoke('logout');
            } catch {
              /* best effort — the account is already gone server-side */
            }
            logout();
          }}
        />
      )}
    </div>
  );
}
