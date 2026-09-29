import { useState } from 'react';
import { motion } from 'framer-motion';
import { open as openExternal } from '@tauri-apps/plugin-shell';
import { Shield, Eye, BarChart3, ShieldOff } from 'lucide-react';
import { AppIconMark, BirdoButton, BirdoCard, BirdoToggleRow } from './birdo';
import { brand } from '@/lib/birdo-theme';

export const TERMS_URL = 'https://birdo.app/terms';
export const PRIVACY_URL = 'https://birdo.app/privacy';

/**
 * The pre-use disclosure text. Owned by the audit remediation of 29 Sep 2026
 * (REMEDIATION-DECISIONS.md §1.5, shared with Android and iOS): it must say no
 * more than the privacy model actually supports.
 *
 * The previous text claimed "RAM-only volatile infrastructure" (the nodes are
 * ordinary cloud servers with disks), that no connection timestamps or IP
 * addresses were logged (a live session record exists while you are
 * connected), and that crash reports carried "no personal data" while they
 * were sent unconditionally. Do not reintroduce any of those.
 */
export const CONSENT_COPY = {
  noActivityLogs:
    "Our VPN servers don't record the sites you visit, your DNS queries or your traffic. " +
    "While you're connected, our account system keeps a live record of your session " +
    '(server, device, connect time). It is deleted when you disconnect and is never ' +
    'included in backups. We also count your data use per billing period.',
  accountHolds:
    'Your email (or anonymous account number), plan, the devices you add, and your ' +
    'usage totals. Full list: birdo.app/privacy.',
  crashReports:
    'Off by default. If you turn this on, the app sends crash details (stack trace, app ' +
    'and OS version, device model) to Sentry so we can fix bugs. No account details or ' +
    'browsing data. Change it any time in Settings.',
  noAds: "No advertising or analytics SDKs. We don't sell your data or share it with advertisers.",
} as const;

interface ConsentScreenProps {
  /** Called with the user's crash-report choice (default OFF). */
  onAccept: (crashReportsEnabled: boolean) => void;
  onDecline: () => void;
}

/**
 * Consent screen shown on first launch, before sign-in or any connection.
 *
 * "I Agree & Continue" accepts BOTH the Terms of Service and the Privacy
 * Policy and confirms the user is 18 or over (the Terms' age). Every desktop
 * sign-up path (email, anonymous, SSO) sits behind this screen, so this is
 * where the Terms are accepted on desktop (audit B-13).
 *
 * Crash reporting is a separate, optional choice made here with a toggle that
 * starts OFF; nothing is sent to Sentry unless it is switched on (C-3).
 */
export function ConsentScreen({ onAccept, onDecline }: ConsentScreenProps) {
  const [crashReports, setCrashReports] = useState(false);

  return (
    <div className="flex h-full flex-col">
      {/* Brand now lives in the window TitleBar. */}
      <div className="flex-1 overflow-y-auto px-6 pb-6 pt-3">
        <motion.div
          className="flex flex-col items-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          {/* Brand mark */}
          <motion.div
            className="mt-8 mb-4"
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <AppIconMark mark size={76} />
          </motion.div>

          {/* Title */}
          <motion.h1
            className="mb-2 text-center text-2xl font-bold text-w100"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.15 }}
          >
            Your Privacy Matters
          </motion.h1>

          <motion.p
            className="mb-6 text-center text-sm leading-relaxed text-w60"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            Before using BirdoVPN, please review how your data is handled.
          </motion.p>

          {/* Data processing summary card */}
          <motion.div
            className="mb-5 w-full"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.25 }}
          >
            <BirdoCard padding="1.25rem" cornerRadius={20}>
              <div className="space-y-5">
                <DataItem
                  icon={Eye}
                  title="No Activity Logs"
                  description={CONSENT_COPY.noActivityLogs}
                />
                <DataItem
                  icon={Shield}
                  title="What Your Account Holds"
                  description={CONSENT_COPY.accountHolds}
                />
                <DataItem
                  icon={BarChart3}
                  title="Crash Reports (optional)"
                  description={CONSENT_COPY.crashReports}
                />
                <DataItem
                  icon={ShieldOff}
                  title="No Ads or Analytics"
                  description={CONSENT_COPY.noAds}
                />
              </div>
            </BirdoCard>
          </motion.div>

          {/* The crash-report choice: a real control, starting OFF. */}
          <motion.div
            className="mb-5 w-full"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.28 }}
          >
            <BirdoCard padding="0.25rem" cornerRadius={20}>
              <BirdoToggleRow
                title="Send crash reports"
                subtitle="Optional. Off unless you turn it on."
                leadingIcon={BarChart3}
                checked={crashReports}
                onCheckedChange={setCrashReports}
              />
            </BirdoCard>
          </motion.div>

          {/* Terms + Privacy links. Opened in the SYSTEM browser via the scoped
              shell plugin (like every other external link): a raw
              <a target="_blank"> is outside the shell allowlist, and a webview
              that follows it in-place strands this frameless window on a
              remote page with no way back. */}
          <motion.div
            className="mb-4 flex items-center justify-center gap-4"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.3 }}
          >
            <button
              type="button"
              onClick={() => openExternal(TERMS_URL).catch(() => {})}
              aria-label="Read the Terms of Service (opens in your browser)"
              className="text-sm underline underline-offset-2 transition hover:opacity-80"
              style={{ color: brand.accentSoft }}
            >
              Terms of Service
            </button>
            <button
              type="button"
              onClick={() => openExternal(PRIVACY_URL).catch(() => {})}
              aria-label="Read the Privacy Policy (opens in your browser)"
              className="text-sm underline underline-offset-2 transition hover:opacity-80"
              style={{ color: brand.accentSoft }}
            >
              Privacy Policy
            </button>
          </motion.div>

          <motion.p
            className="mb-5 text-center text-xs leading-relaxed text-w60"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.32 }}
          >
            You must be 18 or over to use BirdoVPN. By selecting &ldquo;I Agree &amp;
            Continue&rdquo; you accept the Terms of Service and the Privacy Policy.
          </motion.p>

          {/* Accept button */}
          <motion.div
            className="w-full"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.35 }}
          >
            <BirdoButton
              text="I Agree & Continue"
              variant="brand"
              size="large"
              fullWidth
              onClick={() => onAccept(crashReports)}
            />
          </motion.div>

          {/* Decline button */}
          <motion.div
            className="mt-3 w-full"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.4 }}
          >
            <BirdoButton
              text="Decline"
              variant="secondary"
              size="medium"
              fullWidth
              onClick={onDecline}
            />
          </motion.div>

          {/* Required notice */}
          <motion.p
            className="mt-4 text-center text-xs text-w40"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.45 }}
          >
            You must accept the Terms of Service and the Privacy Policy to use BirdoVPN.
          </motion.p>
        </motion.div>
      </div>
    </div>
  );
}

function DataItem({
  icon: Icon,
  title,
  description,
}: {
  icon: React.ElementType;
  title: string;
  description: string;
}) {
  return (
    <div className="flex gap-3">
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-birdo-sm bg-white/10">
        <Icon size={18} className="text-w60" />
      </div>
      <div>
        <p className="text-sm font-medium text-w100">{title}</p>
        <p className="mt-0.5 text-xs leading-relaxed text-w60">{description}</p>
      </div>
    </div>
  );
}
