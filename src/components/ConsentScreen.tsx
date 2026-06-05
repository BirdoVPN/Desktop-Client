import { motion } from 'framer-motion';
import { Shield, Eye, BarChart3, ShieldOff } from 'lucide-react';
import { AppIconMark, BirdoButton, BirdoCard } from './birdo';
import { brand } from '@/lib/birdo-theme';

interface ConsentScreenProps {
  onAccept: () => void;
  onDecline: () => void;
}

/**
 * GDPR-compliant consent screen shown on first launch.
 * User must accept the privacy policy before proceeding.
 * Mirrors the Android ConsentScreen.kt implementation.
 */
export function ConsentScreen({ onAccept, onDecline }: ConsentScreenProps) {
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
            <AppIconMark size={64} style={{ borderRadius: 20 }} />
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
            Before using Birdo VPN, please review how your data is handled.
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
                  description="Birdo VPN operates a strict zero-logs policy on RAM-only volatile infrastructure. No browsing activity, DNS queries, traffic content, connection timestamps, or IP addresses are logged."
                />
                <DataItem
                  icon={Shield}
                  title="Account Data Only"
                  description="Only your email, subscription status, and aggregate bandwidth are stored in a separate account database — never on VPN servers."
                />
                <DataItem
                  icon={BarChart3}
                  title="Crash Reports"
                  description="Anonymous crash reports help fix bugs faster. No personal data is included."
                />
                <DataItem
                  icon={ShieldOff}
                  title="No Data Sales"
                  description="Your data is never sold, shared with advertisers, or used for profiling."
                />
              </div>
            </BirdoCard>
          </motion.div>

          {/* Privacy policy link */}
          <motion.a
            href="https://birdo.app/privacy"
            target="_blank"
            rel="noopener noreferrer"
            className="mb-6 text-sm underline underline-offset-2 transition hover:opacity-80"
            style={{ color: brand.purpleSoft }}
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.3 }}
          >
            Read the full Privacy Policy
          </motion.a>

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
              onClick={onAccept}
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
            You must accept the privacy policy to use Birdo VPN.
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
