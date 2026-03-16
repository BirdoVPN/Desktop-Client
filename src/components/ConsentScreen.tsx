import { motion } from 'framer-motion';
import { Shield, Eye, BarChart3, ShieldOff } from 'lucide-react';

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
      {/* Header drag region */}
      <div
        data-tauri-drag-region
        className="flex h-8 shrink-0 items-center justify-center"
      >
        <span className="text-[10px] font-semibold tracking-widest text-white/30 uppercase">
          Birdo VPN
        </span>
      </div>

      <div className="flex-1 overflow-y-auto px-6 pb-6">
        <motion.div
          className="flex flex-col items-center"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          {/* Shield icon */}
          <motion.div
            className="mt-8 mb-4 flex h-16 w-16 items-center justify-center rounded-2xl bg-white/5 border border-white/10"
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <Shield size={32} className="text-white" />
          </motion.div>

          {/* Title */}
          <motion.h1
            className="mb-2 text-2xl font-bold text-white text-center"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.15 }}
          >
            Your Privacy Matters
          </motion.h1>

          <motion.p
            className="mb-6 text-sm text-white/50 text-center leading-relaxed"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            Before you get started, here's how we handle your data.
          </motion.p>

          {/* Data processing summary card */}
          <motion.div
            className="w-full rounded-2xl glass-card p-5 space-y-5 mb-5"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.25 }}
          >
            <DataItem
              icon={Eye}
              title="No Activity Logs"
              description="We never log your browsing activity or DNS queries. Minimal connection metadata is retained for up to 90 days for security monitoring."
            />
            <DataItem
              icon={Shield}
              title="Minimal Account Data"
              description="Only your email and subscription status are stored — nothing more."
            />
            <DataItem
              icon={BarChart3}
              title="Anonymous Crash Reports"
              description="Crash reports help us fix bugs. They contain no personal information."
            />
            <DataItem
              icon={ShieldOff}
              title="No Data Sales"
              description="Your data is never sold, shared with advertisers, or monetized in any way."
            />
          </motion.div>

          {/* Privacy policy link */}
          <motion.a
            href="https://birdo.app/privacy"
            target="_blank"
            rel="noopener noreferrer"
            className="mb-6 text-sm text-white/60 underline underline-offset-2 hover:text-white/80 transition"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.3 }}
          >
            Read our full Privacy Policy
          </motion.a>

          {/* Accept button */}
          <motion.button
            onClick={onAccept}
            className="btn-primary w-full rounded-xl px-4 py-3.5 font-semibold text-sm"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.35 }}
            whileHover={{ scale: 1.02 }}
            whileTap={{ scale: 0.98 }}
          >
            I Agree &amp; Continue
          </motion.button>

          {/* Decline button */}
          <motion.button
            onClick={onDecline}
            className="mt-3 w-full rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-white/40 hover:bg-white/10 hover:text-white/60 transition"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.4 }}
          >
            Decline
          </motion.button>

          {/* Required notice */}
          <motion.p
            className="mt-4 text-xs text-white/20 text-center"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.45 }}
          >
            Consent is required to use Birdo VPN. Declining will close the app.
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
      <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-white/10">
        <Icon size={18} className="text-white/70" />
      </div>
      <div>
        <p className="text-sm font-medium text-white">{title}</p>
        <p className="mt-0.5 text-xs text-white/50 leading-relaxed">
          {description}
        </p>
      </div>
    </div>
  );
}
