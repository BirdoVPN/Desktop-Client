import { useEffect } from 'react';
import { useAppStore } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';
import { WifiOff } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { motion as motionTokens } from '@/lib/birdo-theme';

/**
 * "No internet connection", shown above every screen while the OS reports no
 * network (`navigator.onLine`; the OS fires online/offline on interface
 * changes).
 *
 * Hidden while a tunnel is up or coming up (P1-parity-029, the iOS/Android
 * rule): the tunnel's own adapter changes what the webview reports, and a red
 * "No internet connection" over "Protected" contradicts a working connection.
 * The connection states say what is happening then.
 */
export function OfflineBanner() {
  const { isOnline, setOnline, tunnelUp } = useAppStore(
    useShallow((s) => ({
      isOnline: s.isOnline,
      setOnline: s.setOnline,
      tunnelUp:
        s.connectionState === 'connected' ||
        s.connectionState === 'connecting' ||
        s.connectionState === 'reconnecting' ||
        s.connectionState === 'switching' ||
        s.pendingAction === 'connecting' ||
        s.pendingAction === 'switching',
    })),
  );

  useEffect(() => {
    setOnline(navigator.onLine);
    const handleOnline = () => setOnline(true);
    const handleOffline = () => setOnline(false);
    window.addEventListener('online', handleOnline);
    window.addEventListener('offline', handleOffline);
    return () => {
      window.removeEventListener('online', handleOnline);
      window.removeEventListener('offline', handleOffline);
    };
  }, [setOnline]);

  return (
    <div role="status" aria-live="polite" className="shrink-0">
      <AnimatePresence>
        {!isOnline && !tunnelUp && (
          <motion.div
            className="flex items-center justify-center gap-2 px-3 py-1.5 text-xs font-semibold"
            // The theme red (status.red) at 0.95 — it was Tailwind's red-500,
            // a different red from every other alert in the app. Dark text:
            // white on this light red would fail contrast.
            style={{ backgroundColor: 'rgba(248,113,113,0.95)', color: '#1A0505' }}
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            transition={{ duration: motionTokens.fast }}
          >
            <WifiOff size={14} aria-hidden />
            <span>No internet connection</span>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
