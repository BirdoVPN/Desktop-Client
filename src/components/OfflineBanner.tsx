import { useEffect } from 'react';
import { useAppStore } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';
import { WifiOff } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

/**
 * Monitors network connectivity and shows a banner when offline.
 * Mirrors Android's NetworkMonitor.kt + BirdoNavGraph offline banner.
 *
 * Uses the browser's `navigator.onLine` as a lightweight heuristic.
 * This is sufficient for desktop since the OS triggers online/offline
 * events when the network interface changes.
 */
export function OfflineBanner() {
  const { isOnline, setOnline } = useAppStore(
    useShallow((s) => ({
      isOnline: s.isOnline,
      setOnline: s.setOnline,
    }))
  );

  useEffect(() => {
    // Set initial state
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
    <AnimatePresence>
      {!isOnline && (
        <motion.div
          className="flex items-center justify-center gap-2 bg-red-500/90 px-3 py-1.5 text-xs font-medium text-white"
          initial={{ opacity: 0, height: 0 }}
          animate={{ opacity: 1, height: 'auto' }}
          exit={{ opacity: 0, height: 0 }}
          transition={{ duration: 0.2 }}
        >
          <WifiOff size={14} />
          <span>No internet connection</span>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
