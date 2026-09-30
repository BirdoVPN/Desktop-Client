/**
 * AppShell — the authenticated phone-width frame.
 *
 * The canonical navigation (P1-parity §13): a four-tab bottom nav — Profile ·
 * Connect · Limit · Settings — hosting tab roots, with slide-in push
 * sub-screens layered on top (VPN Settings, Kill Switch Exceptions, Port
 * Forwarding, Plans & Pricing).
 *
 * Visually: the whole Tauri window is pure black (with PixelCanvas behind, owned
 * by App.tsx); this shell renders a centered ~420px column so the desktop app
 * reads like "a phone on a desk" — matching the portrait mobile layout.
 *
 * The shell owns navigation only. Connection state, tray actions and data
 * loading belong to the session controller App mounts above it, because tab
 * roots unmount on every switch.
 */
import { useEffect } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { useShallow } from 'zustand/react/shallow';
import { useAppStore, type RouteId } from '@/store/app-store';
import { useClientConfig } from '@/hooks/useClientConfig';
import { isModalOpen } from '@/lib/modal';
import { motion as motionTokens } from '@/lib/birdo-theme';
import { BottomNav } from '@/components/BottomNav';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { PixelCanvas } from '@/components/PixelCanvas';
import { Dashboard } from '@/components/Dashboard';
import { DeepLinkDialog } from '@/components/home/DeepLinkDialog';
import { Profile } from '@/screens/Profile';
import { Limit } from '@/screens/Limit';
import { Settings } from '@/components/Settings';
import { VpnSettings } from '@/screens/VpnSettings';
import { SplitTunnel } from '@/screens/SplitTunnel';
import { PortForward } from '@/screens/PortForward';
import { Pricing } from '@/screens/Pricing';

const PUSH_SCREENS: Record<RouteId, React.ComponentType> = {
  vpnSettings: VpnSettings,
  splitTunnel: SplitTunnel,
  portForward: PortForward,
  pricing: Pricing,
};

export function AppShell() {
  const { tab, navStack, popRoute } = useAppStore(
    useShallow((s) => ({ tab: s.tab, navStack: s.navStack, popRoute: s.popRoute })),
  );

  // ── BirdoShield fleet gate ────────────────────────────────────────
  // `GET /api/client-config` → `dnsFilteringAvailable`, fetched HERE and not
  // on a tab root, because the shell is mounted for every authenticated
  // session whichever tab or pushed sub-screen is showing (a cold
  // `birdo://settings` launch lands on Settings with Connect never mounted).
  // Pinned by `src/__tests__/AppShellClientConfig.test.tsx`; the staleness
  // bound and the "unknown means AVAILABLE" rule live in the hook.
  useClientConfig();

  const topRoute = navStack[navStack.length - 1];
  // Bottom nav is hidden whenever a sub-screen is pushed (matches mobile).
  const showNav = navStack.length === 0;

  // Escape goes back (W2-033) — unless a dialog or sheet is open, which
  // handles Escape itself and must not also pop the screen under it.
  useEffect(() => {
    if (!topRoute) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !e.defaultPrevented && !isModalOpen()) popRoute();
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [topRoute, popRoute]);

  const TabRoot = tab === 'profile' ? Profile : tab === 'limit' ? Limit : tab === 'settings' ? Settings : Dashboard;

  return (
    <div className="relative z-10 mx-auto flex h-full w-full min-w-phone-min max-w-phone flex-col overflow-hidden">
      {/* Tab root. Inert while a sub-screen covers it: it stays mounted, and
          keyboard users used to tab into the invisible screen behind (W2-017). */}
      <div className="relative flex-1 overflow-hidden">
        <div className="h-full" inert={topRoute ? true : undefined}>
          {/* A crash in one tab keeps the title bar, the bottom nav and the
              other tabs working (W2-044). Keyed so switching tabs resets it. */}
          <ErrorBoundary key={tab}>
            <TabRoot />
          </ErrorBoundary>
        </div>

        {/* Pushed sub-screens slide in from the right over the active tab */}
        <AnimatePresence>
          {topRoute && (
            <motion.div
              key={topRoute}
              // Fully OPAQUE base so the pushed sub-screen completely occludes
              // the tab behind it. Its own PixelCanvas paints the same ambient
              // grid (App parks the full-window one meanwhile).
              className="absolute inset-0 z-20 overflow-hidden bg-birdo-black"
              initial={{ x: '100%' }}
              animate={{ x: 0 }}
              exit={{ x: '100%' }}
              transition={{ duration: motionTokens.standard, ease: motionTokens.ease }}
            >
              <PixelCanvas className="absolute inset-0 h-full w-full" />
              <div className="relative z-10 h-full">
                {(() => {
                  const Screen = PUSH_SCREENS[topRoute];
                  // Guard against PUSH_SCREENS drifting out of sync with RouteId
                  // (a route pushed with no mapped component would render
                  // <undefined /> and crash the shell).
                  if (!Screen) return null;
                  return (
                    <ErrorBoundary>
                      <Screen />
                    </ErrorBoundary>
                  );
                })()}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        <DeepLinkDialog />
      </div>

      {showNav && <BottomNav />}
    </div>
  );
}
