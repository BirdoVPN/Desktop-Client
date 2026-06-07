/**
 * AppShell — the authenticated phone-width frame.
 *
 * Mirrors mobile's BirdoNavGraph.kt: a 3-tab bottom nav (Profile / Connect /
 * Settings) hosting tab roots, with slide-in push sub-screens layered on top
 * (VpnSettings, SplitTunnel, PortForward, Subscription, ServerList).
 *
 * Visually: the whole Tauri window is pure black (with PixelCanvas behind, owned
 * by App.tsx); this shell renders a centered ~420px column so the desktop app
 * reads like "a phone on a desk" — matching the portrait mobile layout.
 *
 * The Home tab keeps the full-bleed globe + 2s status poll exactly as before;
 * this shell only changes navigation, not the connection logic.
 */
import { AnimatePresence, motion } from 'framer-motion';
import { useShallow } from 'zustand/react/shallow';
import { useAppStore, type RouteId } from '@/store/app-store';
import { motion as motionTokens } from '@/lib/birdo-theme';
import { BottomNav } from '@/components/BottomNav';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { PixelCanvas } from '@/components/PixelCanvas';
import { Dashboard } from '@/components/Dashboard';
import { Profile } from '@/screens/Profile';
import { Settings } from '@/components/Settings';
import { ServerListScreen } from '@/screens/ServerList';
import { VpnSettings } from '@/screens/VpnSettings';
import { SplitTunnel } from '@/screens/SplitTunnel';
import { PortForward } from '@/screens/PortForward';
import { Subscription } from '@/screens/Subscription';

const PUSH_SCREENS: Record<RouteId, React.ComponentType> = {
  serverList: ServerListScreen,
  vpnSettings: VpnSettings,
  splitTunnel: SplitTunnel,
  portForward: PortForward,
  subscription: Subscription,
};

export function AppShell() {
  const { tab, navStack } = useAppStore(
    useShallow((s) => ({ tab: s.tab, navStack: s.navStack }))
  );

  const topRoute = navStack[navStack.length - 1];
  // Bottom nav is hidden whenever a sub-screen is pushed (matches mobile).
  const showNav = navStack.length === 0;

  return (
    <div className="relative z-10 mx-auto flex h-full w-full min-w-phone max-w-phone flex-col overflow-hidden">
      {/* Tab root */}
      <div className="relative flex-1 overflow-hidden">
        {tab === 'home' && <Dashboard />}
        {tab === 'profile' && <Profile />}
        {tab === 'settings' && <Settings />}

        {/* Pushed sub-screens slide in from the right over the active tab */}
        <AnimatePresence>
          {topRoute && (
            <motion.div
              key={topRoute}
              // Solid black base occludes the tab rendered behind it, then its
              // own PixelCanvas paints the same ambient grid as the rest of the
              // app so pushed sub-screens (VPN settings, split tunnel, etc.)
              // aren't missing the backdrop. Screen roots are transparent so the
              // grid shows through.
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
      </div>

      {showNav && <BottomNav />}
    </div>
  );
}
