import { useState, useEffect } from 'react';
import { useAppStore } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';
import { ConsentScreen } from '@/components/ConsentScreen';
import { Login } from '@/components/Login';
import { AppShell } from '@/components/AppShell';
import { OfflineBanner } from '@/components/OfflineBanner';
import { PixelCanvas } from '@/components/PixelCanvas';
import { WindowControls } from '@/components/WindowControls';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { exit } from '@tauri-apps/plugin-process';
import { motion, AnimatePresence, MotionConfig } from 'framer-motion';

interface AuthState {
  is_authenticated: boolean;
  email: string | null;
  account_id: string | null;
  plan: string | null;
}

function App() {
  const {
    isAuthenticated,
    hasAcceptedConsent,
    setAuthenticated,
    setLoading,
    setUserEmail,
    setAccount,
    setConsent,
    theme,
    connectionState,
    currentServerName,
    windowCorner,
  } = useAppStore(
    useShallow((s) => ({
      isAuthenticated: s.isAuthenticated,
      hasAcceptedConsent: s.hasAcceptedConsent,
      setAuthenticated: s.setAuthenticated,
      setLoading: s.setLoading,
      setUserEmail: s.setUserEmail,
      setAccount: s.setAccount,
      setConsent: s.setConsent,
      theme: s.theme,
      connectionState: s.connectionState,
      currentServerName: s.currentServer?.name ?? null,
      windowCorner: s.windowCorner,
    }))
  );
  const [initializing, setInitializing] = useState(true);

  // Apply the saved window-position preference (corner anchor / draggable).
  // Runs on startup and whenever the user changes it in Settings. main.rs pins
  // top-left at launch as the pre-load default, so non-default corners reposition
  // once on first paint.
  useEffect(() => {
    invoke('set_window_position', { corner: windowCorner }).catch(() => {
      /* window not ready / non-fatal */
    });
  }, [windowCorner]);

  // Keep the system-tray icon + tooltip in sync with the live connection state.
  // The Rust `set_tray_state` command swaps the embedded status icon (green /
  // amber / slate) and the hover tooltip. Every in-progress phase maps to the
  // amber "connecting" icon.
  useEffect(() => {
    const trayState =
      connectionState === 'connected'
        ? 'connected'
        : connectionState === 'disconnected' || connectionState === 'error'
          ? 'disconnected'
          : 'connecting';
    const tooltip =
      trayState === 'connected'
        ? `Birdo VPN — Connected${currentServerName ? ` · ${currentServerName}` : ''}`
        : trayState === 'connecting'
          ? 'Birdo VPN — Connecting…'
          : 'Birdo VPN — Disconnected';
    invoke('set_tray_state', { state: trayState, tooltip }).catch(() => {
      /* tray not ready / non-fatal */
    });
  }, [connectionState, currentServerName]);

  // Apply theme class to <html> element
  useEffect(() => {
    const root = document.documentElement;
    root.classList.remove('light', 'dark');
    if (theme === 'system') {
      const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
      root.classList.add(prefersDark ? 'dark' : 'light');
    } else {
      root.classList.add(theme);
    }
  }, [theme]);

  useEffect(() => {
    // Check for stored authentication on startup
    const checkAuth = async () => {
      try {
        setLoading(true);
        const authState = await invoke<AuthState>('get_auth_state');
        setAuthenticated(authState.is_authenticated);

        if (authState.is_authenticated) {
          // Populate user email + account info from auth state
          if (authState.email) setUserEmail(authState.email);
          if (authState.plan || authState.account_id) {
            setAccount({
              email: authState.email,
              accountId: authState.account_id,
              plan: authState.plan,
              status: 'active',
            });
          }
        }
      } catch {
        // Auth check failed - assume not authenticated
        setAuthenticated(false);
      } finally {
        setLoading(false);
        setInitializing(false);
      }
    };

    checkAuth();
  }, [setAuthenticated, setLoading, setUserEmail, setAccount]);

  // Listen for birdo:// deep link events from the Rust backend
  useEffect(() => {
    const unlisten = listen<string>('deep-link', (event) => {
      const url = event.payload;
      try {
        const parsed = new URL(url);
        const action = parsed.hostname;
        const path = parsed.pathname.replace(/^\//, '');

        if (action === 'connect' && path) {
          // birdo://connect/<server-id>
          // Validate: allow only alphanumeric, dashes, underscores, max 64 chars
          if (!/^[a-zA-Z0-9_-]{1,64}$/.test(path)) return;
          // Ensure the Home tab is foregrounded so Dashboard handles the connect.
          useAppStore.getState().setTab('home');
          useAppStore.getState().setDeepLinkAction({ action: 'connect', serverId: path });
        } else if (action === 'settings') {
          // birdo://settings → route to the Settings tab (router refactor).
          useAppStore.getState().setTab('settings');
          useAppStore.getState().setDeepLinkAction({ action: 'settings' });
        }
      } catch {
        // Malformed deep-link URL — ignore silently
      }
    });
    return () => { unlisten.then((fn) => fn()).catch(() => {}); };
  }, []);

  if (initializing) {
    return (
      <div className="relative flex h-screen items-center justify-center overflow-hidden bg-[#000000]">
        <PixelCanvas />
        <WindowControls />

        <motion.div
          className="relative z-10 flex flex-col items-center gap-4"
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.5 }}
        >
          <div className="relative">
            <div className="h-16 w-16 animate-spin rounded-full border-2 border-white/10 border-t-white" />
          </div>
          <p className="text-sm text-white/60">Loading...</p>
        </motion.div>
      </div>
    );
  }

  // ── Consent handlers ──────────────────────────────────────────
  const handleAcceptConsent = () => {
    setConsent(true);
  };

  const handleDeclineConsent = async () => {
    try {
      await exit(0);
    } catch {
      window.close();
    }
  };

  return (
    <MotionConfig reducedMotion="user">
    <div className="relative h-screen overflow-hidden bg-birdo-black">
      <PixelCanvas />
      <WindowControls />

      {/* Global offline banner — shows on every screen (matches mobile's
          above-NavHost placement), not just the dashboard. */}
      <OfflineBanner />

      <AnimatePresence mode="wait">
        {!hasAcceptedConsent ? (
          <motion.div
            key="consent"
            className="relative z-10 h-full"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.3 }}
          >
            <ConsentScreen
              onAccept={handleAcceptConsent}
              onDecline={handleDeclineConsent}
            />
          </motion.div>
        ) : isAuthenticated ? (
          <motion.div
            key="appshell"
            className="relative z-10 h-full"
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.3 }}
          >
            <AppShell />
          </motion.div>
        ) : (
          <motion.div
            key="login"
            className="relative z-10 h-full"
            initial={{ opacity: 0, x: -20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
            transition={{ duration: 0.3 }}
          >
            <Login />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
    </MotionConfig>
  );
}

export default App;
