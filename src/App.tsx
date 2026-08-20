import { useState, useEffect, useRef, useCallback } from 'react';
import { useAppStore, type AccountInfo } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';
import { ConsentScreen } from '@/components/ConsentScreen';
import { Login } from '@/components/Login';
import { AppShell } from '@/components/AppShell';
import { OfflineBanner } from '@/components/OfflineBanner';
import { PixelCanvas } from '@/components/PixelCanvas';
import { TitleBar } from '@/components/TitleBar';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { exit } from '@tauri-apps/plugin-process';
import { notifyUpdateAvailable } from '@/utils/notifications';
import { motion, AnimatePresence, MotionConfig } from 'framer-motion';

interface AuthState {
  is_authenticated: boolean;
  email: string | null;
  account_id: string | null;
  plan: string | null;
  /** Optional: absent when talking to a backend that predates the field. */
  has_password?: boolean;
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
      connectionState: s.connectionState,
      currentServerName: s.currentServer?.name ?? null,
      windowCorner: s.windowCorner,
    }))
  );
  const [initializing, setInitializing] = useState(true);

  // Biometric app-lock. When "Biometric Unlock" is enabled in Settings the
  // entire UI must stay behind an unlock screen until Windows Hello / Touch ID
  // succeeds — previously the flag was persisted but never enforced, so the
  // advertised lock was a no-op (same class of bug as the Android fix in
  // Mobile #146). 'checking' avoids a flash of unlocked content at boot.
  const [bioLock, setBioLock] = useState<'checking' | 'locked' | 'open'>('checking');

  const requestBiometricUnlock = async () => {
    try {
      const ok = await invoke<boolean>('authenticate_biometric', {
        reason: 'Unlock Birdo VPN',
      });
      if (ok) setBioLock('open');
    } catch {
      // Prompt failed/cancelled — remain locked; the user can retry or quit.
    }
  };

  useEffect(() => {
    invoke<{ available: boolean; enabled: boolean }>('check_biometric_available')
      .then((st) => {
        if (st?.available && st?.enabled) {
          setBioLock('locked');
          // Prompt immediately at launch; the lock screen offers a retry.
          requestBiometricUnlock();
        } else {
          setBioLock('open');
        }
      })
      .catch(() => setBioLock('open'));
  }, []);

  // Re-arm the biometric lock when the app is hidden to the tray and re-prompt
  // when it returns. Without this the opt-in lock only guarded the cold start —
  // close-to-tray then reopen left the authenticated UI one tray-click away for
  // anyone at the machine. Mirrors mobile's onStop re-arm + onResume re-prompt.
  // (Keyed off hide-to-tray, not plain blur, so alt-tabbing never re-locks.)
  const bioLockRef = useRef(bioLock);
  bioLockRef.current = bioLock;
  useEffect(() => {
    const unlistenHidden = listen('app-hidden', async () => {
      try {
        const st = await invoke<{ available: boolean; enabled: boolean }>(
          'check_biometric_available'
        );
        if (st?.available && st?.enabled) setBioLock('locked');
      } catch {
        /* non-fatal — leave current lock state */
      }
    });
    const unlistenShown = listen('app-shown', () => {
      if (bioLockRef.current === 'locked') requestBiometricUnlock();
    });
    return () => {
      unlistenHidden.then((fn) => fn()).catch(() => {});
      unlistenShown.then((fn) => fn()).catch(() => {});
    };
  }, []);

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
  // amber "connecting" icon — EXCEPT kill_switch_active, which used to fall
  // into that catch-all: the tray (often the only visible surface, the window
  // being hidden) said "Connecting…" while every packet on the machine was
  // being dropped. It now gets the slate icon and an explicit tooltip.
  useEffect(() => {
    const trayState =
      connectionState === 'connected'
        ? 'connected'
        : connectionState === 'disconnected'
            || connectionState === 'error'
            || connectionState === 'kill_switch_active'
          ? 'disconnected'
          : 'connecting';
    const tooltip =
      connectionState === 'kill_switch_active'
        ? 'Birdo VPN — Kill switch active: traffic blocked'
        : trayState === 'connected'
          ? `Birdo VPN — Connected${currentServerName ? ` · ${currentServerName}` : ''}`
          : trayState === 'connecting'
            ? 'Birdo VPN — Connecting…'
            : 'Birdo VPN — Disconnected';
    invoke('set_tray_state', { state: trayState, tooltip }).catch(() => {
      /* tray not ready / non-fatal */
    });
  }, [connectionState, currentServerName]);

  useEffect(() => {
    // Check for stored authentication on startup
    const checkAuth = async () => {
      try {
        setLoading(true);
        const authState = await invoke<AuthState>('get_auth_state');
        setAuthenticated(authState.is_authenticated);

        if (authState.is_authenticated) {
          // Populate user email + account info from auth state. Always set the
          // account when authenticated — gating on plan/account_id meant a
          // stored session that returns only an email left `account` null, so
          // the Profile screen rendered "Anonymous" for a real email login.
          if (authState.email) setUserEmail(authState.email);
          // Merge only the fields we actually received. `setAccount` MERGES, so
          // passing explicit nulls would wipe a good identity whenever the
          // profile fetch failed transiently (get_auth_state deliberately keeps
          // the session alive with an unknown identity in that case rather than
          // signing the user out). Absent means "unchanged", not "cleared".
          const patch: Partial<AccountInfo> = {
            status: 'active',
            // Always set, and `?? true` keeps the password prompt when the
            // backend predates the field — never drop a confirmation because a
            // value went missing. Unlike the identity fields, a stale `false`
            // here would REMOVE a safety prompt, so absent must mean "ask".
            hasPassword: authState.has_password ?? true,
          };
          if (authState.email) patch.email = authState.email;
          if (authState.account_id) patch.accountId = authState.account_id;
          if (authState.plan) patch.plan = authState.plan;
          setAccount(patch);
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

  // Retry identity hydration when we are signed in but the email never arrived.
  //
  // `get_auth_state` deliberately keeps a valid session alive when the profile
  // fetch fails (a rate-limit or a network blip) and reports the identity as
  // unknown rather than signing the user out. Nothing re-fetched it though, so a
  // single transient failure left the Profile stuck on "Loading your account…"
  // until the app was restarted — a momentary error turned permanent.
  //
  // Backs off (4s, 8s, 16s) so a retry cannot itself become the thing keeping
  // the rate-limit window saturated, and stops after 3 attempts.
  //
  // The attempt counter is STATE (not a ref) on purpose: bumping it after a
  // failed attempt re-runs this effect, which is what schedules the next try.
  // The previous ref-based version never re-ran on failure — the documented
  // 3-attempt ladder was actually a single attempt, and a profile fetch still
  // failing 4 s after sign-in left the Profile stuck on "Loading your
  // account…" until an app restart.
  const [identityAttempt, setIdentityAttempt] = useState(0);
  const accountEmail = useAppStore((s) => s.account.email);
  useEffect(() => {
    if (!isAuthenticated || accountEmail || identityAttempt >= 3) return;
    const delayMs = 4000 * 2 ** identityAttempt;
    const timer = setTimeout(async () => {
      try {
        const st = await invoke<AuthState>('get_auth_state');
        if (st?.email) {
          setUserEmail(st.email);
          const patch: Partial<AccountInfo> = { email: st.email };
          if (st.account_id) patch.accountId = st.account_id;
          if (st.plan) patch.plan = st.plan;
          setAccount(patch);
        }
      } catch {
        /* non-fatal — the backoff above bounds how often this runs */
      } finally {
        // On success `accountEmail` gates the effect off; on failure this
        // re-triggers it to schedule the next backed-off attempt.
        setIdentityAttempt((a) => a + 1);
      }
    }, delayMs);
    return () => clearTimeout(timer);
  }, [isAuthenticated, accountEmail, identityAttempt, setUserEmail, setAccount]);

  // Daily background update check. The per-platform update endpoint is live
  // (api.birdo.app/updates/…), but the only in-app check used to be the manual
  // button in Settings → Software Updates — users who never opened it would
  // never learn about security fixes. Checks shortly after startup and then
  // every 24h; notifies at most once per app run.
  //
  // Goes through the Rust `check_for_updates` command, which runs the updater
  // over the cert-pinned client (commands/updater.rs). The un-pinned
  // @tauri-apps/plugin-updater JS path is no longer reachable from the webview.
  useEffect(() => {
    let notified = false;
    const runCheck = async () => {
      if (notified) return;
      try {
        const update = await Promise.race([
          invoke<{ version: string } | null>('check_for_updates'),
          new Promise<null>((resolve) => setTimeout(() => resolve(null), 15000)),
        ]);
        if (update) {
          notified = true;
          notifyUpdateAvailable(update.version);
        }
      } catch {
        // Offline / endpoint hiccup — silent; the next interval retries.
      }
    };
    const initial = setTimeout(runCheck, 20_000); // let startup settle first
    const daily = setInterval(runCheck, 24 * 60 * 60 * 1000);
    return () => {
      clearTimeout(initial);
      clearInterval(daily);
    };
  }, []);

  // Parse and route a birdo:// deep link. Shared by the runtime event listener
  // and the cold-start path (a URL the app was launched with).
  const handleDeepLinkUrl = useCallback((url: string) => {
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
  }, []);

  // Listen for birdo:// deep link events from the Rust backend, and pull any
  // link the app was cold-launched with (Windows delivers that via launch argv,
  // which the runtime listener never sees).
  useEffect(() => {
    const unlisten = listen<string>('deep-link', (event) => handleDeepLinkUrl(event.payload));
    invoke<string | null>('take_pending_deep_link')
      .then((url) => {
        if (url) handleDeepLinkUrl(url);
      })
      .catch(() => {});
    return () => { unlisten.then((fn) => fn()).catch(() => {}); };
  }, [handleDeepLinkUrl]);

  if (initializing || bioLock === 'checking') {
    return (
      <div className="relative flex h-screen flex-col overflow-hidden bg-[#000000]">
        <PixelCanvas />
        <TitleBar />

        <div className="relative z-10 flex flex-1 flex-col items-center justify-center">
          <motion.div
            className="flex flex-col items-center gap-4"
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
      </div>
    );
  }

  // Biometric lock screen — nothing behind it renders until unlock succeeds.
  if (bioLock === 'locked') {
    return (
      <div className="relative flex h-screen flex-col overflow-hidden bg-[#000000]">
        <PixelCanvas />
        <TitleBar />

        <div className="relative z-10 flex flex-1 flex-col items-center justify-center gap-6 px-8">
          <motion.div
            className="flex flex-col items-center gap-3 text-center"
            initial={{ opacity: 0, scale: 0.95 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.3 }}
          >
            <h1 className="text-lg font-semibold text-white">Birdo VPN is locked</h1>
            <p className="max-w-xs text-sm text-white/60">
              Biometric Unlock is enabled for this app. Authenticate to continue.
            </p>
          </motion.div>
          <div className="flex flex-col items-center gap-3">
            <button
              type="button"
              onClick={requestBiometricUnlock}
              className="rounded-lg bg-white px-6 py-2.5 text-sm font-semibold text-black transition hover:bg-white/90"
            >
              Unlock
            </button>
            <button
              type="button"
              onClick={() => exit(0).catch(() => window.close())}
              className="text-xs text-white/50 transition hover:text-white/80"
            >
              Quit
            </button>
          </div>
        </div>
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
    } catch (err) {
      console.error('Failed to exit after consent decline; falling back to window.close()', err);
      try {
        window.close();
      } catch (closeErr) {
        console.error('window.close() also failed after consent decline', closeErr);
      }
    }
  };

  return (
    <MotionConfig reducedMotion="user">
    <div className="relative flex h-screen flex-col overflow-hidden bg-birdo-black">
      <PixelCanvas />
      <TitleBar />

      <div className="relative z-10 flex-1 overflow-hidden">
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
    </div>
    </MotionConfig>
  );
}

export default App;
