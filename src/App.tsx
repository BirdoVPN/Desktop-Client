import { useState, useEffect, useRef, useCallback, type ReactNode } from 'react';
import { useAppStore, type AccountInfo } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';
import { ConsentScreen } from '@/components/ConsentScreen';
import { Login } from '@/components/Login';
import { AppShell } from '@/components/AppShell';
import { OfflineBanner } from '@/components/OfflineBanner';
import { PixelCanvas } from '@/components/PixelCanvas';
import { TitleBar } from '@/components/TitleBar';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { LiveAnnouncer } from '@/components/LiveAnnouncer';
import { NoticeHost } from '@/components/NoticeHost';
import { MODAL_ROOT_ID } from '@/components/birdo/Dialog';
import { UpdateRequired, type RequiredUpdate } from '@/components/UpdateRequired';
import { VpnSessionController } from '@/session/controller';
import { endSession } from '@/session/session';
import { checkForUpdates } from '@/session/updater';
import { applyWindowPlacement } from '@/lib/window-placement';
import { installBrowserShortcutGuard } from '@/lib/keyboard';
import { motion as motionTokens } from '@/lib/birdo-theme';
import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import { exit } from '@tauri-apps/plugin-process';
import { notifyUpdateAvailable } from '@/utils/notifications';
import { anonymityPatch } from '@/utils/helpers';
import { hasCurrentConsent } from '@/lib/consent';
import { motion, AnimatePresence, MotionConfig } from 'framer-motion';

interface AuthState {
  is_authenticated: boolean;
  email: string | null;
  account_id: string | null;
  plan: string | null;
  /** Optional: absent when talking to a backend that predates the field. */
  has_password?: boolean;
  /** Account API contract item 86; absent or null on an older backend. */
  is_anonymous?: boolean | null;
  account_number?: string | null;
}

/** Whether the window is on screen; unknown counts as visible (never skip a prompt the user can see). */
async function windowIsVisible(): Promise<boolean> {
  try {
    return await getCurrentWindow().isVisible();
  } catch {
    return true;
  }
}

function App() {
  const { isAuthenticated, hasAcceptedConsent, setAuthenticated, setLoading, setUserEmail, setAccount, acceptConsent, windowCorner, pushed } =
    useAppStore(
      useShallow((s) => ({
        isAuthenticated: s.isAuthenticated,
        // The CURRENT text (D7): an older acceptance shows the screen again.
        hasAcceptedConsent: hasCurrentConsent(s.acceptedConsentVersion),
        setAuthenticated: s.setAuthenticated,
        setLoading: s.setLoading,
        setUserEmail: s.setUserEmail,
        setAccount: s.setAccount,
        acceptConsent: s.acceptConsent,
        windowCorner: s.windowCorner,
        pushed: s.navStack.length > 0,
      })),
    );
  // The startup sign-in check has answered. It runs only once the CURRENT
  // consent is in (below), so until then there is nothing to wait for.
  const [authChecked, setAuthChecked] = useState(false);
  const initializing = hasAcceptedConsent && !authChecked;

  // Forced client-version floor. The backend answers every request from a
  // too-old build with a structured 426; api::upgrade_gate latches that
  // process-wide, emits `update-required`, and stops auto-reconnect from
  // hammering the wall. Once set this is never cleared in-process — the way
  // out is installing the update, which restarts the app.
  const [requiredUpdate, setRequiredUpdate] = useState<RequiredUpdate | null>(null);
  useEffect(() => {
    const unlisten = listen<RequiredUpdate>('update-required', (event) => {
      setRequiredUpdate(event.payload ?? {});
    });
    // A request can be refused before this listener exists (the launch-time
    // get_auth_state, for instance), so also read the latch once. No polling:
    // one refusal is enough and the gate never reopens.
    invoke<RequiredUpdate | null>('get_required_update')
      .then((info) => {
        if (info) setRequiredUpdate(info);
      })
      .catch(() => {
        /* command unavailable — the event path still covers the live case */
      });
    return () => {
      unlisten.then((fn) => fn()).catch(() => {});
    };
  }, []);

  // Hide App Contents (the biometric cover). It covers the SCREEN only: the
  // session controller below keeps running behind it, so the VPN — including
  // Auto-Connect, the tray and notifications — works while it is up (W2-026;
  // iOS says the same in its copy). 'checking' avoids a flash of the app.
  const [bioLock, setBioLock] = useState<'checking' | 'locked' | 'open'>('checking');

  const requestBiometricUnlock = async () => {
    try {
      const ok = await invoke<boolean>('authenticate_biometric', {
        reason: 'Unlock BirdoVPN',
      });
      if (ok) setBioLock('open');
    } catch {
      // Prompt failed/cancelled — remain locked; the user can retry or quit.
    }
  };

  useEffect(() => {
    invoke<{ available: boolean; enabled: boolean }>('check_biometric_available')
      .then(async (st) => {
        if (st?.available && st?.enabled) {
          setBioLock('locked');
          // Prompt only if the window is actually on screen. With Start
          // Minimized the app boots into the tray, and a Windows Hello prompt
          // appearing at sign-in over nothing is alarming; `app-shown` below
          // prompts when the user opens the window.
          if (await windowIsVisible()) requestBiometricUnlock();
        } else {
          setBioLock('open');
        }
      })
      .catch(() => setBioLock('open'));
  }, []);

  // Re-arm the cover when the app is hidden to the tray and re-prompt when it
  // returns. Keyed off hide-to-tray, not blur, so alt-tabbing never re-locks.
  const bioLockRef = useRef(bioLock);
  useEffect(() => {
    bioLockRef.current = bioLock;
  }, [bioLock]);
  useEffect(() => {
    const unlistenHidden = listen('app-hidden', async () => {
      try {
        const st = await invoke<{ available: boolean; enabled: boolean }>('check_biometric_available');
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

  // Window size + position from the monitor work area (W2-020), on startup,
  // when the preference changes, and when the window moves to a display with a
  // different scale factor.
  useEffect(() => {
    applyWindowPlacement(windowCorner).catch(() => {
      /* window not ready / non-fatal */
    });
    const off = getCurrentWindow()
      .onScaleChanged(() => {
        applyWindowPlacement(windowCorner).catch(() => {});
      })
      .catch(() => undefined);
    return () => {
      off.then((fn) => fn?.()).catch(() => {});
    };
  }, [windowCorner]);

  // F5 / Ctrl+R / Ctrl+P and friends (W2-033).
  useEffect(() => installBrowserShortcutGuard(), []);

  // D7 re-consent behind Start Minimized (REVIEW-WIN2-010). Starting in the
  // tray, the consent screen rendered in a hidden window, and auto-connect —
  // which waits for consent — silently never ran: the user booted unprotected
  // with nothing saying why. A launch that needs the user's answer first
  // brings the window up. Once, at launch: closing it to the tray after that
  // is the user's own choice.
  useEffect(() => {
    if (hasCurrentConsent(useAppStore.getState().acceptedConsentVersion)) return;
    getCurrentWindow()
      .isVisible()
      .catch(() => false)
      .then((visible) => {
        if (!visible) return invoke('show_main_window');
      })
      .catch(() => {
        /* best effort: the tray's Show Window still reaches it */
      });
  }, []);

  // NOTE: the tray icon, tooltip and menu are driven by Rust from its state
  // choke point (contract v2, W1-023). This used to push `set_tray_state` from
  // here, keyed on a connection state only Dashboard's poll kept current.

  useEffect(() => {
    // Not before consent (D7, audit D-12): with a stored session this asks
    // api.birdo.app who the user is, and a signed-in user whose consent is to
    // an OLDER text sees the consent screen first. Accepting runs it, behind
    // the loading screen rather than a flash of Login.
    if (!hasAcceptedConsent) return;
    // Check for stored authentication on startup
    const checkAuth = async () => {
      try {
        setLoading(true);
        const authState = await invoke<AuthState>('get_auth_state');
        setAuthenticated(authState.is_authenticated);

        if (authState.is_authenticated) {
          // Merge only the fields we actually received. `setAccount` MERGES, so
          // passing explicit nulls would wipe a good identity whenever the
          // profile fetch failed transiently (get_auth_state deliberately keeps
          // the session alive with an unknown identity in that case rather than
          // signing the user out). Absent means "unchanged", not "cleared".
          if (authState.email) setUserEmail(authState.email);
          const patch: Partial<AccountInfo> = {
            status: 'active',
            // `?? true` keeps the password prompt when the backend predates the
            // field — a stale `false` would REMOVE a safety prompt.
            hasPassword: authState.has_password ?? true,
          };
          if (authState.email) patch.email = authState.email;
          if (authState.account_id) patch.accountId = authState.account_id;
          if (authState.plan) patch.plan = authState.plan;
          setAccount({ ...patch, ...anonymityPatch(authState) });
        }
      } catch {
        // Auth check failed - assume not authenticated
        setAuthenticated(false);
      } finally {
        setLoading(false);
        setAuthChecked(true);
      }
    };

    checkAuth();
  }, [hasAcceptedConsent, setAuthenticated, setLoading, setUserEmail, setAccount]);

  // Retry identity hydration when we are signed in but the email never
  // arrived (`get_auth_state` keeps a valid session alive through a transient
  // profile-fetch failure). Backs off 4s, 8s, 16s and stops after 3 attempts;
  // the attempt counter is STATE so a failed attempt re-runs the effect.
  //
  // A reply of `is_authenticated: false` is NOT a transient failure: Rust
  // cleared a rejected refresh token, so the session is over (W2-006). It used
  // to be ignored, leaving a signed-in shell that could do nothing.
  const [identityAttempt, setIdentityAttempt] = useState(0);
  const accountEmail = useAppStore((s) => s.account.email);
  useEffect(() => {
    if (!isAuthenticated || accountEmail || identityAttempt >= 3) return;
    const delayMs = 4000 * 2 ** identityAttempt;
    const timer = setTimeout(async () => {
      try {
        const st = await invoke<AuthState>('get_auth_state');
        if (st && st.is_authenticated === false) {
          endSession('expired');
          return;
        }
        if (st?.email) {
          setUserEmail(st.email);
          const patch: Partial<AccountInfo> = { email: st.email, ...anonymityPatch(st) };
          if (st.account_id) patch.accountId = st.account_id;
          if (st.plan) patch.plan = st.plan;
          setAccount(patch);
        }
      } catch {
        /* non-fatal — the backoff above bounds how often this runs */
      } finally {
        setIdentityAttempt((a) => a + 1);
      }
    }, delayMs);
    return () => clearTimeout(timer);
  }, [isAuthenticated, accountEmail, identityAttempt, setUserEmail, setAccount]);

  // Daily background update check through the pinned Rust updater. Shortly
  // after startup, then every 24h; notifies at most once per app run. Not
  // before consent (audit D-12): the check is a request to api.birdo.app.
  useEffect(() => {
    if (!hasAcceptedConsent) return;
    let notified = false;
    const runCheck = async () => {
      if (notified) return;
      const update = await checkForUpdates(true);
      if (update) {
        notified = true;
        notifyUpdateAvailable(update.version);
      }
    };
    const initial = setTimeout(runCheck, 20_000); // let startup settle first
    const daily = setInterval(runCheck, 24 * 60 * 60 * 1000);
    return () => {
      clearTimeout(initial);
      clearInterval(daily);
    };
  }, [hasAcceptedConsent]);

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
        // Show the Connect tab; the session controller stages the confirmation.
        useAppStore.getState().setTab('home');
        useAppStore.getState().setDeepLinkAction({ action: 'connect', serverId: path });
      } else if (action === 'settings') {
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

  // ── Consent handlers ──────────────────────────────────────────
  // The crash-report choice made on the consent screen goes straight to Rust
  // through the dedicated command (it reads settings.json, flips the one
  // field and applies the opt-in live), never through a full save of a store
  // that has not been hydrated from Rust yet. Default OFF; a failed write
  // leaves it OFF, which is the safe direction.
  const handleAcceptConsent = (crashReportsEnabled: boolean) => {
    acceptConsent();
    useAppStore.getState().updateSettings({ crashReportsEnabled });
    invoke('set_crash_reports_enabled', { enabled: crashReportsEnabled }).catch((err) => {
      console.error('Failed to save the crash-report choice', err);
      useAppStore.getState().updateSettings({ crashReportsEnabled: false });
    });
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

  // ── Which screen ──────────────────────────────────────────────
  // Order: initialising, then the biometric cover (the user's own
  // device-security boundary: nothing renders until unlock succeeds, not even
  // the version wall), then the version wall, then consent / login / the app.
  let screen: ReactNode;
  let screenKey: string;
  if (initializing || bioLock === 'checking') {
    screenKey = 'loading';
    screen = (
      <div className="flex h-full flex-col items-center justify-center gap-4">
        <div className="h-16 w-16 animate-spin rounded-full border-2 border-white/10 border-t-white" />
        <p className="text-sm text-white/60">Loading…</p>
      </div>
    );
  } else if (bioLock === 'locked') {
    screenKey = 'locked';
    screen = (
      <div className="flex h-full flex-col items-center justify-center gap-6 px-8">
        <div className="flex flex-col items-center gap-3 text-center">
          <h1 className="text-lg font-semibold text-white">BirdoVPN is locked</h1>
          <p className="max-w-xs text-sm text-white/60">
            Hide App Contents is on. Verify it's you to continue. The VPN keeps running in the background.
          </p>
        </div>
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
            className="text-xs text-white/60 transition hover:text-white/80"
          >
            Quit
          </button>
        </div>
      </div>
    );
  } else if (requiredUpdate) {
    // A hard block: the backend refuses every request from this build.
    screenKey = 'update-required';
    screen = <UpdateRequired info={requiredUpdate} />;
  } else if (!hasAcceptedConsent) {
    screenKey = 'consent';
    screen = <ConsentScreen onAccept={handleAcceptConsent} onDecline={handleDeclineConsent} />;
  } else if (isAuthenticated) {
    screenKey = 'appshell';
    screen = <AppShell />;
  } else {
    screenKey = 'login';
    screen = <Login />;
  }

  return (
    // MotionConfig wraps EVERY screen: the loading, lock and update screens
    // used to animate outside it, ignoring reduced motion (W2-034).
    <MotionConfig reducedMotion="user">
      <div className="relative flex h-screen flex-col overflow-hidden bg-birdo-black">
        {/* Parked while a pushed sub-screen (which has its own) covers it. */}
        <PixelCanvas paused={pushed} />
        {/* Outside the content boundary: a crash in a screen must never take
            the frameless window's only controls with it (W2-044). */}
        <TitleBar />

        {/* The session controller runs for the whole signed-in session —
            under the biometric cover and the version wall too — so the VPN
            is watched and driven whatever the screen shows (W2-001). */}
        {isAuthenticated && hasAcceptedConsent && <VpnSessionController />}

        {/* A column: the offline banner takes its height and the screen gets
            the rest. It used to sit above a 100%-height screen and push the
            bottom navigation out of the window (W2-021). */}
        <div className="relative z-10 flex min-h-0 flex-1 flex-col overflow-hidden">
          <OfflineBanner />
          <div className="relative min-h-0 flex-1">
            {/* Dialogs portal here (BirdoDialog): over the screen, under the
                title bar, never clipped by the card they are declared in. */}
            <div id={MODAL_ROOT_ID} className="pointer-events-none absolute inset-0 z-50" />
            <ErrorBoundary>
              <AnimatePresence mode="wait">
                <motion.div
                  key={screenKey}
                  className="relative z-10 h-full"
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  transition={{ duration: motionTokens.standard, ease: motionTokens.ease }}
                >
                  {screen}
                </motion.div>
              </AnimatePresence>
            </ErrorBoundary>
          </div>
          <NoticeHost />
        </div>
        {isAuthenticated && <LiveAnnouncer />}
      </div>
    </MotionConfig>
  );
}

export default App;
