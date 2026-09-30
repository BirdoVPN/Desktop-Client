import { useState, useRef, useId, type FormEvent, type KeyboardEvent } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-shell';
import { useAppStore, type AccountInfo } from '@/store/app-store';
import { useShallow } from 'zustand/react/shallow';
import { ShieldCheck, KeyRound, Copy, Check, ShieldAlert, Info } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { BirdoButton, BirdoTextField, AppIconMark } from './birdo';
import { brand, gradient, white, status, hairline, motion as motionTokens } from '@/lib/birdo-theme';
import { errorCopy, SESSION_EXPIRED_COPY, type ErrorContext } from '@/lib/errors';
import { toIpcError } from '@/lib/ipc';
import { formatAccountNumber } from '@/utils/helpers';

type AuthTab = 'email' | 'anonymous' | 'sso';
type SsoProvider = 'google' | 'github' | 'apple';

const SSO_NAME: Record<SsoProvider, string> = { google: 'Google', github: 'GitHub', apple: 'Apple' };

interface LoginResponse {
  success: boolean;
  message?: string;
  error?: string;
  /** v2 may carry a code on a `success: false` answer; mapped like a rejection. */
  code?: string;
  requires_two_factor?: boolean;
  challenge_token?: string;
  user?: { email?: string; account_id?: string; is_anonymous?: boolean };
}

/** A syntactically plausible email: something@something.tld. */
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Copy for a failed sign-in (W2-012). A rejection maps by its code; an Ok
 * `{ success: false }` answer maps by its code when it has one, and otherwise
 * to a neutral sentence — never the raw `message`, which is Rust's `ApiError`
 * text ("Authentication failed", "Network error: …", "Server error (502)").
 */
function signInError(e: unknown, context: ErrorContext = 'sign_in'): string {
  return errorCopy(toIpcError(e), context).message;
}
function refusedCopy(result: LoginResponse, context: ErrorContext, fallback: string): string {
  return result.code ? signInError({ code: result.code, message: '' }, context) : fallback;
}

// Module scope, not inside Login(): a component TYPE created inside the render
// body is a new type on every render, so React would remount it (replaying its
// enter animation and losing focus) on each re-render.
const ErrorBanner = ({ message }: { message: string }) => (
  <motion.div
    role="alert"
    className="rounded-birdo-sub px-4 py-3 text-sm"
    style={{
      backgroundColor: status.redBg,
      border: `1px solid rgba(248,113,113,0.20)`,
      color: status.red,
    }}
    initial={{ opacity: 0, scale: 0.95 }}
    animate={{ opacity: 1, scale: 1 }}
  >
    {message}
  </motion.div>
);

export function Login() {
  const [activeTab, setActiveTab] = useState<AuthTab>('email');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  // Separate flags per action (W2-045): the create link used to read
  // "Creating…" during an ordinary sign-in because both shared one flag.
  const [signingIn, setSigningIn] = useState(false);
  const [creating, setCreating] = useState(false);

  // 2FA challenge state
  const [twoFactorRequired, setTwoFactorRequired] = useState(false);
  const [challengeToken, setChallengeToken] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState('');

  // Anonymous sign-in state
  const [anonId, setAnonId] = useState('');
  const [anonPassword, setAnonPassword] = useState('');

  // A newly created anonymous account: its account number is shown once so
  // the user can save it before we sign them in (the account already exists
  // and its tokens are stored by the backend command).
  const [createdId, setCreatedId] = useState<string | null>(null);
  const [copiedId, setCopiedId] = useState(false);

  // SSO in progress: which provider we're waiting on the browser for.
  // `ssoAttemptRef` lets Cancel invalidate the in-flight attempt so a late
  // resolve (or the ~5-min loopback timeout) can't clobber the UI after the
  // user has moved on.
  const [ssoWaiting, setSsoWaiting] = useState<SsoProvider | null>(null);
  const ssoAttemptRef = useRef(0);
  // Set by "Sign up"; the Create button takes focus when it mounts, which is
  // after the previous tab's exit animation — not on the next frame.
  const focusCreateRef = useRef(false);
  const createButtonRef = (el: HTMLButtonElement | null) => {
    if (el && focusCreateRef.current) {
      focusCreateRef.current = false;
      el.focus();
    }
  };
  const tabsId = useId();

  const { setAuthenticated, setUserEmail, sessionEndedReason, setSessionEndedReason } = useAppStore(
    useShallow((s) => ({
      setAuthenticated: s.setAuthenticated,
      setUserEmail: s.setUserEmail,
      sessionEndedReason: s.sessionEndedReason,
      setSessionEndedReason: s.setSessionEndedReason,
    })),
  );

  const signedIn = () => {
    setSessionEndedReason(null);
    setAuthenticated(true);
  };

  // After a login that doesn't carry the email in its response (native SSO
  // exchange, 2FA, anonymous create), fetch the canonical profile so the app
  // shows the REAL identity immediately. Only what was received is written
  // back: `setAccount` MERGES, and explicit nulls would overwrite a known-good
  // identity on a transient profile-fetch failure.
  const hydrateIdentity = async () => {
    try {
      const st = await invoke<{
        is_authenticated: boolean;
        email: string | null;
        account_id: string | null;
        plan: string | null;
      }>('get_auth_state');
      if (st?.email) setUserEmail(st.email);
      const patch: Partial<AccountInfo> = {};
      if (st?.email) patch.email = st.email;
      if (st?.account_id) patch.accountId = st.account_id;
      if (st?.plan) patch.plan = st.plan;
      if (st?.is_authenticated) patch.status = 'active';
      if (Object.keys(patch).length > 0) useAppStore.getState().setAccount(patch);
    } catch {
      /* non-fatal — App startup re-hydrates identity from get_auth_state */
    }
  };

  const emailValid = EMAIL_RE.test(email.trim());
  const canSubmitEmail = emailValid && password.length > 0 && !signingIn;

  const handleLogin = async (e: FormEvent) => {
    e.preventDefault();
    // Validated before any request (W2-045): an empty submit used to reach the
    // backend and count against the sign-in rate limit.
    if (!canSubmitEmail) return;
    setError(null);
    setSigningIn(true);
    try {
      const result = await invoke<LoginResponse>('login', { request: { email: email.trim(), password } });
      if (result.requires_two_factor && result.challenge_token) {
        setTwoFactorRequired(true);
        setChallengeToken(result.challenge_token);
      } else if (result.success) {
        setUserEmail(result.user?.email || email.trim());
        setPassword('');
        signedIn();
      } else {
        setError(refusedCopy(result, 'sign_in', "Couldn't sign in. Check your email and password and try again."));
      }
    } catch (err) {
      setError(signInError(err));
    } finally {
      setSigningIn(false);
    }
  };

  const handleAnonymousLogin = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (anonId.replace(/\D/g, '').length < 24) {
      setError('Enter your full 24-digit account number.');
      return;
    }
    setSigningIn(true);
    try {
      // The backend signs in to that EXISTING account — it never creates one.
      const result = await invoke<LoginResponse>('login_anonymous', {
        request: {
          anonymousId: anonId.replace(/\D/g, ''),
          password: anonPassword || null,
        },
      });
      if (result.requires_two_factor && result.challenge_token) {
        setTwoFactorRequired(true);
        setChallengeToken(result.challenge_token);
      } else if (result.success) {
        await hydrateIdentity();
        setAnonPassword('');
        signedIn();
      } else {
        setError(
          refusedCopy(
            result,
            'anonymous_sign_in',
            "Couldn't sign in. Check your account number and try again.",
          ),
        );
      }
    } catch (err) {
      setError(signInError(err, 'anonymous_sign_in'));
    } finally {
      setSigningIn(false);
    }
  };

  // Create a brand-new anonymous account in-app. The backend mints the
  // 24-digit number and stores tokens; we show the number to save first.
  const handleCreateAnonymous = async () => {
    setError(null);
    setCreating(true);
    try {
      const result = await invoke<LoginResponse>('register_anonymous');
      if (result.success && result.user?.account_id) {
        setCreatedId(result.user.account_id);
      } else {
        setError(refusedCopy(result, 'general', "Couldn't create an account. Please try again."));
      }
    } catch (err) {
      setError(signInError(err, 'general'));
    } finally {
      setCreating(false);
    }
  };

  const copyCreatedId = async () => {
    if (!createdId) return;
    try {
      // Digits only: that is what the sign-in field and the backend take.
      await navigator.clipboard.writeText(createdId.replace(/\D/g, ''));
      setCopiedId(true);
      setTimeout(() => setCopiedId(false), 2000);
    } catch {
      /* clipboard unavailable — the number is still on screen */
    }
  };

  const handleForgotPassword = async () => {
    try {
      await open('https://auth.birdo.app/reset-password');
    } catch {
      setError("Couldn't open your browser. Visit auth.birdo.app to reset your password.");
    }
  };

  // Native SSO: the Rust command opens the system browser to the Birdo broker,
  // catches the loopback redirect, and exchanges the code for tokens. Apple
  // uses the same broker Android uses (P1-parity-008): an account created with
  // Sign in with Apple on a phone has no password to type here.
  const handleSsoLogin = async (provider: SsoProvider) => {
    setError(null);
    setSigningIn(true);
    setSsoWaiting(provider);
    const attempt = ++ssoAttemptRef.current;
    try {
      const result = await invoke<LoginResponse>('native_oauth_login', { provider });
      // Ignore a result the user already cancelled.
      if (attempt !== ssoAttemptRef.current) return;
      if (result.requires_two_factor && result.challenge_token) {
        setTwoFactorRequired(true);
        setChallengeToken(result.challenge_token);
      } else if (result.success) {
        await hydrateIdentity();
        signedIn();
      } else {
        setError(refusedCopy(result, 'sign_in', 'Sign-in was cancelled or did not finish. Please try again.'));
      }
    } catch (err) {
      if (attempt !== ssoAttemptRef.current) return;
      setError(signInError(err));
    } finally {
      if (attempt === ssoAttemptRef.current) {
        setSigningIn(false);
        setSsoWaiting(null);
      }
    }
  };

  // Abandon an in-flight SSO attempt and return to the buttons. The backend
  // loopback keeps waiting harmlessly until it times out; the attempt guard
  // makes its eventual result a no-op.
  const cancelSso = () => {
    ssoAttemptRef.current += 1;
    setSsoWaiting(null);
    setSigningIn(false);
    setError(null);
  };

  const totpValid = /^\d{6}$/.test(totpCode) || /^[0-9A-Fa-f]{4}(?:-?[0-9A-Fa-f]{4})+$/.test(totpCode);

  const handleVerify2FA = async (e: FormEvent) => {
    e.preventDefault();
    if (!totpValid) return;
    setError(null);
    setSigningIn(true);
    try {
      const result = await invoke<LoginResponse>('verify_2fa', {
        request: { challenge_token: challengeToken, code: totpCode },
      });
      if (result.success) {
        await hydrateIdentity();
        setPassword('');
        setChallengeToken(null);
        signedIn();
      } else {
        setError(
          refusedCopy(result, 'sign_in', 'That verification code is invalid or has expired. Please try again.'),
        );
      }
    } catch (err) {
      setError(signInError(err));
    } finally {
      setSigningIn(false);
    }
  };

  const handleBack = () => {
    setTwoFactorRequired(false);
    setChallengeToken(null);
    setTotpCode('');
    setPassword('');
    setError(null);
  };

  const selectTab = (tab: AuthTab) => {
    setActiveTab(tab);
    setError(null);
  };

  // "Sign up" goes to the Anonymous tab and its Create button (iOS), instead of
  // opening the web SIGN-IN page as "Register at birdo.app" did (W2-027).
  const goToSignUp = () => {
    focusCreateRef.current = true;
    selectTab('anonymous');
  };

  const tabs: { id: AuthTab; label: string }[] = [
    { id: 'email', label: 'Email' },
    { id: 'anonymous', label: 'Anonymous' },
    { id: 'sso', label: 'SSO' },
  ];
  const onTabKeyDown = (e: KeyboardEvent<HTMLButtonElement>, index: number) => {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    e.preventDefault();
    const next = (index + (e.key === 'ArrowRight' ? 1 : -1) + tabs.length) % tabs.length;
    selectTab(tabs[next].id);
    const buttons = e.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="tab"]');
    buttons?.[next]?.focus();
  };

  const sessionBanner =
    sessionEndedReason === 'expired'
      ? SESSION_EXPIRED_COPY
      : sessionEndedReason === 'revoked'
        ? 'You were signed out because this session was ended. Sign in again.'
        : null;

  return (
    // Transparent root so the App-level PixelCanvas shows through.
    <div className="flex h-full flex-col">
      {/* Scrollable: the window can be shorter than the content (a small or
          high-DPI display, W2-020). `min-h-full` keeps it centred when it fits. */}
      <div className="flex-1 overflow-y-auto">
        <div className="flex min-h-full flex-col items-center justify-center px-8 py-6">
          <motion.div
            className="w-full max-w-sm"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: motionTokens.slow }}
          >
            <div className="mb-3 flex justify-center">
              <AppIconMark mark size={72} />
            </div>

            <h1
              className="mb-2 text-center text-3xl font-bold"
              style={{
                backgroundImage: gradient.headlineText,
                WebkitBackgroundClip: 'text',
                backgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}
            >
              {createdId ? 'Account created' : 'Welcome Back'}
            </h1>

            <p className="mb-5 text-center text-sm" style={{ color: white.w60 }}>
              {createdId
                ? 'Save your account number'
                : twoFactorRequired
                  ? 'Enter your authenticator code'
                  : 'Sign in to your Birdo account'}
            </p>

            {sessionBanner && !createdId && (
              <div
                role="status"
                className="mb-4 flex items-start gap-2 rounded-birdo-sub px-4 py-3 text-sm"
                style={{ backgroundColor: white.w05, border: `1px solid ${hairline.strong}`, color: white.w80 }}
              >
                <Info size={16} aria-hidden className="mt-0.5 shrink-0" color={white.w60} />
                <span>{sessionBanner}</span>
              </div>
            )}

            {createdId ? (
              /* ── New anonymous account: show the number once ── */
              <div className="flex flex-col gap-4">
                <div className="flex flex-col items-center gap-2 text-center">
                  <div
                    className="flex h-12 w-12 items-center justify-center rounded-full"
                    style={{ backgroundColor: white.w05 }}
                  >
                    <KeyRound size={24} color={brand.accentLight} aria-hidden />
                  </div>
                  <p className="text-sm" style={{ color: white.w60 }}>
                    Your anonymous account is ready. This account number is the{' '}
                    <span className="font-semibold" style={{ color: white.w100 }}>
                      only
                    </span>{' '}
                    way back in.
                  </p>
                </div>

                <button
                  type="button"
                  onClick={copyCreatedId}
                  className="flex w-full items-center gap-3 rounded-birdo-sub px-4 py-3 text-left transition-colors hover:bg-white/5"
                  style={{ backgroundColor: white.w04, border: `1px solid ${hairline.soft}` }}
                  aria-label={`Copy account number ${formatAccountNumber(createdId)}`}
                >
                  <span className="min-w-0 flex-1 break-all font-mono text-sm tracking-wide" style={{ color: white.w100 }}>
                    {formatAccountNumber(createdId)}
                  </span>
                  {copiedId ? (
                    <Check size={18} color={brand.accentLight} aria-hidden />
                  ) : (
                    <Copy size={18} color={white.w60} aria-hidden />
                  )}
                </button>

                <p className="flex items-start gap-1.5 text-xs" style={{ color: white.w60 }}>
                  <ShieldAlert size={14} color={status.yellow} aria-hidden className="mt-0.5 shrink-0" />
                  <span>Save it somewhere safe — we can&apos;t reset it if you lose it.</span>
                </p>

                <BirdoButton
                  type="button"
                  text="I've saved it — continue"
                  onClick={async () => {
                    await hydrateIdentity();
                    signedIn();
                  }}
                  variant="brand"
                  size="large"
                  fullWidth
                />
              </div>
            ) : twoFactorRequired ? (
              /* ── 2FA verification ── */
              <form onSubmit={handleVerify2FA} className="flex flex-col items-center space-y-4">
                <div
                  className="flex h-12 w-12 items-center justify-center rounded-full"
                  style={{ backgroundColor: white.w05 }}
                >
                  <ShieldCheck size={24} color={white.w60} aria-hidden />
                </div>

                <label htmlFor="totp" className="block text-xs font-medium" style={{ color: white.w60 }}>
                  Verification Code
                </label>
                <input
                  id="totp"
                  type="text"
                  inputMode="text"
                  autoComplete="one-time-code"
                  value={totpCode}
                  // A 6-digit TOTP OR a hex backup code (16 hex, 19 chars with
                  // dashes). Keep digits, hex letters and dashes; cap at 19.
                  onChange={(e) => setTotpCode(e.target.value.replace(/[^0-9A-Fa-f-]/g, '').slice(0, 19))}
                  placeholder="000000 or backup code"
                  required
                  maxLength={19}
                  autoFocus
                  aria-describedby="totp-hint"
                  className="w-full rounded-birdo-sub px-4 py-3 text-center text-2xl tracking-[0.3em] outline-hidden"
                  style={{
                    backgroundColor: white.w04,
                    border: `1px solid ${hairline.soft}`,
                    color: white.w100,
                  }}
                />
                <p id="totp-hint" className="text-center text-xs" style={{ color: white.w60 }}>
                  Enter the 6-digit code from your authenticator, or a backup code
                </p>

                {error && <ErrorBanner message={error} />}

                <BirdoButton
                  type="submit"
                  text={signingIn ? 'Verifying…' : 'Verify'}
                  onClick={() => {}}
                  variant="brand"
                  size="large"
                  fullWidth
                  isLoading={signingIn}
                  disabled={!totpValid}
                />

                <button
                  type="button"
                  onClick={handleBack}
                  className="text-sm underline transition hover:text-w80"
                  style={{ color: white.w60 }}
                >
                  Back to sign in
                </button>
              </form>
            ) : (
              <>
                {/* ── Auth method tabs (a real tablist, W2-035) ── */}
                <div
                  role="tablist"
                  aria-label="Sign-in method"
                  className="mb-5 flex gap-1 rounded-birdo-sub bg-w06 p-1"
                >
                  {tabs.map((tab, i) => {
                    const active = activeTab === tab.id;
                    return (
                      <button
                        key={tab.id}
                        type="button"
                        role="tab"
                        id={`${tabsId}-${tab.id}`}
                        aria-selected={active}
                        aria-controls={`${tabsId}-panel`}
                        tabIndex={active ? 0 : -1}
                        onClick={() => selectTab(tab.id)}
                        onKeyDown={(e) => onTabKeyDown(e, i)}
                        className="birdo-tab flex flex-1 items-center justify-center rounded-birdo-sm py-2 text-xs font-medium transition-all"
                        style={{
                          backgroundColor: active ? white.w10 : 'transparent',
                          color: active ? white.w100 : white.w60,
                          boxShadow: active
                            ? 'inset 0 1px 0 rgba(255,255,255,0.12), 0 2px 8px -2px rgba(0,0,0,0.45)'
                            : 'none',
                        }}
                      >
                        {tab.label}
                      </button>
                    );
                  })}
                </div>

                <div role="tabpanel" id={`${tabsId}-panel`} aria-labelledby={`${tabsId}-${activeTab}`}>
                  <AnimatePresence mode="wait">
                    {activeTab === 'email' && (
                      <motion.form
                        key="email-form"
                        onSubmit={handleLogin}
                        noValidate
                        className="flex flex-col gap-3"
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 10 }}
                        transition={{ duration: motionTokens.fast }}
                      >
                        <BirdoTextField
                          label="Email"
                          type="email"
                          value={email}
                          onChange={setEmail}
                          placeholder="you@example.com"
                          autoComplete="email"
                        />

                        <div>
                          <div className="mb-1.5 flex items-center justify-between pl-1">
                            <span className="text-xs font-medium" style={{ color: white.w60 }}>
                              Password
                            </span>
                            <button
                              type="button"
                              onClick={handleForgotPassword}
                              className="text-xs transition hover:text-w100"
                              style={{ color: white.w60 }}
                            >
                              Forgot password?
                            </button>
                          </div>
                          <BirdoTextField
                            type="password"
                            value={password}
                            onChange={setPassword}
                            placeholder="••••••••"
                            autoComplete="current-password"
                            ariaLabel="Password"
                          />
                        </div>

                        {error && <ErrorBanner message={error} />}

                        <BirdoButton
                          type="submit"
                          text={signingIn ? 'Signing in…' : 'Sign in'}
                          onClick={() => {}}
                          variant="brand"
                          size="large"
                          fullWidth
                          isLoading={signingIn}
                          disabled={!emailValid || password.length === 0}
                          className="mt-1"
                        />
                      </motion.form>
                    )}

                    {activeTab === 'anonymous' && (
                      <motion.div
                        key="anon-form"
                        className="flex flex-col gap-3"
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 10 }}
                        transition={{ duration: motionTokens.fast }}
                      >
                        {/* Creating an account comes FIRST and is the primary
                            action (iOS LoginView, W2-027): it used to be a small
                            text link under the sign-in button. */}
                        <button
                          ref={createButtonRef}
                          type="button"
                          onClick={handleCreateAnonymous}
                          disabled={creating || signingIn}
                          className="flex h-14 w-full items-center justify-center rounded-birdo-md text-base font-semibold text-white transition-opacity disabled:opacity-60"
                          style={{ backgroundImage: gradient.primary }}
                        >
                          {creating && (
                            <span
                              className="mr-2.5 h-[18px] w-[18px] animate-spin rounded-full border-2 border-current border-t-transparent"
                              aria-hidden
                            />
                          )}
                          {creating ? 'Creating…' : 'Create a new anonymous account'}
                        </button>
                        <p className="text-center text-xs" style={{ color: white.w60 }}>
                          No email needed. You get an account number to sign in with.
                        </p>

                        <div className="my-1 flex items-center gap-3" aria-hidden>
                          <span className="h-px flex-1" style={{ backgroundColor: hairline.soft }} />
                          <span className="text-xs" style={{ color: white.w60 }}>
                            or use an existing account number
                          </span>
                          <span className="h-px flex-1" style={{ backgroundColor: hairline.soft }} />
                        </div>

                        <form onSubmit={handleAnonymousLogin} className="flex flex-col gap-3">
                          <BirdoTextField
                            label="Account number"
                            value={anonId}
                            onChange={(next) => setAnonId(formatAccountNumber(next.replace(/\D/g, '').slice(0, 24)))}
                            placeholder="XXXX XXXX XXXX XXXX XXXX XXXX"
                            className="font-mono"
                            inputMode="numeric"
                            hint="The 24 digits you saved when you created the account."
                          />

                          <BirdoTextField
                            label="Password (only if you set one)"
                            type="password"
                            value={anonPassword}
                            onChange={setAnonPassword}
                            placeholder="••••••••"
                            autoComplete="current-password"
                          />

                          {error && <ErrorBanner message={error} />}

                          <BirdoButton
                            type="submit"
                            text={signingIn ? 'Signing in…' : 'Sign in'}
                            onClick={() => {}}
                            variant="secondary"
                            size="large"
                            fullWidth
                            isLoading={signingIn}
                            disabled={creating}
                          />
                        </form>
                      </motion.div>
                    )}

                    {activeTab === 'sso' && (
                      <motion.div
                        key="sso-form"
                        className="flex flex-col justify-center gap-3"
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: 10 }}
                        transition={{ duration: motionTokens.fast }}
                      >
                        {ssoWaiting ? (
                          <div className="flex flex-col items-center gap-4 text-center" aria-live="polite">
                            <div className="h-9 w-9 animate-spin rounded-full border-2 border-white/10 border-t-white" />
                            <p className="text-sm" style={{ color: white.w60 }}>
                              Finish signing in with {SSO_NAME[ssoWaiting]} in your browser, then return here.
                            </p>
                            <p className="text-xs" style={{ color: white.w60 }}>
                              Tip: if the browser is signed into a different account, pick the right one there.
                            </p>
                            <button
                              type="button"
                              onClick={cancelSso}
                              className="text-xs underline transition hover:text-w100"
                              style={{ color: white.w60 }}
                            >
                              Cancel
                            </button>
                          </div>
                        ) : (
                          <>
                            <p className="text-center text-sm" style={{ color: white.w60 }}>
                              Continue with your Google, GitHub or Apple account — no password needed.
                            </p>
                            {error && <ErrorBanner message={error} />}
                            {(['google', 'github', 'apple'] as const).map((p) => (
                              <BirdoButton
                                key={p}
                                type="button"
                                text={`Continue with ${SSO_NAME[p]}`}
                                onClick={() => handleSsoLogin(p)}
                                variant="brand"
                                size="large"
                                fullWidth
                                disabled={signingIn}
                              />
                            ))}
                          </>
                        )}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>

                {activeTab !== 'anonymous' && (
                  <p className="mt-5 text-center text-sm" style={{ color: white.w60 }}>
                    Don&apos;t have an account?{' '}
                    <button
                      type="button"
                      onClick={goToSignUp}
                      className="font-medium underline-offset-2 transition hover:underline"
                      style={{ color: white.w100 }}
                    >
                      Sign up
                    </button>
                  </p>
                )}
              </>
            )}
          </motion.div>
        </div>
      </div>
    </div>
  );
}
