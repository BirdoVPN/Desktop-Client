import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-shell';
import { useAppStore } from '@/store/app-store';
import { ShieldCheck, UserRound, KeyRound } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { BirdoBadge, BirdoButton, BirdoTextField, AppIconMark } from './birdo';
import { gradient, white, status, hairline, motion as motionTokens } from '@/lib/birdo-theme';

/** Map raw backend error strings to user-friendly messages */
function friendlyError(raw: unknown): string {
  const msg = typeof raw === 'string' ? raw : String(raw);
  const lower = msg.toLowerCase();

  if (lower.includes('invalid credentials') || lower.includes('unauthorized') || lower.includes('401'))
    return 'Incorrect email or password. Please try again.';
  if (lower.includes('network') || lower.includes('dns') || lower.includes('connect'))
    return 'Unable to reach the server. Check your internet connection.';
  if (lower.includes('timeout'))
    return 'The server took too long to respond. Please try again.';
  if (lower.includes('rate limit') || lower.includes('429'))
    return 'Too many login attempts. Please wait a moment and try again.';
  if (lower.includes('subscription') || lower.includes('expired'))
    return 'Your subscription has expired. Please renew at birdo.app.';
  if (lower.includes('server') || lower.includes('500'))
    return 'A server error occurred. Please try again later.';
  if (lower.includes('invalid') && lower.includes('verification'))
    return 'Invalid verification code. Please try again.';

  return msg.length > 120 ? `${msg.slice(0, 120)}…` : msg;
}

type AuthTab = 'email' | 'anonymous';

interface LoginResponse {
  success: boolean;
  message?: string;
  error?: string;
  requires_two_factor?: boolean;
  challenge_token?: string;
  user?: { email?: string; account_id?: string; is_anonymous?: boolean };
}

export function Login() {
  const [activeTab, setActiveTab] = useState<AuthTab>('email');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // 2FA challenge state
  const [twoFactorRequired, setTwoFactorRequired] = useState(false);
  const [challengeToken, setChallengeToken] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState('');

  // Anonymous login state
  const [anonId, setAnonId] = useState('');

  const { setAuthenticated, setUserEmail } = useAppStore();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const result = await invoke<LoginResponse>('login', { request: { email, password } });

      if (result.requires_two_factor && result.challenge_token) {
        setTwoFactorRequired(true);
        setChallengeToken(result.challenge_token);
      } else if (result.success) {
        setUserEmail(result.user?.email || email);
        setPassword('');
        setAuthenticated(true);
      } else {
        setError(result.message || result.error || 'Login failed');
      }
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setIsLoading(false);
    }
  };

  const handleAnonymousLogin = async () => {
    setError(null);
    setIsLoading(true);

    try {
      // The backend derives the account from a stable device ID — no args.
      const result = await invoke<LoginResponse>('login_anonymous');

      if (result.requires_two_factor && result.challenge_token) {
        setTwoFactorRequired(true);
        setChallengeToken(result.challenge_token);
      } else if (result.success) {
        setUserEmail(result.user?.email || null);
        setAuthenticated(true);
      } else {
        setError(result.message || result.error || 'Login failed. Check your anonymous ID.');
      }
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setIsLoading(false);
    }
  };

  const handleForgotPassword = async () => {
    try {
      await open('https://auth.birdo.app/reset-password');
    } catch {
      setError('Failed to open browser');
    }
  };

  const handleVerify2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const result = await invoke<LoginResponse>('verify_2fa', {
        request: {
          challenge_token: challengeToken,
          code: totpCode,
        },
      });

      if (result.success) {
        setUserEmail(result.user?.email || email);
        setPassword('');
        setChallengeToken(null);
        setAuthenticated(true);
      } else {
        setError(result.message || result.error || 'Verification failed');
      }
    } catch (err) {
      setError(friendlyError(err));
    } finally {
      setIsLoading(false);
    }
  };

  const handleBack = () => {
    setTwoFactorRequired(false);
    setChallengeToken(null);
    setTotpCode('');
    setPassword('');
    setError(null);
  };

  const anonDigits = anonId.replace(/\D/g, '');
  const tabs: { id: AuthTab; label: string; icon: React.ReactNode }[] = [
    { id: 'email', label: 'Email', icon: <KeyRound size={14} /> },
    { id: 'anonymous', label: 'Anonymous', icon: <UserRound size={14} /> },
  ];

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

  return (
    // Transparent root so the App-level PixelCanvas shows through behind the
    // login content (opaque bg-birdo-s0 here was hiding the animated backdrop).
    <div className="flex h-full flex-col">
      {/* Brand now lives in the window TitleBar — no duplicate header here. */}
      {/* ── Centered phone column ── */}
      <div className="flex flex-1 flex-col items-center justify-center px-8">
        <motion.div
          className="w-full max-w-sm"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: motionTokens.slow520 }}
        >
          {/* Brand mark */}
          <motion.div
            className="mb-5 flex justify-center"
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: motionTokens.emphasis, delay: 0.06 }}
          >
            <AppIconMark size={72} style={{ borderRadius: 20 }} />
          </motion.div>

          {/* Status badge */}
          <motion.div
            className="mb-6 flex justify-center"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: motionTokens.emphasis, delay: 0.1 }}
          >
            <BirdoBadge text="Secure Connection" tone="success" pulseDot />
          </motion.div>

          {/* Gradient headline */}
          <motion.h2
            className="mb-2 text-center text-3xl font-bold"
            style={{
              backgroundImage: gradient.headlineText,
              WebkitBackgroundClip: 'text',
              backgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: motionTokens.emphasis, delay: 0.15 }}
          >
            {twoFactorRequired ? 'Two-Factor Auth' : 'Welcome Back'}
          </motion.h2>

          <motion.p
            className="mb-7 text-center text-sm text-w40"
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: motionTokens.emphasis, delay: 0.2 }}
          >
            {twoFactorRequired
              ? 'Enter your authenticator code'
              : 'Sign in to access the sovereign network'}
          </motion.p>

          {twoFactorRequired ? (
            /* ── 2FA Verification Form ── */
            <motion.form
              onSubmit={handleVerify2FA}
              className="flex flex-col items-center space-y-4"
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: motionTokens.standard }}
            >
              <div
                className="flex h-12 w-12 items-center justify-center rounded-full"
                style={{ backgroundColor: white.w05 }}
              >
                <ShieldCheck size={24} color={white.w60} />
              </div>

              <label htmlFor="totp" className="block text-xs font-medium text-w60">
                Verification Code
              </label>
              <input
                id="totp"
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                placeholder="000000"
                required
                maxLength={6}
                autoFocus
                className="w-full rounded-birdo-sub px-4 py-3 text-center text-2xl tracking-[0.3em] outline-none"
                style={{
                  backgroundColor: white.w04,
                  border: `1px solid ${hairline.soft}`,
                  color: white.w100,
                }}
              />
              <p className="text-center text-xs text-w40">
                Enter the 6-digit code from your authenticator app
              </p>

              {error && <ErrorBanner message={error} />}

              <BirdoButton
                type="submit"
                text={isLoading ? 'Verifying…' : 'Verify'}
                onClick={() => {}}
                variant="brand"
                size="large"
                fullWidth
                isLoading={isLoading}
                disabled={totpCode.length !== 6}
              />

              <button
                type="button"
                onClick={handleBack}
                className="text-sm text-w60 underline transition hover:text-w80"
              >
                Back to login
              </button>
            </motion.form>
          ) : (
            <>
              {/* ── Auth method tabs ── */}
              <motion.div
                className="mb-5 flex gap-1 rounded-birdo-sub bg-w06 p-1"
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: motionTokens.emphasis, delay: 0.22 }}
              >
                {tabs.map((tab) => {
                  const active = activeTab === tab.id;
                  return (
                    <button
                      key={tab.id}
                      type="button"
                      onClick={() => {
                        setActiveTab(tab.id);
                        setError(null);
                      }}
                      className="flex flex-1 items-center justify-center gap-1.5 rounded-birdo-sm py-2 text-xs font-medium transition-all"
                      style={{
                        backgroundColor: active ? white.w10 : 'transparent',
                        color: active ? white.w100 : white.w40,
                      }}
                    >
                      {tab.icon}
                      {tab.label}
                    </button>
                  );
                })}
              </motion.div>

              <AnimatePresence mode="wait">
                {activeTab === 'email' && (
                  <motion.form
                    key="email-form"
                    onSubmit={handleLogin}
                    className="space-y-4"
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
                        <span className="text-xs font-medium text-w60">Password</span>
                        <button
                          type="button"
                          onClick={handleForgotPassword}
                          className="text-xs text-w40 transition hover:text-w80"
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
                      text={isLoading ? 'Connecting…' : 'Initialize Uplink'}
                      onClick={() => {}}
                      variant="brand"
                      size="large"
                      fullWidth
                      isLoading={isLoading}
                    />
                  </motion.form>
                )}

                {activeTab === 'anonymous' && (
                  <motion.div
                    key="anon-form"
                    className="space-y-4"
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, x: 10 }}
                    transition={{ duration: motionTokens.fast }}
                  >
                    <div>
                      <BirdoTextField
                        label="Anonymous ID"
                        value={anonId}
                        onChange={(next) => setAnonId(next.replace(/[^\d-]/g, '').slice(0, 29))}
                        placeholder="000000-000000-000000-000000"
                        className="font-mono"
                        ariaLabel="Anonymous ID"
                      />
                      <p className="mt-1 pl-1 text-xs text-w40">
                        Enter the 24-digit ID from your anonymous account
                      </p>
                    </div>

                    {error && <ErrorBanner message={error} />}

                    <BirdoButton
                      text={isLoading ? 'Signing in…' : 'Initialize Uplink'}
                      onClick={handleAnonymousLogin}
                      variant="brand"
                      size="large"
                      fullWidth
                      isLoading={isLoading}
                      disabled={anonDigits.length < 24}
                    />

                    <p className="text-center text-xs text-w40">
                      Don&apos;t have an anonymous ID?{' '}
                      <a
                        href="https://auth.birdo.app/register"
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-w60 transition hover:text-w80"
                      >
                        Register at birdo.app
                      </a>
                    </p>
                  </motion.div>
                )}
              </AnimatePresence>

              <motion.p
                className="mt-6 text-center text-sm text-w60"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: motionTokens.emphasis, delay: 0.3 }}
              >
                Don&apos;t have an account?{' '}
                <a
                  href="https://auth.birdo.app/register"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-medium text-w100 transition hover:text-w80"
                >
                  Register at birdo.app
                </a>
              </motion.p>
            </>
          )}
        </motion.div>
      </div>
    </div>
  );
}
