import { useState } from 'react';
import { invoke } from '@tauri-apps/api/core';
import { open } from '@tauri-apps/plugin-shell';
import { useAppStore } from '@/store/app-store';
import { Eye, EyeOff, Loader2, ShieldCheck, UserRound, KeyRound } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

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

export function Login() {
  const [activeTab, setActiveTab] = useState<AuthTab>('email');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  // 2FA challenge state
  const [twoFactorRequired, setTwoFactorRequired] = useState(false);
  const [challengeToken, setChallengeToken] = useState<string | null>(null);
  const [totpCode, setTotpCode] = useState('');

  // Anonymous login state
  const [anonId, setAnonId] = useState('');
  const [anonPassword, setAnonPassword] = useState('');
  const [showAnonPassword, setShowAnonPassword] = useState(false);

  const { setAuthenticated, setUserEmail } = useAppStore();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const result = await invoke<{
        success: boolean;
        message?: string;
        error?: string;
        requires_two_factor?: boolean;
        challenge_token?: string;
        user?: { email?: string; account_id?: string; is_anonymous?: boolean };
      }>('login', { request: { email, password } });

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
      // Login with existing anonymous ID (formatted as email: XXXX@anon.birdo.app)
      const anonEmail = `${anonId.replace(/\D/g, '')}@anon.birdo.app`;
      const result = await invoke<{
        success: boolean;
        message?: string;
        error?: string;
        requires_two_factor?: boolean;
        challenge_token?: string;
        user?: { email?: string; account_id?: string; is_anonymous?: boolean };
      }>('login', { request: { email: anonEmail, password: anonPassword || anonId.replace(/\D/g, '') } });

      if (result.requires_two_factor && result.challenge_token) {
        setTwoFactorRequired(true);
        setChallengeToken(result.challenge_token);
      } else if (result.success) {
        setUserEmail(result.user?.email || anonEmail);
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
      await open('https://birdo.app/reset-password');
    } catch {
      setError('Failed to open browser');
    }
  };

  const handleVerify2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const result = await invoke<{
        success: boolean;
        email?: string;
        error?: string;
        user?: { email?: string };
      }>('verify_2fa', {
        challengeToken: challengeToken,
        code: totpCode,
      });

      if (result.success) {
        setUserEmail(result.user?.email || email);
        setPassword('');
        setAuthenticated(true);
      } else {
        setError(result.error || 'Verification failed');
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

  const tabs: { id: AuthTab; label: string; icon: React.ReactNode }[] = [
    { id: 'email', label: 'Email', icon: <KeyRound size={14} /> },
    { id: 'anonymous', label: 'Anonymous', icon: <UserRound size={14} /> },
  ];

  return (
    <div className="flex h-full flex-col">
      {/* Header with drag region */}
      <div
        data-tauri-drag-region
        className="flex h-12 items-center justify-center border-b border-white/5 glass-strong"
      >
        <span className="text-lg font-semibold text-white">
          Birdo VPN
        </span>
      </div>

      {/* Login form */}
      <div className="flex flex-1 flex-col items-center justify-center px-8">
        <motion.div
          className="w-full max-w-sm"
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          {/* Status badge */}
          <motion.div 
            className="mb-6 flex justify-center"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
          >
            <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-4 py-1.5 text-sm text-white backdrop-blur-md">
              <span className="relative flex h-2 w-2">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-white opacity-75"></span>
                <span className="relative inline-flex h-2 w-2 rounded-full bg-white"></span>
              </span>
              Secure Connection
            </div>
          </motion.div>

          <motion.h2 
            className="mb-2 text-center text-3xl font-bold text-gradient"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.15 }}
          >
            {twoFactorRequired ? 'Two-Factor Auth' : 'Welcome'}
          </motion.h2>
          
          <motion.p 
            className="mb-6 text-center text-sm text-white/50"
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
          >
            {twoFactorRequired ? 'Enter your authenticator code' : 'Sign in to access the sovereign network'}
          </motion.p>

          {twoFactorRequired ? (
            /* ── 2FA Verification Form ── */
            <motion.form
              onSubmit={handleVerify2FA}
              className="space-y-4"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
            >
              <div className="flex justify-center mb-2">
                <div className="rounded-full bg-white/5 border border-white/10 p-3">
                  <ShieldCheck className="h-6 w-6 text-white/70" />
                </div>
              </div>

              <div>
                <label htmlFor="totp" className="mb-1.5 block text-sm font-medium text-white/60">
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
                  className="w-full rounded-xl glass-input px-4 py-3 text-white text-center text-2xl tracking-[0.3em] placeholder-white/30 outline-none"
                  autoFocus
                />
                <p className="mt-2 text-xs text-white/40 text-center">
                  Enter the 6-digit code from your authenticator app
                </p>
              </div>

              {error && (
                <motion.div
                  className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400"
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                >
                  {error}
                </motion.div>
              )}

              <motion.button
                type="submit"
                disabled={isLoading || totpCode.length !== 6}
                className="btn-primary w-full rounded-lg px-4 py-3.5 font-semibold disabled:cursor-not-allowed disabled:opacity-50"
                whileHover={{ scale: 1.02 }}
                whileTap={{ scale: 0.98 }}
              >
                {isLoading ? (
                  <span className="flex items-center justify-center gap-2">
                    <Loader2 className="h-5 w-5 animate-spin" />
                    Verifying...
                  </span>
                ) : (
                  'Verify'
                )}
              </motion.button>

              <button
                type="button"
                onClick={handleBack}
                className="w-full text-center text-sm text-white/50 hover:text-white/70 transition"
              >
                ← Back to login
              </button>
            </motion.form>
          ) : (
          <>
            {/* ── Auth Method Tabs ── */}
            <motion.div
              className="mb-5 flex rounded-xl glass-strong p-1 gap-1"
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.22 }}
            >
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => { setActiveTab(tab.id); setError(null); }}
                  className={`flex-1 flex items-center justify-center gap-1.5 rounded-lg py-2 text-xs font-medium transition-all ${
                    activeTab === tab.id
                      ? 'bg-white/10 text-white'
                      : 'text-white/40 hover:text-white/60'
                  }`}
                >
                  {tab.icon}
                  {tab.label}
                </button>
              ))}
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
                  transition={{ duration: 0.2 }}
                >
                  <div>
                    <label htmlFor="email" className="mb-1.5 block text-sm font-medium text-white/60">
                      Email
                    </label>
                    <input
                      id="email"
                      type="email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      placeholder="you@example.com"
                      required
                      className="w-full rounded-xl glass-input px-4 py-3 text-white placeholder-white/30 outline-none"
                    />
                  </div>

                  <div>
                    <div className="mb-1.5 flex items-center justify-between">
                      <label htmlFor="password" className="text-sm font-medium text-white/60">
                        Password
                      </label>
                      <button
                        type="button"
                        onClick={handleForgotPassword}
                        className="text-xs text-white/40 hover:text-white/70 transition"
                      >
                        Forgot password?
                      </button>
                    </div>
                    <div className="relative">
                      <input
                        id="password"
                        type={showPassword ? 'text' : 'password'}
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        placeholder="••••••••"
                        required
                        className="w-full rounded-xl glass-input px-4 py-3 pr-10 text-white placeholder-white/30 outline-none"
                      />
                      <button
                        type="button"
                        onClick={() => setShowPassword(!showPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-white/40 transition hover:text-white"
                      >
                        {showPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                      </button>
                    </div>
                  </div>

                  {error && (
                    <motion.div 
                      className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400"
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                    >
                      {error}
                    </motion.div>
                  )}

                  <motion.button
                    type="submit"
                    disabled={isLoading}
                    className="btn-primary w-full rounded-lg px-4 py-3.5 font-semibold disabled:cursor-not-allowed disabled:opacity-50"
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    {isLoading ? (
                      <span className="flex items-center justify-center gap-2">
                        <Loader2 className="h-5 w-5 animate-spin" />
                        Connecting...
                      </span>
                    ) : (
                      'Sign In'
                    )}
                  </motion.button>
                </motion.form>
              )}

              {activeTab === 'anonymous' && (
                <motion.div
                  key="anon-form"
                  className="space-y-4"
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: 10 }}
                  transition={{ duration: 0.2 }}
                >
                  <div>
                    <label htmlFor="anonId" className="mb-1.5 block text-sm font-medium text-white/60">
                      Anonymous ID
                    </label>
                    <input
                      id="anonId"
                      type="text"
                      inputMode="numeric"
                      value={anonId}
                      onChange={(e) => setAnonId(e.target.value.replace(/[^\d-]/g, '').slice(0, 29))}
                      placeholder="000000-000000-000000-000000"
                      required
                      className="w-full rounded-xl glass-input px-4 py-3 text-white tracking-wider font-mono placeholder-white/30 outline-none"
                    />
                    <p className="mt-1 text-xs text-white/30">
                      Enter the 24-digit ID from your anonymous account
                    </p>
                  </div>

                  <div>
                    <div className="mb-1.5 flex items-center justify-between">
                      <label htmlFor="anonPassword" className="text-sm font-medium text-white/60">
                        Password <span className="text-white/30">(optional)</span>
                      </label>
                    </div>
                    <div className="relative">
                      <input
                        id="anonPassword"
                        type={showAnonPassword ? 'text' : 'password'}
                        value={anonPassword}
                        onChange={(e) => setAnonPassword(e.target.value)}
                        placeholder="Leave empty if not set"
                        className="w-full rounded-xl glass-input px-4 py-3 pr-10 text-white placeholder-white/30 outline-none"
                      />
                      <button
                        type="button"
                        onClick={() => setShowAnonPassword(!showAnonPassword)}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-white/40 transition hover:text-white"
                      >
                        {showAnonPassword ? <EyeOff size={18} /> : <Eye size={18} />}
                      </button>
                    </div>
                  </div>

                  {error && (
                    <motion.div 
                      className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400"
                      initial={{ opacity: 0, scale: 0.95 }}
                      animate={{ opacity: 1, scale: 1 }}
                    >
                      {error}
                    </motion.div>
                  )}

                  <motion.button
                    type="button"
                    onClick={handleAnonymousLogin}
                    disabled={isLoading || anonId.replace(/\D/g, '').length < 24}
                    className="btn-primary w-full rounded-lg px-4 py-3.5 font-semibold disabled:cursor-not-allowed disabled:opacity-50"
                    whileHover={{ scale: 1.02 }}
                    whileTap={{ scale: 0.98 }}
                  >
                    {isLoading ? (
                      <span className="flex items-center justify-center gap-2">
                        <Loader2 className="h-5 w-5 animate-spin" />
                        Signing in...
                      </span>
                    ) : (
                      'Sign In with ID'
                    )}
                  </motion.button>

                  <p className="text-center text-xs text-white/40">
                    Don't have an anonymous ID?{' '}
                    <a
                      href="https://birdo.app/register"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-white/60 hover:text-white/80 transition"
                    >
                      Register at birdo.app
                    </a>
                  </p>
                </motion.div>
              )}

            </AnimatePresence>

            <motion.p 
              className="mt-6 text-center text-sm text-white/60"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.5, delay: 0.3 }}
            >
              Don't have an account?{' '}
              <a
                href="https://birdo.app/register"
                target="_blank"
                rel="noopener noreferrer"
                className="font-medium text-white transition hover:text-white/80"
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
