'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuth } from '../../context/AuthContext';
import { validateEmail, sanitizeRedirectPath } from '../../lib/authUtils';
import {
  Shield,
  Mail,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Lock,
  Sparkles,
  Info,
} from 'lucide-react';

function LoginFormContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const nextDestination = sanitizeRedirectPath(searchParams.get('next') || '/dashboard');
  const urlError = searchParams.get('error');

  const {
    user,
    sendMagicLink,
    signInWithGoogle,
    isConfigured,
    completeDemoSignIn,
  } = useAuth();

  const [email, setEmail] = useState('');
  const [emailError, setEmailError] = useState<string | null>(null);
  const [generalError, setGeneralError] = useState<string | null>(() => {
    if (urlError === 'invalid_link' || urlError === 'expired') {
      return 'This sign-in link has expired or has already been used. Please request a new one below.';
    }
    if (urlError) {
      return 'Authentication failed. Please try signing in again.';
    }
    return null;
  });
  const [isLoading, setIsLoading] = useState(false);
  const [isGoogleLoading, setIsGoogleLoading] = useState(false);
  const [magicLinkSent, setMagicLinkSent] = useState(false);
  const [sentEmailAddress, setSentEmailAddress] = useState('');
  const [showConfigHelper, setShowConfigHelper] = useState(false);
  const [showPrivacyModal, setShowPrivacyModal] = useState(false);
  const [showTermsModal, setShowTermsModal] = useState(false);

  // If already authenticated, redirect to destination
  useEffect(() => {
    if (user) {
      router.push(nextDestination);
    }
  }, [user, router, nextDestination]);

  const handleEmailSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setEmailError(null);
    setGeneralError(null);

    const validation = validateEmail(email);
    if (!validation.isValid) {
      setEmailError(validation.error || 'Please enter a valid email address.');
      return;
    }

    setIsLoading(true);

    try {
      const result = await sendMagicLink(validation.normalized);

      if (!result.success) {
        setGeneralError(result.error || 'Failed to send magic link. Please try again.');
        setIsLoading(false);
        return;
      }

      setSentEmailAddress(validation.normalized);
      setMagicLinkSent(true);
    } catch (err: unknown) {
      setGeneralError(err instanceof Error ? err.message : 'An unexpected error occurred. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleGoogleSignIn = async () => {
    setGeneralError(null);
    setIsGoogleLoading(true);

    if (!isConfigured) {
      setShowConfigHelper(true);
      setGeneralError('Google OAuth requires Supabase project credentials in .env.local.');
      setIsGoogleLoading(false);
      return;
    }

    try {
      const result = await signInWithGoogle();
      if (!result.success) {
        setGeneralError(result.error || 'Failed to initialize Google Sign-In.');
      }
    } catch (err: unknown) {
      setGeneralError(err instanceof Error ? err.message : 'Failed to initialize Google Sign-In.');
    } finally {
      setIsGoogleLoading(false);
    }
  };

  const handleSimulatedDemoSignIn = async () => {
    const targetEmail = sentEmailAddress || email || 'alex.vance@example.com';
    setIsLoading(true);
    await completeDemoSignIn(targetEmail);
    router.push('/onboarding');
  };

  return (
    <div className="min-h-[calc(100vh-3.5rem)] flex items-center justify-center p-4 sm:p-6 lg:p-8">
      <div className="w-full max-w-md space-y-6">
        {/* Brand Header */}
        <div className="text-center space-y-2">
          <div className="inline-flex h-12 w-12 items-center justify-center rounded-xl bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 shadow-sm mb-2">
            <Shield className="h-6 w-6" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-900 dark:text-zinc-100">
            Your security starts here.
          </h1>
          <p className="text-sm text-zinc-600 dark:text-zinc-400">
            Sign in to Cyclops without creating another password.
          </p>
        </div>

        {/* Unconfigured Provider Banner */}
        {!isConfigured && (
          <div className="rounded-xl border border-amber-300 dark:border-amber-800/60 bg-amber-50 dark:bg-amber-950/30 p-3.5 text-xs text-amber-900 dark:text-amber-200 space-y-2">
            <div className="flex items-start gap-2">
              <Info className="h-4 w-4 text-amber-600 dark:text-amber-400 shrink-0 mt-0.5" />
              <div>
                <p className="font-semibold">Supabase Provider Configuration Required</p>
                <p className="text-[11px] text-amber-800/90 dark:text-amber-300/80 mt-0.5">
                  To send live email magic links and use real Google OAuth, set your Supabase keys in <code className="font-mono bg-amber-100 dark:bg-amber-900/60 px-1 py-0.5 rounded">.env.local</code>.
                </p>
              </div>
            </div>
            <div className="pt-1 flex items-center justify-between text-[11px]">
              <button
                type="button"
                onClick={() => setShowConfigHelper(!showConfigHelper)}
                className="underline font-semibold hover:text-amber-950 dark:hover:text-amber-100 cursor-pointer"
              >
                {showConfigHelper ? 'Hide instructions' : 'View setup variables'}
              </button>
              <button
                type="button"
                onClick={handleSimulatedDemoSignIn}
                className="font-semibold bg-amber-600 text-white hover:bg-amber-700 dark:bg-amber-500 dark:hover:bg-amber-400 dark:text-zinc-950 px-2.5 py-1 rounded-md transition-colors cursor-pointer"
              >
                Try Demo Sign-In
              </button>
            </div>

            {showConfigHelper && (
              <div className="mt-2 p-2.5 rounded-lg bg-white/70 dark:bg-zinc-900/90 border border-amber-200 dark:border-amber-800 font-mono text-[10px] space-y-1 overflow-x-auto text-zinc-800 dark:text-zinc-200">
                <p className="text-zinc-500 dark:text-zinc-400"># Add to .env.local in repository root:</p>
                <p>NEXT_PUBLIC_SUPABASE_URL=https://your-project.supabase.co</p>
                <p>NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJh...</p>
                <p className="text-zinc-500 dark:text-zinc-400 pt-1"># Callback URL to add in Supabase Auth Settings:</p>
                <p>http://localhost:3000/auth/callback</p>
              </div>
            )}
          </div>
        )}

        {/* Global Error Alert */}
        {generalError && (
          <div
            role="alert"
            className="flex items-start gap-2.5 rounded-xl border border-red-200 dark:border-red-900/50 bg-red-50 dark:bg-red-950/30 p-3.5 text-xs text-red-800 dark:text-red-300"
          >
            <AlertTriangle className="h-4 w-4 shrink-0 text-red-600 dark:text-red-400 mt-0.5" />
            <p className="leading-relaxed">{generalError}</p>
          </div>
        )}

        {/* Main Card */}
        <div className="rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 sm:p-8 shadow-sm space-y-6">
          {!magicLinkSent ? (
            <>
              {/* Email Form */}
              <form onSubmit={handleEmailSubmit} noValidate className="space-y-4">
                <div className="space-y-1.5">
                  <label
                    htmlFor="email-input"
                    className="block text-xs font-semibold text-zinc-800 dark:text-zinc-200"
                  >
                    Email address
                  </label>
                  <div className="relative">
                    <div className="pointer-events-none absolute inset-y-0 left-0 flex items-center pl-3">
                      <Mail className="h-4 w-4 text-zinc-400" />
                    </div>
                    <input
                      id="email-input"
                      type="email"
                      autoComplete="email"
                      value={email}
                      onChange={(e) => {
                        setEmail(e.target.value);
                        if (emailError) setEmailError(null);
                      }}
                      placeholder="you@example.com"
                      disabled={isLoading || isGoogleLoading}
                      className={`block w-full rounded-lg border pl-9 pr-3 py-2.5 text-xs text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-hidden focus:ring-2 transition-colors ${
                        emailError
                          ? 'border-red-400 focus:border-red-500 focus:ring-red-200 dark:focus:ring-red-900/40 bg-red-50/20'
                          : 'border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 focus:border-zinc-900 dark:focus:border-zinc-100 focus:ring-zinc-200 dark:focus:ring-zinc-800'
                      }`}
                    />
                  </div>
                  {emailError && (
                    <p className="text-[11px] font-medium text-red-600 dark:text-red-400" role="alert">
                      {emailError}
                    </p>
                  )}
                </div>

                <button
                  type="submit"
                  disabled={isLoading || isGoogleLoading}
                  className="w-full flex items-center justify-center gap-2 rounded-lg bg-zinc-900 dark:bg-white px-4 py-2.5 text-xs font-semibold text-white dark:text-zinc-900 hover:bg-zinc-800 dark:hover:bg-zinc-100 disabled:opacity-50 transition-colors shadow-xs cursor-pointer focus:outline-hidden focus:ring-2 focus:ring-zinc-400"
                >
                  {isLoading ? (
                    <>
                      <div className="h-3.5 w-3.5 border-2 border-white dark:border-zinc-900 border-t-transparent rounded-full animate-spin" />
                      <span>Sending sign-in link...</span>
                    </>
                  ) : (
                    <>
                      <span>Continue with email</span>
                      <ArrowRight className="h-3.5 w-3.5" />
                    </>
                  )}
                </button>
              </form>

              {/* Divider */}
              <div className="relative flex items-center justify-center">
                <div className="w-full border-t border-zinc-200 dark:border-zinc-800" />
                <span className="relative bg-white dark:bg-zinc-900 px-3 text-[11px] uppercase tracking-wider text-zinc-400">
                  or
                </span>
              </div>

              {/* Google OAuth Button */}
              <button
                type="button"
                onClick={handleGoogleSignIn}
                disabled={isLoading || isGoogleLoading}
                className="w-full flex items-center justify-center gap-2.5 rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 hover:bg-zinc-50 dark:hover:bg-zinc-900 text-zinc-800 dark:text-zinc-200 px-4 py-2.5 text-xs font-semibold transition-colors disabled:opacity-50 cursor-pointer focus:outline-hidden focus:ring-2 focus:ring-zinc-300 dark:focus:ring-zinc-700"
              >
                {isGoogleLoading ? (
                  <>
                    <div className="h-3.5 w-3.5 border-2 border-zinc-900 dark:border-white border-t-transparent rounded-full animate-spin" />
                    <span>Connecting to Google...</span>
                  </>
                ) : (
                  <>
                    <svg className="h-4 w-4" viewBox="0 0 24 24">
                      <path
                        fill="#4285F4"
                        d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                      />
                      <path
                        fill="#34A853"
                        d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                      />
                      <path
                        fill="#FBBC05"
                        d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                      />
                      <path
                        fill="#EA4335"
                        d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                      />
                    </svg>
                    <span>Continue with Google</span>
                  </>
                )}
              </button>
            </>
          ) : (
            /* Magic Link Confirmation Screen */
            <div className="space-y-5 text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="h-6 w-6" />
              </div>

              <div className="space-y-1.5">
                <h2 className="text-lg font-bold text-zinc-900 dark:text-zinc-100">
                  Check your email
                </h2>
                <p className="text-xs text-zinc-600 dark:text-zinc-400">
                  We sent a temporary sign-in link to:
                </p>
                <p className="text-xs font-mono font-semibold text-zinc-900 dark:text-zinc-100 bg-zinc-100 dark:bg-zinc-800 py-1 px-2 rounded-md inline-block max-w-full truncate">
                  {sentEmailAddress}
                </p>
              </div>

              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
                Click the link in the message to sign in instantly. The link expires in 10 minutes and can only be used once.
              </p>

              {!isConfigured && (
                <div className="p-3 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 text-left space-y-2">
                  <p className="text-xs font-semibold text-zinc-800 dark:text-zinc-200 flex items-center gap-1.5">
                    <Sparkles className="h-3.5 w-3.5 text-amber-500" />
                    <span>Demo Mode Preview</span>
                  </p>
                  <p className="text-[11px] text-zinc-600 dark:text-zinc-400">
                    Live email sending requires Supabase SMTP. For testing right now, you can proceed directly into onboarding.
                  </p>
                  <button
                    type="button"
                    onClick={handleSimulatedDemoSignIn}
                    className="w-full text-center py-1.5 px-3 rounded-md bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 text-xs font-semibold cursor-pointer"
                  >
                    Simulate Link Click & Enter Onboarding
                  </button>
                </div>
              )}

              <div className="pt-2 flex flex-col gap-2">
                <button
                  type="button"
                  onClick={() => setMagicLinkSent(false)}
                  className="flex items-center justify-center gap-1.5 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100 cursor-pointer"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  <span>Use a different email address</span>
                </button>
              </div>
            </div>
          )}

          {/* Privacy Note Required by Spec */}
          <div className="border-t border-zinc-100 dark:border-zinc-800/80 pt-4 text-center">
            <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
              We don&apos;t use your security scans for advertising. See our{' '}
              <button
                type="button"
                onClick={() => setShowPrivacyModal(true)}
                className="underline hover:text-zinc-800 dark:hover:text-zinc-200 cursor-pointer font-medium"
              >
                Privacy Policy
              </button>{' '}
              to learn how your data is handled.
            </p>
          </div>
        </div>

        {/* Footer Links */}
        <div className="text-center text-xs text-zinc-400 space-x-4">
          <button
            type="button"
            onClick={() => setShowPrivacyModal(true)}
            className="hover:text-zinc-600 dark:hover:text-zinc-300 underline"
          >
            Privacy Policy
          </button>
          <span>•</span>
          <button
            type="button"
            onClick={() => setShowTermsModal(true)}
            className="hover:text-zinc-600 dark:hover:text-zinc-300 underline"
          >
            Terms of Service
          </button>
        </div>
      </div>

      {/* Privacy Policy Modal */}
      {showPrivacyModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-lg rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 space-y-4 shadow-xl max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-zinc-100 dark:border-zinc-800 pb-3">
              <h3 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
                <Shield className="h-4 w-4" />
                <span>Cyclops Privacy Commitment</span>
              </h3>
              <button
                type="button"
                onClick={() => setShowPrivacyModal(false)}
                className="text-xs text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100 cursor-pointer p-1"
              >
                ✕ Close
              </button>
            </div>
            <div className="text-xs text-zinc-600 dark:text-zinc-400 space-y-3 leading-relaxed">
              <p>
                <strong>Zero Advertising Exploitation:</strong> We never sell, rent, or monetize your scan queries, uploaded files, or email contents to ad networks, data brokers, or marketing partners.
              </p>
              <p>
                <strong>Ephemeral File Inspection:</strong> Document files uploaded for static security analysis are parsed in-memory and are not retained on disk or used to train artificial intelligence models.
              </p>
              <p>
                <strong>Passwordless Identity:</strong> We never ask for or store user passwords. Authentication is handled exclusively via one-time cryptographically secure magic links or verified Google OAuth.
              </p>
              <p>
                <strong>Complete Data Erasure:</strong> When you delete your account in Settings, your session tokens and profile information are permanently erased.
              </p>
            </div>
            <div className="pt-2 text-right">
              <button
                type="button"
                onClick={() => setShowPrivacyModal(false)}
                className="px-4 py-2 rounded-lg bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 text-xs font-semibold cursor-pointer"
              >
                Understood
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Terms Modal */}
      {showTermsModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/60 backdrop-blur-xs">
          <div className="w-full max-w-lg rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 space-y-4 shadow-xl max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-zinc-100 dark:border-zinc-800 pb-3">
              <h3 className="text-sm font-bold text-zinc-900 dark:text-zinc-100 flex items-center gap-2">
                <Lock className="h-4 w-4" />
                <span>Terms of Service</span>
              </h3>
              <button
                type="button"
                onClick={() => setShowTermsModal(false)}
                className="text-xs text-zinc-500 hover:text-zinc-900 dark:hover:text-zinc-100 cursor-pointer p-1"
              >
                ✕ Close
              </button>
            </div>
            <div className="text-xs text-zinc-600 dark:text-zinc-400 space-y-3 leading-relaxed">
              <p>
                Cyclops provides personal threat analysis and online safety intelligence on an as-is basis. You agree to submit only links, files, and emails that you own or have explicit authorization to inspect.
              </p>
              <p>
                Security findings represent automated static indicators and threat intelligence heuristics; they do not constitute guaranteed safety or legal certifications.
              </p>
            </div>
            <div className="pt-2 text-right">
              <button
                type="button"
                onClick={() => setShowTermsModal(false)}
                className="px-4 py-2 rounded-lg bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 text-xs font-semibold cursor-pointer"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={
      <div className="min-h-[calc(100vh-3.5rem)] flex items-center justify-center">
        <div className="h-6 w-6 border-2 border-zinc-900 dark:border-white border-t-transparent rounded-full animate-spin" />
      </div>
    }>
      <LoginFormContent />
    </Suspense>
  );
}
