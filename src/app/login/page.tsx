'use client';

import React, { useState, useEffect, Suspense, useCallback } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { useAuth } from '../../context/AuthContext';
import { validateEmail, sanitizeRedirectPath } from '../../lib/authUtils';
import { normalizePhoneNumber, maskPhoneNumber } from '../../lib/phoneUtils';
import {
  Shield,
  Mail,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Lock,
  ExternalLink,
  Info,
  Clock,
  Smartphone,
} from 'lucide-react';
import { InternationalPhoneInput } from '../../components/ui/InternationalPhoneInput';


function LoginFormContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const nextDestination = sanitizeRedirectPath(searchParams.get('next') || '/dashboard');
  const urlError = searchParams.get('error');
  const urlStep = searchParams.get('step');
  const urlTx = searchParams.get('tx');

  const { user, startSentinelAuth, completeSession } = useAuth();

  // Form Fields
  const [email, setEmail] = useState('');
  const [phone, setPhone] = useState('');
  const [emailError, setEmailError] = useState<string | null>(null);
  const [phoneError, setPhoneError] = useState<string | null>(null);
  const [generalError, setGeneralError] = useState<string | null>(() => {
    if (urlError === 'invalid_link' || urlError === 'expired') {
      return 'The sign-in link has expired or has already been used. Please request a new verification link.';
    }
    if (urlError === 'unconfigured') {
      return 'Authentication service is unconfigured. Please check environment variables.';
    }
    if (urlError) {
      return 'Authentication failed. Please verify your details and try again.';
    }
    return null;
  });

  // Flow States: 'input' | 'email_sent' | 'mobile_waiting' | 'completing'
  const [flowStep, setFlowStep] = useState<'input' | 'email_sent' | 'mobile_waiting' | 'completing'>(
    urlStep === 'mobile_waiting' && urlTx ? 'mobile_waiting' : 'input'
  );

  const [activeTx, setActiveTx] = useState<string>(urlTx || '');
  const [isLoading, setIsLoading] = useState(false);
  const [whatsappInfo, setWhatsappInfo] = useState<{
    status: string;
    isConfigured: boolean;
    error?: string;
    mobileVerificationUrl?: string;
  } | null>(null);

  const [showPrivacyModal, setShowPrivacyModal] = useState(false);
  const [showTermsModal, setShowTermsModal] = useState(false);

  // If already authenticated, redirect
  useEffect(() => {
    if (user) {
      router.push(nextDestination);
    }
  }, [user, router, nextDestination]);

  // Handle Initial Form Submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setEmailError(null);
    setPhoneError(null);
    setGeneralError(null);

    const emailVal = validateEmail(email);
    if (!emailVal.isValid) {
      setEmailError(emailVal.error || 'Please enter a valid email address.');
      return;
    }

    const phoneVal = normalizePhoneNumber(phone);
    if (!phoneVal.isValid) {
      setPhoneError(phoneVal.error || 'Please enter a valid mobile number with country code.');
      return;
    }

    setIsLoading(true);

    try {
      const result = await startSentinelAuth(emailVal.normalized, phoneVal.normalized);
      if (!result.success || !result.transactionId) {
        setGeneralError(result.error || 'Failed to start authentication.');
        setIsLoading(false);
        return;
      }

      setActiveTx(result.transactionId);
      setFlowStep('email_sent');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'An unexpected error occurred. Please try again.';
      setGeneralError(msg);
    } finally {
      setIsLoading(false);
    }
  };

  // Cross-Device Polling for Gate 2 Completion
  const pollSessionStatus = useCallback(async () => {
    if (!activeTx) return;

    try {
      const res = await fetch(`/api/auth/status/${encodeURIComponent(activeTx)}`);
      if (!res.ok) return;

      const data = await res.json();
      setWhatsappInfo({
        status: data.whatsappDeliveryStatus || 'unconfigured',
        isConfigured: Boolean(data.whatsappConfigured),
        error: data.whatsappError,
      });

      // When mobile biometric verification passes, finalize session
      if (data.biometricVerified || data.state === 'AUTHENTICATED') {
        setFlowStep('completing');
        const sessionRes = await completeSession(activeTx);
        if (sessionRes.success) {
          router.push(nextDestination);
        } else {
          setGeneralError(sessionRes.error || 'Could not finalize session authorization.');
        }
      }
    } catch (e) {
      console.warn('Status poll exception:', e);
    }
  }, [activeTx, completeSession, nextDestination, router]);

  // Bounded polling loop when on mobile_waiting screen
  useEffect(() => {
    if (flowStep !== 'mobile_waiting' && flowStep !== 'email_sent') return;
    if (!activeTx) return;

    const interval = setInterval(() => {
      pollSessionStatus();
    }, 2500);

    return () => clearInterval(interval);
  }, [flowStep, activeTx, pollSessionStatus]);

  // Manual Trigger to simulate Email Gate (for development test ease)
  const handleSimulateEmailGate = async () => {
    if (!activeTx) return;
    setIsLoading(true);
    try {
      const res = await fetch('/api/auth/confirm-email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          transactionId: activeTx,
          email: email || 'user@sentinel.ai',
        }),
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.detail || 'Email confirmation failed');
      }

      const data = await res.json();
      setWhatsappInfo({
        status: data.whatsappDeliveryStatus || 'unconfigured',
        isConfigured: Boolean(data.whatsappConfigured),
        mobileVerificationUrl: data.mobileVerificationUrl,
      });
      setFlowStep('mobile_waiting');
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to simulate email verification.';
      setGeneralError(msg);
    } finally {
      setIsLoading(false);
    }
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
            Sentinel AI Two-Channel Login
          </h1>
          <p className="text-sm text-zinc-600 dark:text-zinc-400">
            Zero-trust passwordless email & WhatsApp biometric device verification.
          </p>
        </div>

        {/* Global Error Banner */}
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
          {flowStep === 'input' && (
            <form onSubmit={handleSubmit} noValidate className="space-y-4">
              {/* Gate 1: Email Address */}
              <div className="space-y-1.5">
                <label
                  htmlFor="email-input"
                  className="block text-xs font-semibold text-zinc-800 dark:text-zinc-200"
                >
                  Work or Personal Email
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
                    placeholder="you@company.com"
                    disabled={isLoading}
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

              {/* Gate 2: Mobile Number for WhatsApp with Worldwide Country Selector */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="phone-input"
                    className="block text-xs font-semibold text-zinc-800 dark:text-zinc-200"
                  >
                    Mobile Phone Number (WhatsApp)
                  </label>
                  <span className="text-[10px] text-zinc-400">All Countries Supported</span>
                </div>
                <InternationalPhoneInput
                  id="phone-input"
                  value={phone}
                  onChange={(normalizedVal, isValid, err) => {
                    setPhone(normalizedVal);
                    if (phoneError) setPhoneError(err || null);
                  }}
                  disabled={isLoading}
                  error={phoneError}
                />
                <p className="text-[10px] text-zinc-500 dark:text-zinc-400">
                  Select your country code and enter your mobile number. We will send a one-time biometric verification link to your WhatsApp upon email verification.
                </p>
              </div>

              {/* Submit Button */}
              <button
                type="submit"
                disabled={isLoading}
                className="w-full flex items-center justify-center gap-2 rounded-lg bg-zinc-900 dark:bg-white px-4 py-2.5 text-xs font-semibold text-white dark:text-zinc-900 hover:bg-zinc-800 dark:hover:bg-zinc-100 disabled:opacity-50 transition-colors shadow-xs cursor-pointer focus:outline-hidden focus:ring-2 focus:ring-zinc-400"
              >
                {isLoading ? (
                  <>
                    <div className="h-3.5 w-3.5 border-2 border-white dark:border-zinc-900 border-t-transparent rounded-full animate-spin" />
                    <span>Initiating Two-Channel Authentication...</span>
                  </>
                ) : (
                  <>
                    <span>Begin Two-Channel Verification</span>
                    <ArrowRight className="h-3.5 w-3.5" />
                  </>
                )}
              </button>
            </form>
          )}

          {flowStep === 'email_sent' && (
            <div className="space-y-5 text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="h-6 w-6" />
              </div>

              <div className="space-y-1.5">
                <h2 className="text-lg font-bold text-zinc-900 dark:text-zinc-100">
                  Step 1: Check your email
                </h2>
                <p className="text-xs text-zinc-600 dark:text-zinc-400">
                  We dispatched a passwordless sign-in link to:
                </p>
                <p className="text-xs font-mono font-semibold text-zinc-900 dark:text-zinc-100 bg-zinc-100 dark:bg-zinc-800 py-1 px-2.5 rounded-md inline-block max-w-full truncate">
                  {email}
                </p>
              </div>

              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
                Click the link in your email to satisfy Gate 1. Once confirmed, a single-use WhatsApp mobile challenge will automatically be issued to {maskPhoneNumber(phone)}.
              </p>

              {/* Dev Helper to Simulate Gate 1 Callback */}
              <div className="pt-2 p-3 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 text-left space-y-2">
                <div className="flex items-center justify-between text-xs font-semibold text-zinc-800 dark:text-zinc-200">
                  <span className="flex items-center gap-1.5">
                    <Clock className="h-3.5 w-3.5 text-zinc-500" />
                    <span>Awaiting Email Link Click</span>
                  </span>
                  <span className="text-[10px] text-zinc-400">Tx: {activeTx.slice(0, 8)}...</span>
                </div>
                <p className="text-[11px] text-zinc-600 dark:text-zinc-400">
                  In development without SMTP delivery configured, you can confirm Gate 1 directly:
                </p>
                <button
                  type="button"
                  onClick={handleSimulateEmailGate}
                  disabled={isLoading}
                  className="w-full text-center py-1.5 px-3 rounded-md bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 text-xs font-semibold cursor-pointer disabled:opacity-50"
                >
                  {isLoading ? 'Verifying Gate 1...' : 'Confirm Email Gate & Trigger WhatsApp'}
                </button>
              </div>

              <div className="pt-1">
                <button
                  type="button"
                  onClick={() => setFlowStep('input')}
                  className="flex items-center justify-center gap-1.5 text-xs text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200 mx-auto cursor-pointer"
                >
                  <RotateCcw className="h-3.5 w-3.5" />
                  <span>Use different credentials</span>
                </button>
              </div>
            </div>
          )}

          {flowStep === 'mobile_waiting' && (
            <div className="space-y-5 text-center">
              <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-blue-100 dark:bg-blue-950/60 text-blue-600 dark:text-blue-400">
                <Smartphone className="h-6 w-6 animate-pulse" />
              </div>

              <div className="space-y-1.5">
                <div className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-400 text-[10px] font-semibold mb-1">
                  <CheckCircle2 className="h-3 w-3" />
                  <span>Gate 1 Email Verified</span>
                </div>
                <h2 className="text-lg font-bold text-zinc-900 dark:text-zinc-100">
                  Step 2: WhatsApp Mobile Verification
                </h2>
                <p className="text-xs text-zinc-600 dark:text-zinc-400">
                  A secure biometric verification challenge has been issued to:
                </p>
                <p className="text-xs font-mono font-semibold text-zinc-900 dark:text-zinc-100 bg-zinc-100 dark:bg-zinc-800 py-1 px-2.5 rounded-md inline-block">
                  {maskPhoneNumber(phone) || 'Your mobile phone'}
                </p>
              </div>

              {/* WhatsApp Provider Status */}
              {whatsappInfo?.isConfigured ? (
                <div className="p-3.5 rounded-xl border border-emerald-200 dark:border-emerald-900/50 bg-emerald-50 dark:bg-emerald-950/20 text-left text-xs text-emerald-900 dark:text-emerald-300 space-y-1">
                  <p className="font-semibold flex items-center gap-1.5">
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600" />
                    <span>WhatsApp Message Dispatched</span>
                  </p>
                  <p className="text-[11px] text-emerald-800/90 dark:text-emerald-300/80">
                    Open WhatsApp on your mobile phone, tap the link, and complete biometric unlock (Face ID / Touch ID).
                  </p>
                </div>
              ) : (
                <div className="p-3.5 rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 text-left text-xs text-amber-900 dark:text-amber-200 space-y-2">
                  <div className="flex items-start gap-1.5">
                    <Info className="h-4 w-4 text-amber-600 shrink-0 mt-0.5" />
                    <div>
                      <p className="font-semibold">WhatsApp Provider Unconfigured</p>
                      <p className="text-[11px] text-amber-800/90 dark:text-amber-300/80 mt-0.5">
                        Live message delivery requires Twilio (<code className="font-mono">TWILIO_ACCOUNT_SID</code>) or Meta (<code className="font-mono">WHATSAPP_API_TOKEN</code>).
                      </p>
                    </div>
                  </div>
                  {whatsappInfo?.mobileVerificationUrl && (
                    <div className="pt-1">
                      <a
                        href={whatsappInfo.mobileVerificationUrl}
                        target="_blank"
                        rel="noreferrer"
                        className="inline-flex items-center gap-1.5 bg-amber-600 text-white dark:bg-amber-500 dark:text-zinc-950 font-semibold px-3 py-1.5 rounded-md text-xs hover:opacity-90"
                      >
                        <span>Open Mobile WebAuthn Link</span>
                        <ExternalLink className="h-3.5 w-3.5" />
                      </a>
                    </div>
                  )}
                </div>
              )}

              {/* Waiting Indicator & Realtime Pulse */}
              <div className="flex items-center justify-center gap-2 text-xs text-zinc-500 dark:text-zinc-400">
                <div className="h-2 w-2 rounded-full bg-blue-500 animate-ping" />
                <span>Waiting for mobile biometric authorization signal...</span>
              </div>

              <div className="pt-2">
                <button
                  type="button"
                  onClick={() => setFlowStep('input')}
                  className="text-xs text-zinc-400 hover:text-zinc-600 dark:hover:text-zinc-300 cursor-pointer"
                >
                  Cancel and restart
                </button>
              </div>
            </div>
          )}

          {flowStep === 'completing' && (
            <div className="space-y-4 text-center py-6">
              <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-full bg-emerald-100 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="h-8 w-8" />
              </div>
              <div className="space-y-1">
                <h2 className="text-lg font-bold text-zinc-900 dark:text-zinc-100">
                  Two-Channel Authorization Verified!
                </h2>
                <p className="text-xs text-zinc-600 dark:text-zinc-400">
                  Establishing secure authenticated session and navigating to dashboard...
                </p>
              </div>
              <div className="h-5 w-5 border-2 border-zinc-900 dark:border-white border-t-transparent rounded-full animate-spin mx-auto" />
            </div>
          )}

          {/* Privacy Note */}
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
                <span>Sentinel AI Privacy Commitment</span>
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
                <strong>Two-Channel Security:</strong> Sentinel AI enforces two sequential verification channels (Email and WhatsApp Mobile Biometrics) to prevent credential stuffing and account takeover.
              </p>
              <p>
                <strong>Zero Password Exposure:</strong> We never store passwords or bearer tokens on mobile devices. WebAuthn platform authenticators authenticate using public key cryptography.
              </p>
              <p>
                <strong>Zero Advertising Exploitation:</strong> We never monetize, sell, or rent your scanning telemetry to ad networks or third parties.
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
                Sentinel AI provides personal threat analysis and cybersecurity intelligence on an as-is basis. You agree to submit only links, files, and emails that you own or have explicit authorization to inspect.
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
    <Suspense
      fallback={
        <div className="min-h-[calc(100vh-3.5rem)] flex items-center justify-center">
          <div className="h-6 w-6 border-2 border-zinc-900 dark:border-white border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <LoginFormContent />
    </Suspense>
  );
}
