'use client';

import React, { useState, useEffect, Suspense, useCallback } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  Smartphone,
  Fingerprint,
  CheckCircle2,
  XCircle,
  Clock,
  Globe,
  Monitor,
  AlertTriangle,
  RotateCcw,
  Lock,
} from 'lucide-react';
import { performWebAuthnAssertion } from '../../lib/webauthnUtils';

interface PushLoginDetails {
  transactionId: string;
  browser: string;
  os: string;
  ipAddress: string;
  requestTime: string;
  state: string;
  expiresAt: number;
  secondsRemaining: number;
}

function ApproveLoginContent() {
  const searchParams = useSearchParams();
  const router = useRouter();

  const tx = searchParams.get('tx') || '';
  const tok = searchParams.get('tok') || '';

  const [isLoading, setIsLoading] = useState(true);
  const [isProcessing, setIsProcessing] = useState(false);
  const [details, setDetails] = useState<PushLoginDetails | null>(null);
  const [secondsLeft, setSecondsLeft] = useState<number | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  // States: 'initial' | 'prompting_biometrics' | 'approved' | 'rejected' | 'expired'
  const [viewState, setViewState] = useState<'initial' | 'prompting_biometrics' | 'approved' | 'rejected' | 'expired'>('initial');

  // Load transaction details on mount
  useEffect(() => {
    if (!tx || !tok) {
      setErrorMessage('Missing transaction ID or authorization token. Please open the link directly from your push notification.');
      setIsLoading(false);
      return;
    }

    let isMounted = true;

    async function fetchDetails() {
      try {
        const res = await fetch(`/api/auth/push-login/details?tx=${encodeURIComponent(tx)}&tok=${encodeURIComponent(tok)}`);
        if (!res.ok) {
          const err = await res.json().catch(() => ({}));
          throw new Error(err.detail || 'Failed to load login request details.');
        }
        const data = await res.json();
        if (!isMounted) return;

        setDetails(data);
        setSecondsLeft(data.secondsRemaining || 120);

        if (data.state === 'REJECTED') {
          setViewState('rejected');
        } else if (data.state === 'AUTHENTICATED' || data.state === 'COMPLETED') {
          setViewState('approved');
        } else if (data.state === 'EXPIRED') {
          setViewState('expired');
        }
      } catch (err: any) {
        if (!isMounted) return;
        setErrorMessage(err.message || 'An error occurred loading the approval request.');
      } finally {
        if (isMounted) setIsLoading(false);
      }
    }

    fetchDetails();

    return () => {
      isMounted = false;
    };
  }, [tx, tok]);

  // Expiration countdown
  useEffect(() => {
    if (secondsLeft === null || secondsLeft <= 0 || viewState === 'approved' || viewState === 'rejected') {
      if (secondsLeft === 0 && viewState === 'initial') {
        setViewState('expired');
      }
      return;
    }

    const interval = setInterval(() => {
      setSecondsLeft((prev) => {
        if (prev === null || prev <= 1) {
          clearInterval(interval);
          setViewState('expired');
          return 0;
        }
        return prev - 1;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [secondsLeft, viewState]);

  // Action: "Yes, it's me" -> Trigger approval intent and Passkey assertion
  const handleApprove = useCallback(async () => {
    if (!tx || !tok || isProcessing) return;

    setIsProcessing(true);
    setErrorMessage(null);
    setViewState('prompting_biometrics');

    try {
      // Step 3A: Record approval intent on server and receive WebAuthn options
      const approveRes = await fetch('/api/auth/push-login/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ transactionId: tx, token: tok }),
      });

      if (!approveRes.ok) {
        const err = await approveRes.json().catch(() => ({}));
        throw new Error(err.detail || 'Server rejected approval request.');
      }

      const approveData = await approveRes.json();
      const options = approveData.webauthnOptions;
      if (!options || !options.challenge) {
        throw new Error('Server did not return valid WebAuthn options.');
      }

      // Step 3B: Invoke platform biometric passkey ceremony
      let assertion;
      try {
        assertion = await performWebAuthnAssertion({
          challenge: options.challenge,
          rpId: options.rpId,
          allowCredentials: options.allowCredentials,
          userVerification: options.userVerification || 'required',
          timeoutMs: options.timeout || 60000,
        });
      } catch (authErr: any) {
        throw new Error(
          authErr.message?.includes('cancelled') || authErr.name === 'NotAllowedError'
            ? 'Passkey biometric verification was cancelled. Please tap "Yes, it\'s me" to try again.'
            : `Biometric passkey error: ${authErr.message || 'Verification failed.'}`
        );
      }

      // Step 3C: Submit assertion to server for cryptographic verification
      const verifyRes = await fetch('/api/auth/push-login/verify-passkey', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          transactionId: tx,
          token: tok,
          credentialId: assertion.id,
          clientDataJSON: assertion.response.clientDataJSON,
          authenticatorData: assertion.response.authenticatorData,
          signature: assertion.response.signature,
          userHandle: assertion.response.userHandle,
        }),
      });

      if (!verifyRes.ok) {
        const err = await verifyRes.json().catch(() => ({}));
        throw new Error(err.detail || 'Passkey signature verification failed on the server.');
      }

      setViewState('approved');
    } catch (err: any) {
      setErrorMessage(err.message || 'Approval and passkey authorization failed.');
      setViewState('initial');
    } finally {
      setIsProcessing(false);
    }
  }, [tx, tok, isProcessing]);

  // Action: "No, it's not me" -> Reject and protect account
  const handleReject = useCallback(async () => {
    if (!tx || !tok || isProcessing) return;

    setIsProcessing(true);
    setErrorMessage(null);

    try {
      const res = await fetch('/api/auth/push-login/reject', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ transactionId: tx, token: tok }),
      });

      if (!res.ok) {
        const err = await res.json().catch(() => ({}));
        throw new Error(err.detail || 'Failed to reject login request.');
      }

      setViewState('rejected');
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to reject login request.');
    } finally {
      setIsProcessing(false);
    }
  }, [tx, tok, isProcessing]);

  // Format seconds countdown
  const formatTimer = (sec: number | null) => {
    if (sec === null || sec < 0) return '0:00';
    const m = Math.floor(sec / 60);
    const s = sec % 60;
    return `${m}:${s < 10 ? '0' : ''}${s}`;
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col justify-center items-center p-4 sm:p-6 font-sans antialiased selection:bg-emerald-500/30">
      <div className="w-full max-w-md bg-slate-900/90 backdrop-blur-xl border border-slate-800 rounded-3xl p-6 sm:p-8 shadow-2xl relative overflow-hidden">
        {/* Top Glow Accent */}
        <div className="absolute top-0 left-0 right-0 h-1 bg-gradient-to-r from-emerald-500 via-teal-400 to-emerald-600" />

        {/* Header / Logo */}
        <div className="flex items-center space-x-3 mb-6">
          <div className="w-10 h-10 rounded-2xl bg-gradient-to-tr from-emerald-600 to-teal-500 flex items-center justify-center shadow-lg shadow-emerald-500/20">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-1.5">
              Sentinel<span className="text-emerald-400">AI</span>
            </h1>
            <p className="text-xs text-slate-400 font-medium">Push-To-Approve Biometric Gateway</p>
          </div>
        </div>

        {/* Loading State */}
        {isLoading && (
          <div className="py-12 flex flex-col items-center justify-center space-y-4">
            <div className="w-12 h-12 border-3 border-emerald-500/20 border-t-emerald-400 rounded-full animate-spin" />
            <p className="text-sm text-slate-400 font-medium">Verifying login request...</p>
          </div>
        )}

        {/* Error Alert */}
        {!isLoading && errorMessage && (
          <div className="mb-6 p-4 rounded-2xl bg-rose-500/10 border border-rose-500/20 flex items-start space-x-3">
            <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="text-xs text-rose-200 leading-relaxed font-medium">
              {errorMessage}
            </div>
          </div>
        )}

        {/* VIEW 1: APPROVED STATE */}
        {!isLoading && viewState === 'approved' && (
          <div className="py-6 flex flex-col items-center text-center space-y-4">
            <div className="w-20 h-20 rounded-full bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
              <ShieldCheck className="w-10 h-10 text-emerald-400 animate-pulse" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Login Authorized</h2>
              <p className="text-sm text-slate-300 mt-1.5 leading-relaxed">
                Biometric passkey confirmed. Your desktop computer session has been securely established.
              </p>
            </div>
            <div className="w-full p-4 rounded-2xl bg-slate-800/50 border border-slate-700/60 text-xs text-slate-400 flex items-center justify-center gap-2 mt-2">
              <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              You may safely close this browser tab.
            </div>
          </div>
        )}

        {/* VIEW 2: REJECTED STATE */}
        {!isLoading && viewState === 'rejected' && (
          <div className="py-6 flex flex-col items-center text-center space-y-4">
            <div className="w-20 h-20 rounded-full bg-rose-500/10 border border-rose-500/30 flex items-center justify-center">
              <ShieldAlert className="w-10 h-10 text-rose-400" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Login Request Blocked</h2>
              <p className="text-sm text-slate-300 mt-1.5 leading-relaxed">
                We prevented access to your account and logged this unauthorized access attempt.
              </p>
            </div>
            <div className="w-full p-4 rounded-2xl bg-rose-500/5 border border-rose-500/20 text-xs text-rose-300 flex items-center justify-center gap-2 mt-2">
              <Lock className="w-4 h-4 text-rose-400" />
              Account credentials remain fully secure.
            </div>
          </div>
        )}

        {/* VIEW 3: EXPIRED STATE */}
        {!isLoading && viewState === 'expired' && (
          <div className="py-6 flex flex-col items-center text-center space-y-4">
            <div className="w-20 h-20 rounded-full bg-amber-500/10 border border-amber-500/30 flex items-center justify-center">
              <Clock className="w-10 h-10 text-amber-400" />
            </div>
            <div>
              <h2 className="text-lg font-bold text-white">Request Expired</h2>
              <p className="text-sm text-slate-300 mt-1.5 leading-relaxed">
                For security, login authorization requests expire after 2 minutes. Please initiate a new login on your computer.
              </p>
            </div>
          </div>
        )}

        {/* VIEW 4: INITIAL APPROVAL REQUEST */}
        {!isLoading && (viewState === 'initial' || viewState === 'prompting_biometrics') && details && (
          <div className="space-y-6">
            <div className="text-center">
              <h2 className="text-lg font-bold text-white">Is this you signing in?</h2>
              <p className="text-xs text-slate-400 mt-1">
                A computer is requesting immediate access to your SentinelAI account.
              </p>
            </div>

            {/* Request Details Metadata Card */}
            <div className="bg-slate-950/60 border border-slate-800 rounded-2xl p-4 space-y-3">
              <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800/80">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <Monitor className="w-3.5 h-3.5 text-slate-500" />
                  Browser & Device
                </span>
                <span className="font-semibold text-slate-200">
                  {details.browser} • {details.os}
                </span>
              </div>

              <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800/80">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <Globe className="w-3.5 h-3.5 text-slate-500" />
                  IP Address
                </span>
                <span className="font-mono text-slate-300">
                  {details.ipAddress || 'Remote Connection'}
                </span>
              </div>

              <div className="flex items-center justify-between text-xs pb-2 border-b border-slate-800/80">
                <span className="text-slate-400 flex items-center gap-1.5">
                  <Clock className="w-3.5 h-3.5 text-slate-500" />
                  Time of Request
                </span>
                <span className="text-slate-300">{details.requestTime}</span>
              </div>

              {/* Countdown Timer */}
              <div className="flex items-center justify-between text-xs pt-1">
                <span className="text-slate-400 font-medium">Expires in</span>
                <span
                  className={`font-mono font-bold px-2 py-0.5 rounded ${
                    secondsLeft !== null && secondsLeft < 30
                      ? 'bg-rose-500/20 text-rose-300 animate-pulse'
                      : 'bg-emerald-500/10 text-emerald-400'
                  }`}
                >
                  {formatTimer(secondsLeft)}
                </span>
              </div>
            </div>

            {/* Prompting Biometrics Active State */}
            {viewState === 'prompting_biometrics' && (
              <div className="p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/30 flex items-center space-x-3 animate-pulse">
                <Fingerprint className="w-6 h-6 text-emerald-400 shrink-0" />
                <div className="text-xs text-emerald-200 font-medium leading-relaxed">
                  Touch your fingerprint sensor or use Face ID on your device to authorize...
                </div>
              </div>
            )}

            {/* Action Buttons */}
            <div className="space-y-3 pt-2">
              <button
                type="button"
                onClick={handleApprove}
                disabled={isProcessing}
                className="w-full py-3.5 px-4 rounded-2xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-semibold text-sm shadow-lg shadow-emerald-500/25 transition-all duration-200 flex items-center justify-center gap-2 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {isProcessing ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                    <span>Verifying Biometric Passkey...</span>
                  </>
                ) : (
                  <>
                    <Fingerprint className="w-4 h-4" />
                    <span>Yes, it&apos;s me (Authorize)</span>
                  </>
                )}
              </button>

              <button
                type="button"
                onClick={handleReject}
                disabled={isProcessing}
                className="w-full py-3 px-4 rounded-2xl bg-slate-800/80 hover:bg-rose-500/20 hover:border-rose-500/40 border border-slate-700/80 text-rose-400 font-medium text-xs transition-all duration-200 flex items-center justify-center gap-2 active:scale-[0.98] disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <XCircle className="w-4 h-4" />
                <span>No, it&apos;s not me (Block Request)</span>
              </button>
            </div>
          </div>
        )}

        {/* Footer */}
        <div className="mt-8 pt-4 border-t border-slate-800/80 text-center text-[11px] text-slate-400">
          Cryptographically protected by FIDO2 WebAuthn & SentinelAI Zero Trust.
        </div>
      </div>
    </div>
  );
}

export default function ApproveLoginPage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center">
          <div className="w-8 h-8 border-2 border-emerald-500/20 border-t-emerald-400 rounded-full animate-spin" />
        </div>
      }
    >
      <ApproveLoginContent />
    </Suspense>
  );
}
