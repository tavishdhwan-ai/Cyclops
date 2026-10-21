'use client';

import React, { useState, useEffect, Suspense } from 'react';
import { useSearchParams, useRouter } from 'next/navigation';
import {
  Smartphone,
  Fingerprint,
  CheckCircle2,
  AlertTriangle,
  RotateCcw,
  Lock,
} from 'lucide-react';
import { detectDeviceContext } from '../../lib/deviceDetection';
import { checkWebAuthnSupport, performWebAuthnAssertion } from '../../lib/webauthnUtils';

function VerifyMobileContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const token = searchParams.get('t') || searchParams.get('token') || '';

  const [deviceContext] = useState<ReturnType<typeof detectDeviceContext> | null>(() => {
    if (typeof window !== 'undefined') {
      return detectDeviceContext(navigator.userAgent);
    }
    return null;
  });
  const [webAuthnSupport, setWebAuthnSupport] = useState<{
    isSupported: boolean;
    hasPlatformAuthenticator: boolean;
    isWhatsAppInAppBrowser: boolean;
  } | null>(null);

  const [isLoading, setIsLoading] = useState(!token ? false : true);
  const [isVerifying, setIsVerifying] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(
    !token ? 'Missing verification token. Please open the link directly from your WhatsApp message.' : null
  );
  const [isSuccess, setIsSuccess] = useState(false);
  const [challengeData, setChallengeData] = useState<{
    webauthnChallenge?: string;
    rpId?: string;
    transactionId?: string;
  } | null>(null);

  // 1. Initial Device & Challenge Check
  useEffect(() => {
    if (typeof window === 'undefined' || !token) return;

    // Inspect challenge with server
    fetch(`/api/auth/mobile-challenge?t=${encodeURIComponent(token)}`, {
      headers: {
        'User-Agent': navigator.userAgent,
      },
    })
      .then(async (res) => {
        if (!res.ok) {
          const errData = await res.json().catch(() => ({}));
          throw new Error(errData.detail || 'Invalid or expired verification challenge.');
        }
        return res.json();
      })
      .then(async (data) => {
        if (data.desktopDenied) {
          // Desktop access detected
          setIsLoading(false);
          return;
        }

        setChallengeData(data);
        const support = await checkWebAuthnSupport();
        setWebAuthnSupport(support);
        setIsLoading(false);
      })
      .catch((err) => {
        setErrorMessage(err.message || 'Failed to validate verification challenge.');
        setIsLoading(false);
      });
  }, [token]);

  // 2. Perform WebAuthn Ceremony
  const handleAuthenticate = async () => {
    if (!token || !challengeData?.webauthnChallenge) {
      setErrorMessage('Verification challenge unavailable.');
      return;
    }

    setIsVerifying(true);
    setErrorMessage(null);

    try {
      // Invoke platform authenticator (Face ID / Touch ID / Android Biometrics)
      const assertion = await performWebAuthnAssertion({
        challenge: challengeData.webauthnChallenge,
        rpId: challengeData.rpId || window.location.hostname,
        userVerification: 'required',
      });

      // Submit assertion to server
      const verifyRes = await fetch('/api/auth/webauthn/verify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          mobileToken: token,
          credentialId: assertion.id,
          clientDataJSON: assertion.response.clientDataJSON,
          authenticatorData: assertion.response.authenticatorData,
          signature: assertion.response.signature,
        }),
      });

      if (!verifyRes.ok) {
        const errorJson = await verifyRes.json().catch(() => ({}));
        throw new Error(errorJson.detail || 'Server-side WebAuthn validation failed.');
      }

      setIsSuccess(true);
    } catch (err: unknown) {
      console.error('WebAuthn ceremony error:', err);
      const msg = err instanceof Error ? err.message : 'Biometric authentication was cancelled or could not be completed.';
      setErrorMessage(msg);
    } finally {
      setIsVerifying(false);
    }
  };

  // 3. Desktop Access Denied Experience
  if (deviceContext?.isDesktop) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 sm:p-6 bg-zinc-50 dark:bg-zinc-950">
        <div className="w-full max-w-md rounded-2xl border border-red-200 dark:border-red-900/60 bg-white dark:bg-zinc-900 p-6 sm:p-8 shadow-sm text-center space-y-6">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-red-100 dark:bg-red-950/60 text-red-600 dark:text-red-400">
            <Smartphone className="h-7 w-7" />
          </div>

          <div className="space-y-2">
            <h1 className="text-xl font-bold tracking-tight text-zinc-900 dark:text-zinc-100">
              Access Denied: Mobile Verification Required.
            </h1>
            <p className="text-xs text-zinc-600 dark:text-zinc-400 leading-relaxed">
              This verification link can only be authorized from a registered mobile device (iOS or Android) equipped with platform biometrics.
            </p>
          </div>

          <div className="rounded-xl bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 p-3.5 text-left text-xs space-y-2">
            <p className="font-semibold text-zinc-800 dark:text-zinc-200 flex items-center gap-1.5">
              <Lock className="h-3.5 w-3.5 text-zinc-500" />
              <span>Next Steps:</span>
            </p>
            <ol className="list-decimal list-inside text-zinc-600 dark:text-zinc-400 space-y-1 text-[11px] leading-relaxed">
              <li>Open this page on your registered mobile phone browser.</li>
              <li>Or tap the push notification received on your mobile device.</li>
              <li>Authorize the pending desktop sign-in using your device biometric sensor.</li>
            </ol>
            <p className="text-[10px] text-zinc-400 dark:text-zinc-500 pt-1 italic">
              Notice: Device-class detection is enforced alongside server-side cryptographic challenge verification.
            </p>
          </div>

          <div className="pt-2">
            <button
              type="button"
              onClick={() => router.push('/login')}
              className="w-full flex items-center justify-center gap-2 rounded-lg bg-zinc-900 dark:bg-white text-white dark:text-zinc-900 py-2.5 px-4 text-xs font-semibold hover:opacity-90 transition-opacity cursor-pointer"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              <span>Return to Sentinel AI Login</span>
            </button>
          </div>
        </div>
      </div>
    );
  }

  // 4. Loading State
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 bg-zinc-50 dark:bg-zinc-950">
        <div className="text-center space-y-3">
          <div className="h-8 w-8 border-2 border-zinc-900 dark:border-white border-t-transparent rounded-full animate-spin mx-auto" />
          <p className="text-xs text-zinc-600 dark:text-zinc-400 font-medium">
            Verifying mobile security challenge...
          </p>
        </div>
      </div>
    );
  }

  // 5. Success State
  if (isSuccess) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 bg-zinc-50 dark:bg-zinc-950">
        <div className="w-full max-w-sm rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 sm:p-8 shadow-sm text-center space-y-5">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-emerald-100 dark:bg-emerald-950/60 text-emerald-600 dark:text-emerald-400">
            <CheckCircle2 className="h-7 w-7" />
          </div>

          <div className="space-y-1.5">
            <h2 className="text-lg font-bold text-zinc-900 dark:text-zinc-100">
              Session Authorized Successfully
            </h2>
            <p className="text-xs text-zinc-600 dark:text-zinc-400 leading-relaxed">
              Biometric authorization has been validated by Sentinel AI.
            </p>
          </div>

          <div className="rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/50 p-3.5 text-xs text-emerald-900 dark:text-emerald-300">
            <p className="font-semibold">Return to Your Desktop</p>
            <p className="text-[11px] text-emerald-800/90 dark:text-emerald-300/80 mt-1">
              Your desktop browser has received the authorization confirmation and unlocked your secure dashboard. You may safely close this tab.
            </p>
          </div>
        </div>
      </div>
    );
  }

  // 6. Mobile WebAuthn Interaction Screen
  return (
    <div className="min-h-screen flex items-center justify-center p-4 sm:p-6 bg-zinc-50 dark:bg-zinc-950">
      <div className="w-full max-w-sm rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 sm:p-8 shadow-sm text-center space-y-6">
        {/* Biometric Scanner Visual Illustration */}
        <div className="relative mx-auto flex h-20 w-20 items-center justify-center rounded-3xl bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 shadow-md">
          <div className="absolute inset-0 rounded-3xl bg-blue-500/20 animate-ping opacity-30" />
          <Fingerprint className="h-10 w-10 relative z-10" />
        </div>

        {/* Required Prominent Instruction */}
        <div className="space-y-2">
          <h1 className="text-base font-bold text-zinc-900 dark:text-zinc-100 leading-snug">
            Place your Index Finger on the scanner to authorize this session.
          </h1>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
            Your device will prompt for biometric verification (Fingerprint, Face ID, or Screen Lock) to authorize the pending desktop login.
          </p>
        </div>

        {/* Requesting Session Context */}
        <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 p-3.5 text-left text-xs space-y-2">
          <div className="flex items-center justify-between text-zinc-700 dark:text-zinc-300 font-semibold text-[11px]">
            <span>Request Details</span>
            <span className="font-mono text-[10px] text-zinc-400">
              Tx: {(challengeData?.transactionId || token).slice(0, 8)}...
            </span>
          </div>
          <div className="space-y-1 text-[11px] text-zinc-500 dark:text-zinc-400">
            <p>
              <span className="text-zinc-700 dark:text-zinc-300 font-medium">Session: </span>
              Pending Desktop Sign-in
            </p>
            <p>
              <span className="text-zinc-700 dark:text-zinc-300 font-medium">Relying Party: </span>
              {challengeData?.rpId || 'localhost'}
            </p>
          </div>
        </div>

        {/* In-App Browser Warning if applicable */}
        {webAuthnSupport?.isWhatsAppInAppBrowser && (
          <div className="rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 p-3 text-left text-xs text-amber-900 dark:text-amber-200 space-y-1">
            <p className="font-semibold flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5 text-amber-600" />
              <span>In-App Browser Detected</span>
            </p>
            <p className="text-[11px] text-amber-800/90 dark:text-amber-300/80">
              In-app browsers may restrict biometric hardware. If authentication does not trigger, tap (•••) and select &quot;Open in Safari/Chrome&quot;.
            </p>
          </div>
        )}

        {/* Error Alert */}
        {errorMessage && (
          <div
            role="alert"
            className="rounded-xl border border-red-200 dark:border-red-900/50 bg-red-50 dark:bg-red-950/30 p-3 text-xs text-red-800 dark:text-red-300 text-left space-y-1"
          >
            <p className="font-semibold flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5 text-red-600" />
              <span>Verification Error</span>
            </p>
            <p className="text-[11px]">{errorMessage}</p>
          </div>
        )}

        {/* Explicit Approve and Cancel Controls */}
        <div className="space-y-2 pt-1">
          <button
            type="button"
            onClick={handleAuthenticate}
            disabled={isVerifying}
            className="w-full flex items-center justify-center gap-2 rounded-xl bg-zinc-900 dark:bg-white text-white dark:text-zinc-900 py-3 px-4 text-xs font-semibold hover:opacity-90 disabled:opacity-50 transition-opacity cursor-pointer shadow-sm"
          >
            {isVerifying ? (
              <>
                <div className="h-3.5 w-3.5 border-2 border-white dark:border-zinc-900 border-t-transparent rounded-full animate-spin" />
                <span>Verifying Biometric Sensor...</span>
              </>
            ) : (
              <>
                <Fingerprint className="h-4 w-4" />
                <span>Approve & Authorize Session</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={() => router.push('/login')}
            disabled={isVerifying}
            className="w-full py-2.5 px-4 rounded-xl border border-zinc-200 dark:border-zinc-800 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100 hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors cursor-pointer"
          >
            Cancel Authorization
          </button>

          <p className="text-[10px] text-zinc-400 dark:text-zinc-500 pt-1">
            WebAuthn cryptographic verification ensures biometric templates never leave this device.
          </p>
        </div>
      </div>
    </div>
  );

}

export default function VerifyMobilePage() {
  return (
    <Suspense
      fallback={
        <div className="min-h-screen flex items-center justify-center">
          <div className="h-6 w-6 border-2 border-zinc-900 dark:border-white border-t-transparent rounded-full animate-spin" />
        </div>
      }
    >
      <VerifyMobileContent />
    </Suspense>
  );
}
