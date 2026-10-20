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

  // 3. Desktop Authorization Denied Experience
  if (deviceContext?.isDesktop) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 sm:p-6 bg-zinc-50 dark:bg-zinc-950">
        <div className="w-full max-w-md rounded-2xl border border-red-200 dark:border-red-900/60 bg-white dark:bg-zinc-900 p-6 sm:p-8 shadow-sm text-center space-y-6">
          <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-red-100 dark:bg-red-950/60 text-red-600 dark:text-red-400">
            <Smartphone className="h-7 w-7" />
          </div>

          <div className="space-y-2">
            <h1 className="text-xl font-bold tracking-tight text-zinc-900 dark:text-zinc-100">
              Access Denied: Mobile Authorization Required
            </h1>
            <p className="text-xs text-zinc-600 dark:text-zinc-400 leading-relaxed">
              This verification link was delivered via WhatsApp and can only be authorized from a supported mobile device (iOS or Android) equipped with platform biometrics.
            </p>
          </div>

          <div className="rounded-xl bg-zinc-50 dark:bg-zinc-950 border border-zinc-200 dark:border-zinc-800 p-3.5 text-left text-xs space-y-2">
            <p className="font-semibold text-zinc-800 dark:text-zinc-200 flex items-center gap-1.5">
              <Lock className="h-3.5 w-3.5 text-zinc-500" />
              <span>Next Steps:</span>
            </p>
            <ol className="list-decimal list-inside text-zinc-600 dark:text-zinc-400 space-y-1 text-[11px] leading-relaxed">
              <li>Open WhatsApp on your mobile phone.</li>
              <li>Locate the security verification message from Sentinel AI.</li>
              <li>Tap the secure link directly on your mobile device.</li>
            </ol>
            <p className="text-[10px] text-zinc-400 dark:text-zinc-500 pt-1 italic">
              Notice: User-Agent detection is a preliminary UX control. Native biometric hardware guarantees device possession.
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
              Device Verified Successfully
            </h2>
            <p className="text-xs text-zinc-600 dark:text-zinc-400 leading-relaxed">
              Biometric authorization has been validated by Sentinel AI.
            </p>
          </div>

          <div className="rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/50 p-3.5 text-xs text-emerald-900 dark:text-emerald-300">
            <p className="font-semibold">Return to Your Computer</p>
            <p className="text-[11px] text-emerald-800/90 dark:text-emerald-300/80 mt-1">
              Your computer session has automatically progressed to the secure dashboard. You may safely close this tab.
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
        <div className="mx-auto flex h-14 w-14 items-center justify-center rounded-2xl bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 shadow-sm">
          <Fingerprint className="h-7 w-7" />
        </div>

        <div className="space-y-1.5">
          <h1 className="text-lg font-bold text-zinc-900 dark:text-zinc-100">
            Sentinel AI Mobile Verification
          </h1>
          <p className="text-xs text-zinc-600 dark:text-zinc-400">
            Authorize your login session using your device platform biometrics (Face ID, Touch ID, or Screen Lock).
          </p>
        </div>

        {/* WhatsApp In-App Browser Warning */}
        {webAuthnSupport?.isWhatsAppInAppBrowser && (
          <div className="rounded-xl border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 p-3 text-left text-xs text-amber-900 dark:text-amber-200 space-y-1">
            <p className="font-semibold flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5 text-amber-600" />
              <span>In-App Browser Detected</span>
            </p>
            <p className="text-[11px] text-amber-800/90 dark:text-amber-300/80">
              WhatsApp&apos;s internal browser may restrict biometric hardware. If authentication does not trigger, tap the menu (•••) and select &quot;Open in Safari&quot; or &quot;Open in Chrome&quot;.
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

        {/* Action Button */}
        <div className="space-y-3 pt-2">
          <button
            type="button"
            onClick={handleAuthenticate}
            disabled={isVerifying}
            className="w-full flex items-center justify-center gap-2 rounded-xl bg-zinc-900 dark:bg-white text-white dark:text-zinc-900 py-3 px-4 text-xs font-semibold hover:opacity-90 disabled:opacity-50 transition-opacity cursor-pointer shadow-sm"
          >
            {isVerifying ? (
              <>
                <div className="h-3.5 w-3.5 border-2 border-white dark:border-zinc-900 border-t-transparent rounded-full animate-spin" />
                <span>Prompting Biometrics...</span>
              </>
            ) : (
              <>
                <Fingerprint className="h-4 w-4" />
                <span>Authorize with Biometrics</span>
              </>
            )}
          </button>

          <p className="text-[10px] text-zinc-400 dark:text-zinc-500">
            Protected by Sentinel AI Two-Channel Zero-Trust Protocol.
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
