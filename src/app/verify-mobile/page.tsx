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
  Bell,
  KeyRound,
  ShieldCheck,
} from 'lucide-react';
import { detectDeviceContext } from '../../lib/deviceDetection';
import {
  checkWebAuthnSupport,
  performWebAuthnAssertion,
  performWebAuthnRegistration,
} from '../../lib/webauthnUtils';
import { isPushNotificationSupported, subscribeToWebPush, registerMobileDevice } from '../../lib/pushUtils';

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
  const [successMessage, setSuccessMessage] = useState<string>('Biometric authorization has been validated by Sentinel AI.');

  const [challengeData, setChallengeData] = useState<{
    webauthnChallenge?: string;
    rpId?: string;
    transactionId?: string;
    userId?: string;
    mode?: 'register' | 'authenticate';
    hasRegisteredPasskey?: boolean;
    registrationOptions?: any;
    authenticationOptions?: any;
    registeredCredentials?: Array<{ id: string }>;
  } | null>(null);

  const [authMode, setAuthMode] = useState<'register' | 'authenticate'>('register');

  // Mobile Device Push Notification Enrollment State
  const [isPushSupported, setIsPushSupported] = useState<boolean | null>(null);
  const [isEnrollingPush, setIsEnrollingPush] = useState(false);
  const [pushEnrollSuccess, setPushEnrollSuccess] = useState(false);
  const [pushEnrollError, setPushEnrollError] = useState<string | null>(null);

  useEffect(() => {
    isPushNotificationSupported().then(setIsPushSupported);
  }, []);

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
        const mode = data.mode || (data.hasRegisteredPasskey ? 'authenticate' : 'register');
        setAuthMode(mode);

        const support = await checkWebAuthnSupport();
        setWebAuthnSupport(support);
        setIsLoading(false);
      })
      .catch((err) => {
        setErrorMessage(err.message || 'Failed to validate verification challenge.');
        setIsLoading(false);
      });
  }, [token]);

  // 2. Perform WebAuthn Ceremony (Registration or Authentication)
  const handleBiometricAction = async (overrideMode?: 'register' | 'authenticate') => {
    if (!token || !challengeData?.webauthnChallenge) {
      setErrorMessage('Verification challenge unavailable.');
      return;
    }

    const currentMode = overrideMode || authMode;
    setIsVerifying(true);
    setErrorMessage(null);

    try {
      if (currentMode === 'register') {
        // First-Time Passkey Registration Ceremony (attestation)
        const rpId = challengeData.rpId || window.location.hostname;
        const regOptions = challengeData.registrationOptions || {
          challenge: challengeData.webauthnChallenge,
          rp: { id: rpId, name: 'Sentinel AI' },
          user: {
            id: challengeData.userId || 'user',
            name: 'Sentinel User',
            displayName: 'Sentinel User',
          },
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'preferred',
          },
        };

        const registrationResult = await performWebAuthnRegistration(regOptions);

        const ua = navigator.userAgent;
        const isAndroid = /android/i.test(ua);
        const isIos = /iphone|ipad|ipod/i.test(ua);
        const platformName = isAndroid ? 'Android' : (isIos ? 'iOS' : 'Mobile');
        const deviceName = isAndroid ? 'Android Device' : (isIos ? 'Apple Device' : 'Mobile Device');

        const registerRes = await fetch('/api/auth/webauthn/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            mobileToken: token,
            credential: registrationResult,
            deviceName,
            platform: platformName,
          }),
        });

        if (!registerRes.ok) {
          const errorJson = await registerRes.json().catch(() => ({}));
          throw new Error(errorJson.detail || 'Server-side passkey registration verification failed.');
        }

        setSuccessMessage('Biometric passkey registered successfully and session authorized.');
        setIsSuccess(true);
      } else {
        // Subsequent Authentication Ceremony (assertion)
        const rpId = challengeData.rpId || window.location.hostname;
        const allowCredentials =
          challengeData.authenticationOptions?.allowCredentials ||
          challengeData.registeredCredentials;

        const assertion = await performWebAuthnAssertion({
          challenge: challengeData.webauthnChallenge,
          rpId,
          allowCredentials,
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
            credential: assertion,
          }),
        });

        if (!verifyRes.ok) {
          const errorJson = await verifyRes.json().catch(() => ({}));
          throw new Error(errorJson.detail || 'Server-side WebAuthn assertion validation failed.');
        }

        setSuccessMessage('Biometric authorization has been validated by Sentinel AI.');
        setIsSuccess(true);
      }
    } catch (err: unknown) {
      console.error('WebAuthn ceremony error:', err);
      let userFriendlyMsg = 'Biometric operation was cancelled or could not be completed.';

      if (err instanceof Error) {
        if (err.name === 'NotAllowedError') {
          userFriendlyMsg = 'Biometric request was cancelled or timed out. Please tap below to try again.';
        } else if (err.message.includes('No passkeys available') || err.name === 'NotFoundError') {
          userFriendlyMsg = 'No matching passkey was found on this device. You can register a new passkey below.';
        } else {
          userFriendlyMsg = err.message;
        }
      }
      setErrorMessage(userFriendlyMsg);
    } finally {
      setIsVerifying(false);
    }
  };

  // 2b. Enroll Device for Push Notifications
  const handleEnrollDevicePush = async () => {
    if (!challengeData?.userId) {
      setPushEnrollError('User identification unavailable. Please refresh.');
      return;
    }
    setIsEnrollingPush(true);
    setPushEnrollError(null);

    try {
      const pushRes = await subscribeToWebPush(challengeData.userId);
      if (!pushRes.success) {
        throw new Error(pushRes.error || 'Failed to subscribe to Web Push.');
      }

      const devRes = await registerMobileDevice(challengeData.userId, 'Mobile Browser');
      if (!devRes.success) {
        throw new Error(devRes.error || 'Failed to enroll mobile device.');
      }

      setPushEnrollSuccess(true);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Push enrollment failed.';
      setPushEnrollError(msg);
      setPushEnrollSuccess(false);
    } finally {
      setIsEnrollingPush(false);
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
              {successMessage}
            </p>
          </div>

          <div className="rounded-xl bg-emerald-50 dark:bg-emerald-950/30 border border-emerald-200 dark:border-emerald-900/50 p-3.5 text-xs text-emerald-900 dark:text-emerald-300">
            <p className="font-semibold flex items-center justify-center gap-1.5">
              <ShieldCheck className="h-4 w-4 text-emerald-600" />
              <span>Return to Your Desktop</span>
            </p>
            <p className="text-[11px] text-emerald-800/90 dark:text-emerald-300/80 mt-1">
              Your desktop browser has received the authorization confirmation and unlocked your secure dashboard. You may safely close this tab.
            </p>
          </div>
        </div>
      </div>
    );
  }

  // 6. Mobile WebAuthn Interaction Screen
  const isRegisterMode = authMode === 'register';

  return (
    <div className="min-h-screen flex items-center justify-center p-4 sm:p-6 bg-zinc-50 dark:bg-zinc-950">
      <div className="w-full max-w-sm rounded-2xl border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-6 sm:p-8 shadow-sm text-center space-y-6">
        {/* Biometric Scanner Visual Illustration */}
        <div className="relative mx-auto flex h-20 w-20 items-center justify-center rounded-3xl bg-zinc-900 text-white dark:bg-white dark:text-zinc-900 shadow-md">
          <div className="absolute inset-0 rounded-3xl bg-blue-500/20 animate-ping opacity-30" />
          {isRegisterMode ? (
            <KeyRound className="h-10 w-10 relative z-10 text-blue-400 dark:text-blue-600" />
          ) : (
            <Fingerprint className="h-10 w-10 relative z-10" />
          )}
        </div>

        {/* Dynamic Prominent Instruction */}
        <div className="space-y-2">
          <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[10px] font-semibold bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300">
            {isRegisterMode ? (
              <>
                <KeyRound className="h-3 w-3 text-blue-500" />
                <span>First-Time Device Setup</span>
              </>
            ) : (
              <>
                <Fingerprint className="h-3 w-3 text-emerald-500" />
                <span>Passkey Authorization</span>
              </>
            )}
          </div>

          <h1 className="text-base font-bold text-zinc-900 dark:text-zinc-100 leading-snug">
            {isRegisterMode
              ? 'Register Biometric Passkey on this Device'
              : 'Place your Index Finger on the scanner to authorize this session.'}
          </h1>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
            {isRegisterMode
              ? 'No passkey is stored on this phone yet. Create a secure passkey using your device fingerprint, Face ID, or screen lock.'
              : 'Your device will prompt for biometric verification (Fingerprint, Face ID, or Screen Lock) to authorize the pending desktop login.'}
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
            <p>
              <span className="text-zinc-700 dark:text-zinc-300 font-medium">Mode: </span>
              {isRegisterMode ? 'New Passkey Registration' : 'Passkey Authentication'}
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
              In-app browsers may restrict biometric hardware. If authentication does not trigger, tap (•••) and select &quot;Open in Chrome / Safari&quot;.
            </p>
          </div>
        )}

        {/* Error Alert */}
        {errorMessage && (
          <div
            role="alert"
            className="rounded-xl border border-red-200 dark:border-red-900/50 bg-red-50 dark:bg-red-950/30 p-3 text-xs text-red-800 dark:text-red-300 text-left space-y-2"
          >
            <div className="flex items-center gap-1.5 font-semibold">
              <AlertTriangle className="h-3.5 w-3.5 text-red-600 shrink-0" />
              <span>Verification Notice</span>
            </div>
            <p className="text-[11px] leading-relaxed">{errorMessage}</p>

            {/* Quick action to switch to registration if passkey was missing */}
            {!isRegisterMode && (
              <button
                type="button"
                onClick={() => {
                  setErrorMessage(null);
                  setAuthMode('register');
                }}
                className="inline-flex items-center gap-1 text-[11px] font-semibold text-blue-600 dark:text-blue-400 underline cursor-pointer pt-0.5"
              >
                <KeyRound className="h-3 w-3" />
                <span>Register a new passkey on this phone instead</span>
              </button>
            )}
          </div>
        )}

        {/* Mobile Device Push Notification Enrollment */}
        <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 bg-zinc-50/60 dark:bg-zinc-950/60 p-3.5 text-left text-xs space-y-2.5">
          <div className="flex items-center justify-between">
            <span className="font-semibold text-zinc-800 dark:text-zinc-200 flex items-center gap-1.5 text-xs">
              <Bell className="h-3.5 w-3.5 text-blue-500" />
              <span>Register This Device for Push</span>
            </span>
            {pushEnrollSuccess && (
              <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-600 dark:text-emerald-400">
                <CheckCircle2 className="h-3 w-3" />
                <span>Enrolled</span>
              </span>
            )}
          </div>

          <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
            Enroll this mobile browser to receive one-tap push notifications for future desktop sign-in attempts.
          </p>

          {pushEnrollError && (
            <div className="text-[11px] text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-950/30 p-2 rounded-lg border border-red-200 dark:border-red-900/40">
              {pushEnrollError}
            </div>
          )}

          {!pushEnrollSuccess ? (
            <button
              type="button"
              onClick={handleEnrollDevicePush}
              disabled={isEnrollingPush || isVerifying}
              className="w-full flex items-center justify-center gap-1.5 py-2 px-3 rounded-lg border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 text-zinc-800 dark:text-zinc-200 text-xs font-semibold hover:bg-zinc-100 dark:hover:bg-zinc-800 transition-colors disabled:opacity-50 cursor-pointer shadow-2xs"
            >
              {isEnrollingPush ? (
                <>
                  <div className="h-3 w-3 border-2 border-zinc-700 dark:border-zinc-300 border-t-transparent rounded-full animate-spin" />
                  <span>Enrolling Push...</span>
                </>
              ) : (
                <>
                  <Smartphone className="h-3.5 w-3.5" />
                  <span>Enable Instant Push on this Device</span>
                </>
              )}
            </button>
          ) : (
            <div className="p-2 rounded-lg bg-emerald-50 dark:bg-emerald-950/20 border border-emerald-200 dark:border-emerald-900/40 text-emerald-800 dark:text-emerald-300 text-[11px] flex items-center gap-1.5">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 shrink-0" />
              <span>This device will now receive instant push authorizations!</span>
            </div>
          )}
        </div>

        {/* Primary Action Button */}
        <div className="space-y-2 pt-1">
          <button
            type="button"
            onClick={() => handleBiometricAction()}
            disabled={isVerifying}
            className="w-full flex items-center justify-center gap-2 rounded-xl bg-zinc-900 dark:bg-white text-white dark:text-zinc-900 py-3 px-4 text-xs font-semibold hover:opacity-90 disabled:opacity-50 transition-opacity cursor-pointer shadow-sm"
          >
            {isVerifying ? (
              <>
                <div className="h-3.5 w-3.5 border-2 border-white dark:border-zinc-900 border-t-transparent rounded-full animate-spin" />
                <span>
                  {isRegisterMode ? 'Enrolling Biometric Passkey...' : 'Verifying Biometric Sensor...'}
                </span>
              </>
            ) : isRegisterMode ? (
              <>
                <KeyRound className="h-4 w-4" />
                <span>Register Passkey & Authorize</span>
              </>
            ) : (
              <>
                <Fingerprint className="h-4 w-4" />
                <span>Authorize with Passkey</span>
              </>
            )}
          </button>

          {/* Toggle between register and authenticate if needed */}
          {!isRegisterMode && (
            <button
              type="button"
              onClick={() => {
                setErrorMessage(null);
                setAuthMode('register');
              }}
              disabled={isVerifying}
              className="text-[11px] text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200 cursor-pointer py-1"
            >
              Don&apos;t have a passkey on this phone? Register one
            </button>
          )}

          <button
            type="button"
            onClick={() => router.push('/login')}
            disabled={isVerifying}
            className="w-full py-2.5 px-4 rounded-xl border border-zinc-200 dark:border-zinc-800 text-xs font-medium text-zinc-600 dark:text-zinc-400 hover:text-zinc-900 dark:hover:text-zinc-100 hover:bg-zinc-50 dark:hover:bg-zinc-800 transition-colors cursor-pointer"
          >
            Cancel Authorization
          </button>

          <p className="text-[10px] text-zinc-400 dark:text-zinc-500 pt-1">
            FIDO2 / WebAuthn cryptographic verification ensures biometric templates never leave this device.
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
