/**
 * Sentinel AI Client-Side WebAuthn & Platform Authenticator Utilities.
 * Handles platform authenticator checks, challenge encoding, and browser ceremony invocation.
 */

// Base64URL string <-> Uint8Array conversions
export function bufferToBase64URL(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let str = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    str += String.fromCharCode(bytes[i]);
  }
  return btoa(str).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

export function base64URLToBuffer(base64url: string): ArrayBuffer {
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4 !== 0) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Checks if the current browser supports WebAuthn and platform authenticators.
 */
export async function checkWebAuthnSupport(): Promise<{
  isSupported: boolean;
  hasPlatformAuthenticator: boolean;
  isWhatsAppInAppBrowser: boolean;
}> {
  if (typeof window === 'undefined') {
    return { isSupported: false, hasPlatformAuthenticator: false, isWhatsAppInAppBrowser: false };
  }

  const isSupported = Boolean(
    window.PublicKeyCredential &&
    typeof window.PublicKeyCredential === 'function' &&
    navigator.credentials &&
    typeof navigator.credentials.create === 'function' &&
    typeof navigator.credentials.get === 'function'
  );

  let hasPlatformAuthenticator = false;
  if (isSupported && typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
    try {
      hasPlatformAuthenticator = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch {
      hasPlatformAuthenticator = false;
    }
  }

  // Detect in-app webviews that often restrict WebAuthn APIs
  const ua = navigator.userAgent || '';
  const isWhatsAppInAppBrowser = /fban|fbav|whatsapp/i.test(ua);

  return {
    isSupported,
    hasPlatformAuthenticator,
    isWhatsAppInAppBrowser,
  };
}

export interface WebAuthnAssertionResult {
  id: string;
  rawId: string;
  type: string;
  response: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
    userHandle?: string;
  };
}

/**
 * Initiates the WebAuthn authentication ceremony on a supported mobile device.
 * Triggers Face ID, Touch ID, Android Biometrics, or device unlock.
 */
export async function performWebAuthnAssertion(options: {
  challenge: string;
  rpId: string;
  allowCredentials?: Array<{ id: string; type: 'public-key' }>;
  userVerification?: UserVerificationRequirement;
  timeoutMs?: number;
}): Promise<WebAuthnAssertionResult> {
  const challengeBuffer = base64URLToBuffer(options.challenge);

  const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
    challenge: challengeBuffer,
    rpId: options.rpId,
    timeout: options.timeoutMs || 60000,
    userVerification: options.userVerification || 'required',
  };

  if (options.allowCredentials && options.allowCredentials.length > 0) {
    publicKeyCredentialRequestOptions.allowCredentials = options.allowCredentials.map((c) => ({
      type: 'public-key',
      id: base64URLToBuffer(c.id),
      transports: ['internal'],
    }));
  }

  const credential = (await navigator.credentials.get({
    publicKey: publicKeyCredentialRequestOptions,
  })) as PublicKeyCredential;

  if (!credential || credential.type !== 'public-key') {
    throw new Error('WebAuthn assertion failed or was cancelled.');
  }

  const response = credential.response as AuthenticatorAssertionResponse;

  return {
    id: credential.id,
    rawId: bufferToBase64URL(credential.rawId),
    type: credential.type,
    response: {
      authenticatorData: bufferToBase64URL(response.authenticatorData),
      clientDataJSON: bufferToBase64URL(response.clientDataJSON),
      signature: bufferToBase64URL(response.signature),
      userHandle: response.userHandle ? bufferToBase64URL(response.userHandle) : undefined,
    },
  };
}
