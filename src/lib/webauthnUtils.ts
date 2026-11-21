/**
 * Sentinel AI Client-Side WebAuthn & Platform Authenticator Utilities.
 * Handles platform authenticator checks, challenge encoding, and browser ceremony invocation.
 * Supports both passkey registration (attestation) and authentication (assertion).
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

function stringOrBufferToBuffer(input: string | ArrayBuffer): ArrayBuffer {
  if (typeof input !== 'string') {
    return input;
  }
  try {
    return base64URLToBuffer(input);
  } catch {
    return new TextEncoder().encode(input).buffer;
  }
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

export interface WebAuthnRegistrationResult {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    attestationObject: string;
    transports?: string[];
    publicKeyAlgorithm?: number;
    publicKey?: string;
  };
  authenticatorAttachment?: string;
}

/**
 * Initiates the WebAuthn passkey registration ceremony (attestation) on a supported device.
 * Enforces platform authenticator (Android Biometrics / Touch ID / Face ID / Windows Hello).
 */
export async function performWebAuthnRegistration(options: {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName?: string };
  pubKeyCredParams?: Array<{ type: 'public-key'; alg: number }>;
  authenticatorSelection?: {
    authenticatorAttachment?: AuthenticatorAttachment;
    userVerification?: UserVerificationRequirement;
    residentKey?: ResidentKeyRequirement;
    requireResidentKey?: boolean;
  };
  excludeCredentials?: Array<{ id: string; type: 'public-key' }>;
  attestation?: AttestationConveyancePreference;
  timeout?: number;
}): Promise<WebAuthnRegistrationResult> {
  const challengeBuffer = base64URLToBuffer(options.challenge);
  const userIdBuffer = stringOrBufferToBuffer(options.user.id);

  const creationOptions: PublicKeyCredentialCreationOptions = {
    challenge: challengeBuffer,
    rp: options.rp,
    user: {
      id: userIdBuffer,
      name: options.user.name,
      displayName: options.user.displayName || options.user.name,
    },
    pubKeyCredParams: options.pubKeyCredParams || [
      { type: 'public-key', alg: -8 },   // EdDSA
      { type: 'public-key', alg: -7 },   // ES256 (NIST P-256)
      { type: 'public-key', alg: -257 }, // RS256
    ],
    authenticatorSelection: {
      authenticatorAttachment: options.authenticatorSelection?.authenticatorAttachment || 'platform',
      userVerification: options.authenticatorSelection?.userVerification || 'required',
      residentKey: options.authenticatorSelection?.residentKey || 'preferred',
      requireResidentKey: options.authenticatorSelection?.requireResidentKey || false,
    },
    attestation: options.attestation || 'none',
    timeout: options.timeout || 60000,
  };

  if (options.excludeCredentials && options.excludeCredentials.length > 0) {
    creationOptions.excludeCredentials = options.excludeCredentials.map((c) => ({
      type: 'public-key',
      id: base64URLToBuffer(c.id),
      transports: ['internal'],
    }));
  }

  const credential = (await navigator.credentials.create({
    publicKey: creationOptions,
  })) as PublicKeyCredential | null;

  if (!credential || credential.type !== 'public-key') {
    throw new Error('WebAuthn passkey registration failed or was cancelled.');
  }

  const response = credential.response as AuthenticatorAttestationResponse;
  const rawResponse = response as unknown as {
    getTransports?: () => string[];
    getPublicKeyAlgorithm?: () => number;
    getPublicKey?: () => ArrayBuffer | null;
  };

  return {
    id: credential.id,
    rawId: bufferToBase64URL(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: bufferToBase64URL(response.clientDataJSON),
      attestationObject: bufferToBase64URL(response.attestationObject),
      transports: typeof rawResponse.getTransports === 'function' ? rawResponse.getTransports() : undefined,
      publicKeyAlgorithm: typeof rawResponse.getPublicKeyAlgorithm === 'function' ? rawResponse.getPublicKeyAlgorithm() : undefined,
      publicKey: typeof rawResponse.getPublicKey === 'function' && rawResponse.getPublicKey() ? bufferToBase64URL(rawResponse.getPublicKey()!) : undefined,
    },
    authenticatorAttachment: (credential as unknown as { authenticatorAttachment?: string }).authenticatorAttachment || 'platform',
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
  })) as PublicKeyCredential | null;

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
