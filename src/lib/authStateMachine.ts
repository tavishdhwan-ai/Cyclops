/**
 * Sentinel AI Authoritative Authentication State Machine.
 * Enforces rigid sequential gates:
 * Gate 1: Passwordless Email Verification -> Gate 2: Mobile WhatsApp Delivery & WebAuthn Ceremony.
 */

export type AuthState =
  | 'EMAIL_REQUIRED'
  | 'EMAIL_PENDING'
  | 'EMAIL_VERIFIED'
  | 'MOBILE_PENDING'
  | 'MOBILE_CHALLENGE_ISSUED'
  | 'MOBILE_VERIFICATION_PENDING'
  | 'BIOMETRIC_VERIFICATION_PENDING'
  | 'AUTHENTICATED'
  | 'EXPIRED'
  | 'REVOKED'
  | 'FAILED';

export interface AuthTransaction {
  id: string;
  userId?: string;
  email: string;
  phoneNumber: string;
  state: AuthState;
  emailVerified: boolean;
  mobileVerified: boolean;
  biometricVerified: boolean;
  createdAt: number;
  expiresAt: number;
  mobileChallengeTokenHash?: string;
  webauthnChallenge?: string;
  whatsappMessageId?: string;
  whatsappDeliveryStatus?: 'unconfigured' | 'pending' | 'sent' | 'delivered' | 'failed';
  userAgent?: string;
  lastError?: string;
}

// Legal State Transitions Mapping
const LEGAL_TRANSITIONS: Record<AuthState, AuthState[]> = {
  EMAIL_REQUIRED: ['EMAIL_PENDING', 'FAILED'],
  EMAIL_PENDING: ['EMAIL_VERIFIED', 'EXPIRED', 'FAILED'],
  EMAIL_VERIFIED: ['MOBILE_PENDING', 'MOBILE_CHALLENGE_ISSUED', 'FAILED'],
  MOBILE_PENDING: ['MOBILE_CHALLENGE_ISSUED', 'EXPIRED', 'FAILED'],
  MOBILE_CHALLENGE_ISSUED: ['MOBILE_VERIFICATION_PENDING', 'BIOMETRIC_VERIFICATION_PENDING', 'EXPIRED', 'REVOKED', 'FAILED'],
  MOBILE_VERIFICATION_PENDING: ['BIOMETRIC_VERIFICATION_PENDING', 'AUTHENTICATED', 'EXPIRED', 'REVOKED', 'FAILED'],
  BIOMETRIC_VERIFICATION_PENDING: ['AUTHENTICATED', 'EXPIRED', 'REVOKED', 'FAILED'],
  AUTHENTICATED: ['REVOKED'],
  EXPIRED: ['EMAIL_REQUIRED', 'EMAIL_PENDING'],
  REVOKED: ['EMAIL_REQUIRED'],
  FAILED: ['EMAIL_REQUIRED', 'EMAIL_PENDING'],
};

/**
 * Validates whether a state transition is legal in the authoritative state engine.
 * Out-of-order, replayed, or unauthorized jumps are strictly rejected.
 */
export function isLegalTransition(from: AuthState, to: AuthState): boolean {
  if (from === to) return true;
  const allowed = LEGAL_TRANSITIONS[from];
  return Boolean(allowed && allowed.includes(to));
}

/**
 * Asserts legal transition and throws error if unauthorized.
 */
export function assertLegalTransition(from: AuthState, to: AuthState): void {
  if (!isLegalTransition(from, to)) {
    throw new Error(`Illegal authentication state transition from [${from}] to [${to}].`);
  }
}
