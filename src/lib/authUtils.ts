/**
 * Cyclops Privacy-First Authentication Utilities
 * Handles safe email normalization, strict redirect verification, and user-facing error translation.
 */

const EMAIL_REGEX = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;

export interface EmailValidationResult {
  isValid: boolean;
  normalized: string;
  error?: string;
}

/**
 * Safely validates and normalizes an email address.
 * Trims whitespace, lowercases, and enforces RFC standards without leaking information.
 */
export function validateEmail(rawEmail: string): EmailValidationResult {
  if (!rawEmail || typeof rawEmail !== 'string') {
    return {
      isValid: false,
      normalized: '',
      error: 'Please enter your email address.',
    };
  }

  const normalized = rawEmail.trim().toLowerCase();

  if (normalized.length === 0) {
    return {
      isValid: false,
      normalized: '',
      error: 'Please enter your email address.',
    };
  }

  if (normalized.length > 254) {
    return {
      isValid: false,
      normalized,
      error: 'Email address is too long (maximum 254 characters).',
    };
  }

  if (!normalized.includes('@')) {
    return {
      isValid: false,
      normalized,
      error: 'Email address must include an "@" symbol.',
    };
  }

  const parts = normalized.split('@');
  if (parts.length !== 2) {
    return {
      isValid: false,
      normalized,
      error: 'Email address cannot contain multiple "@" symbols.',
    };
  }

  const [localPart, domainPart] = parts;

  if (localPart.length === 0) {
    return {
      isValid: false,
      normalized,
      error: 'Email address is missing the username before "@".',
    };
  }

  if (domainPart.length === 0 || !domainPart.includes('.')) {
    return {
      isValid: false,
      normalized,
      error: 'Email address must include a valid domain name (e.g. example.com).',
    };
  }

  if (!EMAIL_REGEX.test(normalized)) {
    return {
      isValid: false,
      normalized,
      error: 'Please enter a valid email address format.',
    };
  }

  return {
    isValid: true,
    normalized,
  };
}

/**
 * Prevents open redirects by guaranteeing the redirect path is a relative path
 * starting with a single '/' and not '//' or a protocol.
 */
export function sanitizeRedirectPath(path: string | null | undefined, fallback: string = '/dashboard'): string {
  if (!path || typeof path !== 'string') {
    return fallback;
  }

  const trimmed = path.trim();

  // Reject protocol-relative URLs (//malicious.com) or external schemes
  if (
    trimmed.startsWith('//') ||
    trimmed.startsWith('http://') ||
    trimmed.startsWith('https://') ||
    trimmed.startsWith('javascript:') ||
    trimmed.startsWith('data:')
  ) {
    return fallback;
  }

  // Must begin with a single '/'
  if (!trimmed.startsWith('/')) {
    return fallback;
  }

  // Prevent backslash evasion on Windows (\malicious.com)
  if (trimmed.includes('\\')) {
    return fallback;
  }

  return trimmed;
}

/**
 * Translates Supabase authentication errors into secure, clear, privacy-first messages.
 */
export function formatAuthError(error: unknown): string {
  if (!error || typeof error !== 'object') return 'An unexpected error occurred. Please try again.';

  const errObj = error as { message?: string; status?: number; code?: string; error_code?: string };
  const message = (errObj.message || '').toLowerCase();
  const code = (errObj.code || errObj.error_code || '').toLowerCase();
  const status = errObj.status;

  if (message.includes('rate limit') || code.includes('rate_limit') || status === 429) {
    return 'For security, please wait a minute before requesting another magic link.';
  }

  if (message.includes('invalid email') || message.includes('email not valid') || code.includes('email_address_invalid')) {
    return 'The email address provided is not valid. Please check for typos.';
  }

  if (message.includes('network') || message.includes('fetch')) {
    return 'Unable to reach authentication servers. Please check your internet connection.';
  }

  if (message.includes('otp_disabled') || message.includes('magiclink disabled')) {
    return 'Email magic links are not enabled in the current authentication provider configuration.';
  }

  if (message.includes('expired') || message.includes('token has expired')) {
    return 'This sign-in link has expired. Please request a new link.';
  }

  return errObj.message || 'Unable to complete sign in. Please try again.';
}
