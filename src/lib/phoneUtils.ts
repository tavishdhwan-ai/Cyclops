/**
 * Sentinel AI International Phone Number Normalization & Validation.
 * Enforces strict E.164 compliance (+[country code][subscriber number]).
 */

// E.164 specification: + followed by 7 to 15 digits, starting with non-zero
const E164_REGEX = /^\+[1-9]\d{6,14}$/;

export interface PhoneValidationResult {
  isValid: boolean;
  normalized: string;
  error?: string;
  countryCode?: string;
}

/**
 * Normalizes and validates a phone number to standard international E.164 format.
 * Strips whitespace, dashes, parentheses, dots.
 * Requires country code prefix (+).
 */
export function normalizePhoneNumber(rawPhone: string, defaultCountryPrefix: string = '+1'): PhoneValidationResult {
  if (!rawPhone || typeof rawPhone !== 'string') {
    return {
      isValid: false,
      normalized: '',
      error: 'Please enter a mobile phone number for WhatsApp verification.',
    };
  }

  // Remove common punctuation: spaces, dashes, parentheses, periods
  let cleaned = rawPhone.trim().replace(/[\s\-().]/g, '');

  if (cleaned.length === 0) {
    return {
      isValid: false,
      normalized: '',
      error: 'Please enter a mobile phone number.',
    };
  }

  // Handle leading international 00 notation (e.g. 0044 -> +44)
  if (cleaned.startsWith('00')) {
    cleaned = '+' + cleaned.substring(2);
  }

  // If user didn't provide a leading +, prepend default country prefix if numeric
  if (!cleaned.startsWith('+')) {
    const prefix = defaultCountryPrefix.startsWith('+') ? defaultCountryPrefix : `+${defaultCountryPrefix}`;
    cleaned = `${prefix}${cleaned}`;
  }

  // Validate against E.164 standard (+ followed by 7 to 15 digits)
  if (!E164_REGEX.test(cleaned)) {
    return {
      isValid: false,
      normalized: cleaned,
      error: 'Please enter a valid international mobile number including country code (e.g. +14155552671).',
    };
  }

  // Extract preliminary country calling code for display
  const match = cleaned.match(/^\+(\d{1,3})/);
  const countryCode = match ? `+${match[1]}` : undefined;

  return {
    isValid: true,
    normalized: cleaned,
    countryCode,
  };
}

/**
 * Masks a phone number for privacy-first user-facing screens (e.g. +1 ••• ••• 2671).
 */
export function maskPhoneNumber(phone: string): string {
  if (!phone || phone.length < 6) return phone;
  const prefix = phone.slice(0, 3);
  const suffix = phone.slice(-4);
  return `${prefix} ••• ••• ${suffix}`;
}
