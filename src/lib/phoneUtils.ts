/**
 * Sentinel AI Worldwide Phone Number Validation & E.164 Normalization.
 * Powered by maintained libphonenumber-js with international country calling codes.
 */
import { parsePhoneNumberFromString, type CountryCode } from 'libphonenumber-js';

export interface CountryInfo {
  name: string;
  iso2: CountryCode;
  dialCode: string;
  flag: string;
}

export const COUNTRIES: CountryInfo[] = [
  { name: 'India', iso2: 'IN', dialCode: '+91', flag: '🇮🇳' },
  { name: 'United States', iso2: 'US', dialCode: '+1', flag: '🇺🇸' },
  { name: 'United Kingdom', iso2: 'GB', dialCode: '+44', flag: '🇬🇧' },
  { name: 'Germany', iso2: 'DE', dialCode: '+49', flag: '🇩🇪' },
  { name: 'Australia', iso2: 'AU', dialCode: '+61', flag: '🇦🇺' },
  { name: 'Canada', iso2: 'CA', dialCode: '+1', flag: '🇨🇦' },
  { name: 'France', iso2: 'FR', dialCode: '+33', flag: '🇫🇷' },
  { name: 'Japan', iso2: 'JP', dialCode: '+81', flag: '🇯🇵' },
  { name: 'Singapore', iso2: 'SG', dialCode: '+65', flag: '🇸🇬' },
  { name: 'United Arab Emirates', iso2: 'AE', dialCode: '+971', flag: '🇦🇪' },
  { name: 'Brazil', iso2: 'BR', dialCode: '+55', flag: '🇧🇷' },
  { name: 'Netherlands', iso2: 'NL', dialCode: '+31', flag: '🇳🇱' },
  { name: 'Spain', iso2: 'ES', dialCode: '+34', flag: '🇪🇸' },
  { name: 'Italy', iso2: 'IT', dialCode: '+39', flag: '🇮🇹' },
  { name: 'Switzerland', iso2: 'CH', dialCode: '+41', flag: '🇨🇭' },
  { name: 'Sweden', iso2: 'SE', dialCode: '+46', flag: '🇸🇪' },
  { name: 'South Africa', iso2: 'ZA', dialCode: '+27', flag: '🇿🇦' },
  { name: 'New Zealand', iso2: 'NZ', dialCode: '+64', flag: '🇳🇿' },
  { name: 'Mexico', iso2: 'MX', dialCode: '+52', flag: '🇲🇽' },
  { name: 'Ireland', iso2: 'IE', dialCode: '+353', flag: '🇮🇪' },
  { name: 'Israel', iso2: 'IL', dialCode: '+972', flag: '🇮🇱' },
  { name: 'Saudi Arabia', iso2: 'SA', dialCode: '+966', flag: '🇸🇦' },
  { name: 'South Korea', iso2: 'KR', dialCode: '+82', flag: '🇰🇷' },
  { name: 'Nigeria', iso2: 'NG', dialCode: '+234', flag: '🇳🇬' },
  { name: 'Kenya', iso2: 'KE', dialCode: '+254', flag: '🇰🇪' },
  { name: 'Argentina', iso2: 'AR', dialCode: '+54', flag: '🇦🇷' },
  { name: 'Chile', iso2: 'CL', dialCode: '+56', flag: '🇨🇱' },
  { name: 'Colombia', iso2: 'CO', dialCode: '+57', flag: '🇨🇴' },
  { name: 'Indonesia', iso2: 'ID', dialCode: '+62', flag: '🇮🇩' },
  { name: 'Malaysia', iso2: 'MY', dialCode: '+60', flag: '🇲🇾' },
  { name: 'Philippines', iso2: 'PH', dialCode: '+63', flag: '🇵🇭' },
  { name: 'Poland', iso2: 'PL', dialCode: '+48', flag: '🇵🇱' },
  { name: 'Portugal', iso2: 'PT', dialCode: '+351', flag: '🇵🇹' },
  { name: 'Norway', iso2: 'NO', dialCode: '+47', flag: '🇳🇴' },
  { name: 'Denmark', iso2: 'DK', dialCode: '+45', flag: '🇩🇰' },
  { name: 'Finland', iso2: 'FI', dialCode: '+358', flag: '🇫🇮' },
  { name: 'Austria', iso2: 'AT', dialCode: '+43', flag: '🇦🇹' },
  { name: 'Belgium', iso2: 'BE', dialCode: '+32', flag: '🇧🇪' },
  { name: 'Turkey', iso2: 'TR', dialCode: '+90', flag: '🇹🇷' },
  { name: 'Egypt', iso2: 'EG', dialCode: '+20', flag: '🇪🇬' },
];

export interface PhoneValidationResult {
  isValid: boolean;
  normalized: string; // E.164 format, e.g. +919876543210
  formattedInternational?: string; // e.g. +91 98765 43210
  formattedNational?: string; // e.g. 098765 43210
  countryCode?: CountryCode;
  countryCallingCode?: string;
  error?: string;
}

/**
 * Detects user default country from locale or browser language.
 */
export function getDefaultCountry(): CountryInfo {
  if (typeof window !== 'undefined' && navigator.language) {
    const localeParts = navigator.language.split('-');
    if (localeParts.length > 1) {
      const region = localeParts[1].toUpperCase() as CountryCode;
      const match = COUNTRIES.find((c) => c.iso2 === region);
      if (match) return match;
    }
  }
  // Default to India or US
  return COUNTRIES[0]; // India (+91)
}

/**
 * Validates and normalizes phone number to strict international E.164 format.
 * Works seamlessly with any country code worldwide without US-only assumptions.
 */
export function normalizePhoneNumber(
  rawPhone: string,
  defaultCountry?: CountryCode
): PhoneValidationResult {
  if (!rawPhone || typeof rawPhone !== 'string') {
    return {
      isValid: false,
      normalized: '',
      error: 'Please enter a mobile phone number for WhatsApp verification.',
    };
  }

  const trimmed = rawPhone.trim();
  if (trimmed.length === 0) {
    return {
      isValid: false,
      normalized: '',
      error: 'Please enter a mobile phone number.',
    };
  }

  try {
    // Parse using libphonenumber-js
    const phoneNumber = parsePhoneNumberFromString(trimmed, defaultCountry);

    if (!phoneNumber) {
      return {
        isValid: false,
        normalized: '',
        error: 'Please enter a valid international mobile number including country calling code.',
      };
    }

    if (!phoneNumber.isValid()) {
      return {
        isValid: false,
        normalized: phoneNumber.number || trimmed,
        error: `Please enter a valid phone number for ${phoneNumber.country || 'selected country'}.`,
        countryCode: phoneNumber.country,
        countryCallingCode: phoneNumber.countryCallingCode ? `+${phoneNumber.countryCallingCode}` : undefined,
      };
    }

    const e164 = phoneNumber.format('E.164');
    const international = phoneNumber.formatInternational();
    const national = phoneNumber.formatNational();

    return {
      isValid: true,
      normalized: e164,
      formattedInternational: international,
      formattedNational: national,
      countryCode: phoneNumber.country,
      countryCallingCode: `+${phoneNumber.countryCallingCode}`,
    };
  } catch {
    return {
      isValid: false,
      normalized: '',
      error: 'Unable to parse phone number format. Please check the country code and digits.',
    };
  }
}

/**
 * Masks international phone number for privacy display, showing country code and last 4 digits.
 */
export function maskPhoneNumber(phone: string): string {
  if (!phone || phone.length < 6) return phone;

  try {
    const parsed = parsePhoneNumberFromString(phone);
    if (parsed) {
      const callingCode = `+${parsed.countryCallingCode}`;
      const national = parsed.nationalNumber;
      if (national.length <= 4) {
        return `${callingCode} ••• ${national}`;
      }
      const suffix = national.slice(-4);
      return `${callingCode} ••• ••• ${suffix}`;
    }
  } catch {}

  const prefix = phone.slice(0, 3);
  const suffix = phone.slice(-4);
  return `${prefix} ••• ••• ${suffix}`;
}
