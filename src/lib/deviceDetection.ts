/**
 * Sentinel AI Context & Device Detection Utility.
 * Inspects User-Agent string to provide a preliminary UX control.
 *
 * NOTE: User-Agent strings can be spoofed by attackers and cannot be treated as
 * cryptographic proof of a native mobile device or proof that WhatsApp Web is not used.
 * Authoritative security relies on server-validated WebAuthn platform authenticator assertions.
 */

export interface DeviceContext {
  isMobile: boolean;
  isDesktop: boolean;
  isTablet: boolean;
  os: 'iOS' | 'Android' | 'Windows' | 'macOS' | 'Linux' | 'Other';
  browser: 'Safari' | 'Chrome' | 'Firefox' | 'Edge' | 'WhatsAppInApp' | 'Other';
  supportsPlatformBiometricsHint: boolean;
}

export function detectDeviceContext(userAgent: string | null | undefined): DeviceContext {
  const ua = (userAgent || '').toLowerCase();

  // Operating system detection
  let os: DeviceContext['os'] = 'Other';
  let isMobile = false;
  let isTablet = false;

  if (/ipad|tablet|(android(?!.*mobile))/i.test(ua)) {
    isTablet = true;
    os = /ipad/i.test(ua) ? 'iOS' : 'Android';
  } else if (/iphone|ipod/i.test(ua)) {
    isMobile = true;
    os = 'iOS';
  } else if (/android.*mobile|mobile/i.test(ua)) {
    isMobile = true;
    os = 'Android';
  } else if (/windows nt/i.test(ua)) {
    os = 'Windows';
  } else if (/macintosh|mac os x/i.test(ua)) {
    os = 'macOS';
  } else if (/linux/i.test(ua)) {
    os = 'Linux';
  }

  const isDesktop = !isMobile && !isTablet;

  // Browser & in-app detection
  let browser: DeviceContext['browser'] = 'Other';
  if (/fban|fbav|whatsapp/i.test(ua)) {
    browser = 'WhatsAppInApp';
  } else if (/edg\//i.test(ua)) {
    browser = 'Edge';
  } else if (/chrome|crios/i.test(ua)) {
    browser = 'Chrome';
  } else if (/firefox|fxios/i.test(ua)) {
    browser = 'Firefox';
  } else if (/safari/i.test(ua) && !/chrome|crios/i.test(ua)) {
    browser = 'Safari';
  }

  // Mobile platform authenticators (Face ID, Touch ID, Android BiometricPrompt)
  const supportsPlatformBiometricsHint = isMobile || isTablet;

  return {
    isMobile,
    isDesktop,
    isTablet,
    os,
    browser,
    supportsPlatformBiometricsHint,
  };
}
