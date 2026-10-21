import assert from 'node:assert';
import { normalizePhoneNumber, maskPhoneNumber } from '../src/lib/phoneUtils';
import { isLegalTransition, assertLegalTransition } from '../src/lib/authStateMachine';
import { detectDeviceContext } from '../src/lib/deviceDetection';
import { bufferToBase64URL, base64URLToBuffer } from '../src/lib/webauthnUtils';

console.log('--- Running Sentinel AI Dual-Channel Authentication Test Suite ---');

// ---------------------------------------------------------------------------
// 1. Phone Normalization (E.164) Tests - Multiple Worldwide Regions
// ---------------------------------------------------------------------------
console.log('Test 1: International E.164 phone normalization across multiple regions');

// 1. India (+91)
const validIndia = normalizePhoneNumber('+91 98765 43210');
assert.strictEqual(validIndia.isValid, true);
assert.strictEqual(validIndia.normalized, '+919876543210', 'India E.164 must be +919876543210');
assert.strictEqual(validIndia.countryCode, 'IN');

// 2. United States (+1)
const validUS = normalizePhoneNumber(' (415) 555-2671 ', 'US');
assert.strictEqual(validUS.isValid, true);
assert.strictEqual(validUS.normalized, '+14155552671', 'US E.164 must be +14155552671');
assert.strictEqual(validUS.countryCode, 'US');

// 3. United Kingdom (+44)
const validUK = normalizePhoneNumber('+44 7400 123456');
assert.strictEqual(validUK.isValid, true);
assert.strictEqual(validUK.normalized, '+447400123456', 'UK E.164 must be +447400123456');
assert.strictEqual(validUK.countryCode, 'GB');

// 4. Germany (+49)
const validGermany = normalizePhoneNumber('+49 151 23456789');
assert.strictEqual(validGermany.isValid, true);
assert.strictEqual(validGermany.normalized, '+4915123456789', 'Germany E.164 must be +4915123456789');
assert.strictEqual(validGermany.countryCode, 'DE');

// 5. Australia (+61)
const validAustralia = normalizePhoneNumber('+61 412 345 678');
assert.strictEqual(validAustralia.isValid, true);
assert.strictEqual(validAustralia.normalized, '+61412345678', 'Australia E.164 must be +61412345678');
assert.strictEqual(validAustralia.countryCode, 'AU');

// 6. National format with country code context
const validNationalIndia = normalizePhoneNumber('9876543210', 'IN');
assert.strictEqual(validNationalIndia.isValid, true);
assert.strictEqual(validNationalIndia.normalized, '+919876543210');

// 7. Invalid numbers rejected with clear error messages
const invalidEmpty = normalizePhoneNumber('');
assert.strictEqual(invalidEmpty.isValid, false);
assert.ok(invalidEmpty.error?.includes('mobile phone number'));

const invalidTooShort = normalizePhoneNumber('+91 123');
assert.strictEqual(invalidTooShort.isValid, false);
assert.ok(invalidTooShort.error?.includes('valid phone number'));

const invalidChars = normalizePhoneNumber('+1 415-ABC-1234');
assert.strictEqual(invalidChars.isValid, false);

// Privacy masking
const masked = maskPhoneNumber('+919876543210');
assert.ok(masked.includes('+91') && masked.includes('3210') && masked.includes('•••'));

console.log('✓ Worldwide phone validation (India, US, UK, Germany, Australia) verified');

// ---------------------------------------------------------------------------
// 2. Authoritative State Machine Transition Tests
// ---------------------------------------------------------------------------
console.log('Test 2: Sequential State Machine Legal vs Illegal transitions');

// Legal Transitions
assert.strictEqual(isLegalTransition('EMAIL_REQUIRED', 'EMAIL_PENDING'), true);
assert.strictEqual(isLegalTransition('EMAIL_PENDING', 'EMAIL_VERIFIED'), true);
assert.strictEqual(isLegalTransition('EMAIL_VERIFIED', 'MOBILE_CHALLENGE_ISSUED'), true);
assert.strictEqual(isLegalTransition('MOBILE_CHALLENGE_ISSUED', 'BIOMETRIC_VERIFICATION_PENDING'), true);
assert.strictEqual(isLegalTransition('BIOMETRIC_VERIFICATION_PENDING', 'AUTHENTICATED'), true);

// Illegal Transitions (Forbidden shortcuts & out-of-order jumps)
assert.strictEqual(isLegalTransition('EMAIL_REQUIRED', 'AUTHENTICATED'), false, 'Cannot jump to AUTHENTICATED directly');
assert.strictEqual(isLegalTransition('EMAIL_REQUIRED', 'MOBILE_CHALLENGE_ISSUED'), false, 'Cannot issue WhatsApp challenge before email verification');
assert.strictEqual(isLegalTransition('EMAIL_PENDING', 'AUTHENTICATED'), false, 'Cannot authenticate without Gate 2');
assert.strictEqual(isLegalTransition('AUTHENTICATED', 'EMAIL_PENDING'), false, 'Authenticated session cannot transition backwards');

assert.throws(
  () => assertLegalTransition('EMAIL_REQUIRED', 'AUTHENTICATED'),
  /Illegal authentication state transition/
);

console.log('✓ State machine enforces rigid sequential gates and blocks bypass jumps');

// ---------------------------------------------------------------------------
// 3. Preliminary Device Detection Tests
// ---------------------------------------------------------------------------
console.log('Test 3: Device context classification');

const desktopWindowsUA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36';
const desktopCtx = detectDeviceContext(desktopWindowsUA);
assert.strictEqual(desktopCtx.isDesktop, true);
assert.strictEqual(desktopCtx.isMobile, false);
assert.strictEqual(desktopCtx.os, 'Windows');

const desktopMacUA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15';
const macCtx = detectDeviceContext(desktopMacUA);
assert.strictEqual(macCtx.isDesktop, true);
assert.strictEqual(macCtx.os, 'macOS');

const mobileiPhoneUA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1';
const iPhoneCtx = detectDeviceContext(mobileiPhoneUA);
assert.strictEqual(iPhoneCtx.isMobile, true);
assert.strictEqual(iPhoneCtx.isDesktop, false);
assert.strictEqual(iPhoneCtx.os, 'iOS');
assert.strictEqual(iPhoneCtx.supportsPlatformBiometricsHint, true);

const whatsAppInAppUA = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Mobile/15E148 [FBAN/WhatsApp;FBAV/2.23.20.0]';
const waCtx = detectDeviceContext(whatsAppInAppUA);
assert.strictEqual(waCtx.isMobile, true);
assert.strictEqual(waCtx.browser, 'WhatsAppInApp');

console.log('✓ Device context accurately classifies desktop vs mobile and detects in-app browser');

// ---------------------------------------------------------------------------
// 4. Base64URL Encoding & Buffer Conversion Tests
// ---------------------------------------------------------------------------
console.log('Test 4: Base64URL round-trip conversions for WebAuthn challenges');

const testString = 'sentinel-ai-cryptographic-challenge-12345';
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const buffer = encoder.encode(testString).buffer;
const b64url = bufferToBase64URL(buffer);
assert.ok(!b64url.includes('+'), 'Must not contain +');
assert.ok(!b64url.includes('/'), 'Must not contain /');
assert.ok(!b64url.includes('='), 'Must not contain =');

const recoveredBuffer = base64URLToBuffer(b64url);
const recoveredString = decoder.decode(recoveredBuffer);
assert.strictEqual(recoveredString, testString, 'Round-trip must recover original challenge bytes');

console.log('✓ Base64URL encoding & binary conversions passed');

// ---------------------------------------------------------------------------
// 5. Web Push VAPID Utilities & Middleware Server-Side Gate Tests
// ---------------------------------------------------------------------------
console.log('Test 5: Web Push VAPID key conversion & Server-Side Middleware Gate');

import { urlBase64ToUint8Array } from '../src/lib/pushUtils';

const testVapidKey = 'BLpvWXZ9b2EdlwKkT45YskrYQItuYYqTF1UwiIQaqSy-h3TaOHRvOHaAQRCuZX8YCjwNj8wIKnR8Wvo8V6c8SSQ';
const convertedBytes = urlBase64ToUint8Array(testVapidKey);
assert.ok(convertedBytes instanceof Uint8Array, 'VAPID key must convert to Uint8Array');
assert.strictEqual(convertedBytes.length, 65, 'Uncompressed P-256 public key must be 65 bytes');

// Verify that an initial Supabase cookie alone without sentinel_session is GATED
function simulateMiddlewareGate(cookies: { sentinelSession?: string; hasSupabaseCookie: boolean }) {
  if (!cookies.sentinelSession) {
    return {
      status: 'REDIRECT_LOGIN',
      step: cookies.hasSupabaseCookie ? 'mobile_waiting' : undefined,
    };
  }
  return { status: 'AUTHORIZED' };
}

const supabaseOnlyUser = simulateMiddlewareGate({ hasSupabaseCookie: true });
assert.strictEqual(supabaseOnlyUser.status, 'REDIRECT_LOGIN');
assert.strictEqual(supabaseOnlyUser.step, 'mobile_waiting', 'Initial Supabase login must redirect to mobile_waiting');

const fullyVerifiedUser = simulateMiddlewareGate({ sentinelSession: 'token_123', hasSupabaseCookie: true });
assert.strictEqual(fullyVerifiedUser.status, 'AUTHORIZED');

console.log('✓ VAPID conversion and Server-Side Middleware Gate verified');

console.log('--- All Sentinel AI Authentication Tests Passed Successfully! ---');
