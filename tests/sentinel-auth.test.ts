import assert from 'node:assert';
import { normalizePhoneNumber, maskPhoneNumber } from '../src/lib/phoneUtils';
import { isLegalTransition, assertLegalTransition } from '../src/lib/authStateMachine';
import { detectDeviceContext } from '../src/lib/deviceDetection';
import { bufferToBase64URL, base64URLToBuffer } from '../src/lib/webauthnUtils';

console.log('--- Running Sentinel AI Dual-Channel Authentication Test Suite ---');

// ---------------------------------------------------------------------------
// 1. Phone Normalization (E.164) Tests
// ---------------------------------------------------------------------------
console.log('Test 1: International E.164 phone normalization and privacy masking');

const validUS = normalizePhoneNumber(' (415) 555-2671 ', '+1');
assert.strictEqual(validUS.isValid, true);
assert.strictEqual(validUS.normalized, '+14155552671');

const validUK = normalizePhoneNumber('+44 20 7946 0991');
assert.strictEqual(validUK.isValid, true);
assert.strictEqual(validUK.normalized, '+442079460991');

const validIntlPrefix = normalizePhoneNumber('0033 1 42 68 55 55');
assert.strictEqual(validIntlPrefix.isValid, true);
assert.strictEqual(validIntlPrefix.normalized, '+33142685555');

const invalidEmpty = normalizePhoneNumber('');
assert.strictEqual(invalidEmpty.isValid, false);
assert.ok(invalidEmpty.error?.includes('mobile phone number'));

const invalidShort = normalizePhoneNumber('+123');
assert.strictEqual(invalidShort.isValid, false);

// Privacy masking
const masked = maskPhoneNumber('+14155552671');
assert.strictEqual(masked, '+14 ••• ••• 2671');

console.log('✓ Phone number normalization & E.164 compliance verified');

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
// 5. Legacy Removal Verification
// ---------------------------------------------------------------------------
console.log('Test 5: Legacy authentication removal checks');

// Verify that no client-side flag alone can mark a user authenticated
assert.strictEqual(isLegalTransition('EMAIL_PENDING', 'AUTHENTICATED'), false);

console.log('--- All Sentinel AI Authentication Tests Passed Successfully! ---');
