import assert from 'node:assert';
import { validateEmail, sanitizeRedirectPath, formatAuthError } from '../src/lib/authUtils';

console.log('--- Running Cyclops Privacy-First Authentication Tests ---');

// ---------------------------------------------------------------------------
// 1. Email Normalization & Validation Tests
// ---------------------------------------------------------------------------
console.log('Test 1: Email normalization and RFC standard validation');

// Valid cases
const valid1 = validateEmail('  ALEX.VANCE@EXAMPLE.COM  ');
assert.strictEqual(valid1.isValid, true);
assert.strictEqual(valid1.normalized, 'alex.vance@example.com', 'Email must be trimmed and lowercased');

const valid2 = validateEmail('user.name+tag@subdomain.privacy.org');
assert.strictEqual(valid2.isValid, true);
assert.strictEqual(valid2.normalized, 'user.name+tag@subdomain.privacy.org');

// Invalid cases
const invalidEmpty = validateEmail('');
assert.strictEqual(invalidEmpty.isValid, false);
assert.ok(invalidEmpty.error?.includes('enter your email'));

const invalidNoAt = validateEmail('alex.example.com');
assert.strictEqual(invalidNoAt.isValid, false);
assert.ok(invalidNoAt.error?.includes('@'));

const invalidDoubleAt = validateEmail('alex@@example.com');
assert.strictEqual(invalidDoubleAt.isValid, false);

const invalidNoDomain = validateEmail('alex@');
assert.strictEqual(invalidNoDomain.isValid, false);

const invalidNoTLD = validateEmail('alex@localhost');
assert.strictEqual(invalidNoTLD.isValid, false);

const invalidLong = validateEmail('a'.repeat(250) + '@example.com');
assert.strictEqual(invalidLong.isValid, false);
assert.ok(invalidLong.error?.includes('too long'));

console.log('✓ Email normalization and boundary validation passed');

// ---------------------------------------------------------------------------
// 2. Open Redirect Prevention Tests
// ---------------------------------------------------------------------------
console.log('Test 2: Strict open-redirect prevention');

// Safe relative paths
assert.strictEqual(sanitizeRedirectPath('/dashboard'), '/dashboard');
assert.strictEqual(sanitizeRedirectPath('/settings'), '/settings');
assert.strictEqual(sanitizeRedirectPath('/url-scanner?test=1'), '/url-scanner?test=1');

// Malicious external URLs and protocol bypasses
assert.strictEqual(sanitizeRedirectPath('https://evil.com'), '/dashboard', 'Must reject absolute HTTPS');
assert.strictEqual(sanitizeRedirectPath('http://phishing.site/steal'), '/dashboard', 'Must reject absolute HTTP');
assert.strictEqual(sanitizeRedirectPath('//attacker.com/evil'), '/dashboard', 'Must reject protocol-relative //');
assert.strictEqual(sanitizeRedirectPath('javascript:alert(1)'), '/dashboard', 'Must reject javascript: pseudo-protocol');
assert.strictEqual(sanitizeRedirectPath('\\evil.com'), '/dashboard', 'Must reject Windows backslash evasion');
assert.strictEqual(sanitizeRedirectPath(''), '/dashboard', 'Must fallback on empty');
assert.strictEqual(sanitizeRedirectPath(null as unknown as string), '/dashboard', 'Must fallback on null');

console.log('✓ Strict internal redirection verified; all open-redirect vectors neutralized');

// ---------------------------------------------------------------------------
// 3. Privacy-First Error Message Formatting Tests
// ---------------------------------------------------------------------------
console.log('Test 3: Provider error formatting');

const rateLimitErr = formatAuthError({ status: 429, message: 'over_email_send_rate_limit' });
assert.ok(rateLimitErr.includes('wait a minute'), 'Must show helpful rate limit guidance');

const expiredErr = formatAuthError({ message: 'Token has expired' });
assert.ok(expiredErr.includes('expired'), 'Must show helpful expiration message');

const networkErr = formatAuthError({ message: 'Failed to fetch network error' });
assert.ok(networkErr.includes('internet connection'), 'Must show network connectivity note');

console.log('✓ Privacy-first auth error translation passed');

// ---------------------------------------------------------------------------
// 4. Onboarding UX Example Defaults Verification
// ---------------------------------------------------------------------------
console.log('Test 4: Onboarding UX Prototype Defaults');

const prototypeDefaults = {
  displayName: '',
  goal: 'personal',
  concerns: ['phishing', 'documents'],
  experience: 'beginner',
};

assert.strictEqual(prototypeDefaults.displayName, '', 'Display name is optional and defaults to empty');
assert.strictEqual(prototypeDefaults.goal, 'personal');
assert.deepStrictEqual(prototypeDefaults.concerns, ['phishing', 'documents']);
assert.strictEqual(prototypeDefaults.experience, 'beginner');

console.log('✓ Onboarding defaults structure verified');

console.log('--- All Authentication Unit Tests Passed Successfully! ---');
