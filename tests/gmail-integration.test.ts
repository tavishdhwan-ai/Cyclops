import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

console.log('--- Running Cyclops Gmail OAuth Integration Frontend Checks ---');

const root = process.cwd();

function readRepoFile(relPath: string): string {
  return fs.readFileSync(path.join(root, relPath), 'utf8');
}

// Test 1: Verify exact callback route and open-redirect / session protections
console.log('Test 1: Verify Gmail callback Next.js route security');
const callbackRoute = readRepoFile('src/app/api/integrations/gmail/callback/route.ts');
assert(
  callbackRoute.includes("request.cookies.get('sentinel_session')"),
  'Callback route must require sentinel_session HttpOnly cookie'
);
assert(
  callbackRoute.includes("new URL('/settings', requestUrl.origin)"),
  'Callback route must redirect strictly to internal /settings path (no arbitrary redirect destinations)'
);
assert(
  callbackRoute.includes('ALLOWED_STATUS_CODES'),
  'Callback route must sanitize redirect query parameters via strict allowlist'
);
console.log('✓ Callback route security checks passed');

// Test 2: Verify Next.js proxy enforces CSRF, allowlist, and bearer forwarding
console.log('Test 2: Verify Gmail proxy route CSRF and allowlist controls');
const proxyRoute = readRepoFile('src/app/api/integrations/gmail/[...path]/route.ts');
assert(
  proxyRoute.includes('verifySameOriginCsrf'),
  'Proxy route must enforce same-origin CSRF checks on state-changing requests'
);
assert(
  proxyRoute.includes("ALLOWED_SUBPATHS = new Set(['status', 'start', 'verify', 'reconnect', 'disconnect'])"),
  'Proxy route must restrict forwarded endpoints to the Gmail integration allowlist'
);
assert(
  proxyRoute.includes('x-cyclops-csrf'),
  'Proxy route must require custom anti-CSRF header'
);
console.log('✓ Proxy route CSRF and allowlist checks passed');

// Test 3: Verify Settings Connected Accounts UI & privacy disclosures
console.log('Test 3: Verify ConnectedAccountsSection UI, states, and privacy disclosures');
const sectionCode = readRepoFile('src/components/settings/ConnectedAccountsSection.tsx');
assert(sectionCode.includes('gmail.readonly'), 'UI must clearly disclose gmail.readonly read-only scope');
assert(
  sectionCode.includes('cannot send, delete, or modify'),
  'UI must explain Cyclops cannot send, delete, or modify emails'
);
assert(sectionCode.includes('Connect Gmail'), 'UI must include Connect Gmail action');
assert(sectionCode.includes('Verify Connection'), 'UI must include Verify Connection action');
assert(sectionCode.includes('Disconnect Gmail'), 'UI must include Disconnect Gmail action');
assert(sectionCode.includes('Reconnect Gmail'), 'UI must include Reconnect Gmail action');
assert(sectionCode.includes('myaccount.google.com/permissions'), 'UI must include manual revocation guidance');
console.log('✓ ConnectedAccountsSection UI & privacy disclosure checks passed');

// Test 4: Verify Settings page integrates Connected Accounts tab cleanly
console.log('Test 4: Verify Settings page integrates Connected Accounts tab');
const settingsPage = readRepoFile('src/app/settings/page.tsx');
assert(
  settingsPage.includes("id: 'integrations', label: 'Connected Accounts'"),
  'Settings page must render Connected Accounts tab'
);
assert(settingsPage.includes('<ConnectedAccountsSection'), 'Settings page must render ConnectedAccountsSection');
assert(settingsPage.includes('<Suspense'), 'Settings page using useSearchParams must be wrapped in Suspense');
console.log('✓ Settings page integration verified');

console.log('--- All Gmail Integration Frontend Tests Passed Successfully! ---');
