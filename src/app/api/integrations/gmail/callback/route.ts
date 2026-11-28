import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

const ALLOWED_STATUS_CODES = new Set([
  'connected',
  'denied',
  'expired',
  'state_expired',
  'state_replayed',
  'invalid_state',
  'ownership_mismatch',
  'missing_code',
  'missing_permissions',
  'excessive_permissions',
  'missing_refresh_token',
  'account_mismatch',
  'already_connected',
  'token_exchange_failed',
  'invalid_grant',
  'configuration_error',
  'gmail_unconfigured',
  'encryption_key_invalid',
  'temporary_unavailable',
  'rate_limited',
  'session_required',
  'oauth_error',
]);

function normalizeCallbackStatus(rawCode: unknown): string {
  if (typeof rawCode !== 'string') return 'oauth_error';
  const cleaned = rawCode.trim().toLowerCase();
  if (cleaned === 'state_expired') return 'expired';
  if (cleaned === 'gmail_unconfigured' || cleaned === 'encryption_key_invalid' || cleaned === 'invalid_redirect_uri') {
    return 'configuration_error';
  }
  return ALLOWED_STATUS_CODES.has(cleaned) ? cleaned : 'oauth_error';
}

function buildSettingsRedirect(requestUrl: URL, gmailStatus: string): NextResponse {
  const dest = new URL('/settings', requestUrl.origin);
  dest.searchParams.set('tab', 'integrations');
  dest.searchParams.set('gmail_status', gmailStatus);
  return NextResponse.redirect(dest, { status: 302 });
}

export async function GET(request: NextRequest) {
  const requestUrl = new URL(request.url);
  const code = requestUrl.searchParams.get('code');
  const state = requestUrl.searchParams.get('state');
  const oauthError = requestUrl.searchParams.get('error');

  // Require an active two-channel authenticated Cyclops session.
  // Never establish a Cyclops session via Gmail OAuth callback.
  const sentinelSession = request.cookies.get('sentinel_session')?.value;
  if (!sentinelSession) {
    const loginUrl = new URL('/login', requestUrl.origin);
    loginUrl.searchParams.set('next', '/settings?tab=integrations');
    loginUrl.searchParams.set('error', 'session_required');
    return NextResponse.redirect(loginUrl, { status: 302 });
  }

  try {
    const backendRes = await fetch(`${BACKEND_URL}/api/integrations/gmail/callback`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${sentinelSession}`,
        'User-Agent': request.headers.get('user-agent') || 'Cyclops-NextJS-Callback',
      },
      body: JSON.stringify({
        state,
        code,
        error: oauthError,
      }),
      cache: 'no-store',
    });

    const payload = (await backendRes.json().catch(() => ({}))) as {
      success?: boolean;
      status?: string;
      code?: string;
      error?: string;
    };

    if (backendRes.ok && payload.success) {
      return buildSettingsRedirect(requestUrl, 'connected');
    }

    if (backendRes.status === 401) {
      const loginUrl = new URL('/login', requestUrl.origin);
      loginUrl.searchParams.set('next', '/settings?tab=integrations');
      loginUrl.searchParams.set('error', 'session_required');
      return NextResponse.redirect(loginUrl, { status: 302 });
    }

    const mappedStatus = normalizeCallbackStatus(payload.code || payload.error);
    return buildSettingsRedirect(requestUrl, mappedStatus);
  } catch (err) {
    console.error('[gmail/callback] Failed forwarding callback to backend:', err instanceof Error ? err.message : String(err));
    return buildSettingsRedirect(requestUrl, 'temporary_unavailable');
  }
}
