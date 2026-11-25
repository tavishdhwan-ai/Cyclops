
import { NextResponse } from 'next/server';
import type { EmailOtpType } from '@supabase/supabase-js';
import { createServerSupabaseClient } from '../../../lib/supabase/server';
import { sanitizeRedirectPath } from '../../../lib/authUtils';

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

export async function GET(request: Request) {
  const requestUrl = new URL(request.url);
  const code = requestUrl.searchParams.get('code');
  const tokenHash = requestUrl.searchParams.get('token_hash');
  const type = requestUrl.searchParams.get('type') as EmailOtpType | null;
  const next = requestUrl.searchParams.get('next');
  const tx = requestUrl.searchParams.get('tx');
  const sanitizedNext = sanitizeRedirectPath(next, '/dashboard');

  console.info('[auth/callback] Processing callback', {
    hasCode: Boolean(code),
    hasTokenHash: Boolean(tokenHash),
    hasType: Boolean(type),
    hasTx: Boolean(tx),
  });

  try {
    const supabase = await createServerSupabaseClient();

    let verifiedUser: { id: string; email: string } | null = null;

    if (supabase && code) {
      const { data, error } = await supabase.auth.exchangeCodeForSession(code);

      if (error) {
        console.error('[auth/callback] Error exchanging auth code:', error.message);
      } else if (data.session?.user) {
        verifiedUser = {
          id: data.session.user.id,
          email: data.session.user.email || '',
        };
        console.info('[auth/callback] Supabase PKCE code exchange succeeded');
      }
    }

    if (supabase && tokenHash && type && !verifiedUser) {
      const { data, error } = await supabase.auth.verifyOtp({
        token_hash: tokenHash,
        type,
      });

      if (error) {
        console.error('[auth/callback] Error verifying OTP:', error.message);
      } else if (data.session?.user) {
        verifiedUser = {
          id: data.session.user.id,
          email: data.session.user.email || '',
        };
        console.info('[auth/callback] Supabase OTP verification succeeded');
      }
    }

    const transactionId = tx || requestUrl.searchParams.get('transaction_id');

    if (transactionId) {
      let confirmRes: Response | null = null;
      try {
        confirmRes = await fetch(`${BACKEND_URL}/api/auth/confirm-email`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            transactionId,
            email: verifiedUser?.email || '',
            userId: verifiedUser?.id,
          }),
        });
      } catch (fetchErr) {
        console.error('[auth/callback] Failed to reach backend /api/auth/confirm-email:', fetchErr);
      }

      if (confirmRes && confirmRes.ok) {
        console.info('[auth/callback] Backend confirm-email succeeded. Redirecting to mobile_waiting.');
        const waitingUrl = new URL('/login', requestUrl.origin);
        waitingUrl.searchParams.set('step', 'mobile_waiting');
        waitingUrl.searchParams.set('tx', transactionId);
        waitingUrl.searchParams.set('next', sanitizedNext);

        return NextResponse.redirect(waitingUrl);
      } else if (confirmRes) {
        const errBody = await confirmRes.text().catch(() => '');
        console.error('[auth/callback] Backend confirm-email returned error status:', confirmRes.status, errBody);
      }
    }

    if (!verifiedUser && !transactionId) {
      console.warn('[auth/callback] Missing verifiedUser and transactionId, redirecting to invalid_link error.');
      return NextResponse.redirect(
        new URL('/login?error=invalid_link', requestUrl.origin)
      );
    }

    const destination = new URL('/login', requestUrl.origin);

    if (transactionId) {
      destination.searchParams.set('step', 'mobile_waiting');
      destination.searchParams.set('tx', transactionId);
    }

    destination.searchParams.set('next', sanitizedNext);

    return NextResponse.redirect(destination);
  } catch (err) {
    console.error('[auth/callback] Unexpected callback exception:', err);

    return NextResponse.json(
      { error: 'Authentication callback failed' },
      { status: 500 }
    );
  }
}
