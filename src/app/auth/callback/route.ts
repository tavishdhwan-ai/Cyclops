
import { NextResponse } from 'next/server';
import type { EmailOtpType } from '@supabase/supabase-js';
import { createServerSupabaseClient } from '../../../lib/supabase/server';
import { sanitizeRedirectPath } from '../../../lib/authUtils';

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

export async function GET(request: Request) {
  let stage = 'initialization';

  try {
    console.info('[auth/callback] Started');

    const requestUrl = new URL(request.url);
    const code = requestUrl.searchParams.get('code');
    const tokenHash = requestUrl.searchParams.get('token_hash');
    const type = requestUrl.searchParams.get('type') as EmailOtpType | null;
    const next = requestUrl.searchParams.get('next');
    const tx = requestUrl.searchParams.get('tx');
    const sanitizedNext = sanitizeRedirectPath(next, '/dashboard');

    console.info('[auth/callback] Parameters received', {
      hasCode: Boolean(code),
      hasTokenHash: Boolean(tokenHash),
      hasTransactionId: Boolean(tx),
      hasType: Boolean(type),
    });

    stage = 'create-supabase-client';
    const supabase = await createServerSupabaseClient();

    console.info('[auth/callback] Supabase client:', Boolean(supabase));

    let verifiedUser: { id: string; email: string } | null = null;

    // 1. Handle PKCE code exchange
    if (supabase && code) {
      stage = 'exchange-code';

      const { data, error } = await supabase.auth.exchangeCodeForSession(code);

      if (error) {
        console.error('[auth/callback] Code exchange returned an error:', {
          message: error.message,
          status: error.status,
          code: error.code,
        });
      } else if (data.session?.user) {
        verifiedUser = {
          id: data.session.user.id,
          email: data.session.user.email || '',
        };
        console.info('[auth/callback] Code exchange successful');
      }
    }

    // 2. Handle OTP token hash verification
    if (supabase && tokenHash && type && !verifiedUser) {
      stage = 'verify-otp';

      const { data, error } = await supabase.auth.verifyOtp({
        token_hash: tokenHash,
        type,
      });

      if (error) {
        console.error('[auth/callback] OTP verification returned an error:', {
          message: error.message,
          status: error.status,
          code: error.code,
        });
      } else if (data.session?.user) {
        verifiedUser = {
          id: data.session.user.id,
          email: data.session.user.email || '',
        };
        console.info('[auth/callback] OTP verification successful');
      }
    }

    const transactionId = tx || requestUrl.searchParams.get('transaction_id');

    if (transactionId) {
      stage = 'backend-confirm-email';

      const confirmRes = await fetch(`${BACKEND_URL}/api/auth/confirm-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          transactionId,
          email: verifiedUser?.email || '',
          userId: verifiedUser?.id,
        }),
      });

      console.info('[auth/callback] Backend response:', confirmRes.status);

      if (confirmRes.ok) {
        stage = 'redirect-mobile-waiting';

        const waitingUrl = new URL('/login', requestUrl.origin);
        waitingUrl.searchParams.set('step', 'mobile_waiting');
        waitingUrl.searchParams.set('tx', transactionId);
        waitingUrl.searchParams.set('next', sanitizedNext);

        return NextResponse.redirect(waitingUrl);
      }
    }

    if (!verifiedUser && !transactionId) {
      stage = 'redirect-invalid-link';
      return NextResponse.redirect(
        new URL('/login?error=invalid_link', requestUrl.origin)
      );
    }

    stage = 'redirect-login';

    const destination = new URL('/login', requestUrl.origin);

    if (transactionId) {
      destination.searchParams.set('step', 'mobile_waiting');
      destination.searchParams.set('tx', transactionId);
    }

    destination.searchParams.set('next', sanitizedNext);

    return NextResponse.redirect(destination);
  } catch (err) {
    console.error('[auth/callback] FAILED at stage:', stage);
    console.error('[auth/callback] Exception:', err);

    return NextResponse.json(
      { error: 'Authentication callback failed', stage },
      { status: 500 }
    );
  }
}
