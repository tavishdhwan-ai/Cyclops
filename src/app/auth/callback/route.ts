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

  const supabase = await createServerSupabaseClient();

  let verifiedUser: { id: string; email: string } | null = null;

  // 1. Handle PKCE code exchange
  if (supabase && code) {
    try {
      const { data, error } = await supabase.auth.exchangeCodeForSession(code);
      if (!error && data.session?.user) {
        verifiedUser = {
          id: data.session.user.id,
          email: data.session.user.email || '',
        };
      }
    } catch (err) {
      console.error('Error exchanging auth code:', err);
    }
  }

  // 2. Handle OTP token hash verification
  if (supabase && tokenHash && type && !verifiedUser) {
    try {
      const { data, error } = await supabase.auth.verifyOtp({
        token_hash: tokenHash,
        type,
      });
      if (!error && data.session?.user) {
        verifiedUser = {
          id: data.session.user.id,
          email: data.session.user.email || '',
        };
      }
    } catch (err) {
      console.error('Error verifying OTP:', err);
    }
  }

  // If Supabase was unconfigured or in direct transaction callback mode
  const transactionId = tx || requestUrl.searchParams.get('transaction_id');

  if (transactionId) {
    try {
      // Confirm Gate 1 with Sentinel AI Backend
      const confirmRes = await fetch(`${BACKEND_URL}/api/auth/confirm-email`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          transactionId,
          email: verifiedUser?.email || '',
          userId: verifiedUser?.id,
        }),
      });

      if (confirmRes.ok) {
        // Transition user to mobile-waiting screen on computer browser
        const waitingUrl = new URL('/login', requestUrl.origin);
        waitingUrl.searchParams.set('step', 'mobile_waiting');
        waitingUrl.searchParams.set('tx', transactionId);
        waitingUrl.searchParams.set('next', sanitizedNext);
        return NextResponse.redirect(waitingUrl);
      }
    } catch (err) {
      console.error('Failed to confirm email gate with backend:', err);
    }
  }

  // If user completed email gate without transaction param or link was invalid
  if (!verifiedUser && !transactionId) {
    return NextResponse.redirect(new URL('/login?error=invalid_link', requestUrl.origin));
  }

  const destination = new URL('/login', requestUrl.origin);
  if (transactionId) {
    destination.searchParams.set('step', 'mobile_waiting');
    destination.searchParams.set('tx', transactionId);
  }
  destination.searchParams.set('next', sanitizedNext);
  return NextResponse.redirect(destination);
}
