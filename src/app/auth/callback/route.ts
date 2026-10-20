import { NextResponse } from 'next/server';
import type { EmailOtpType } from '@supabase/supabase-js';
import { createServerSupabaseClient } from '../../../lib/supabase/server';
import { sanitizeRedirectPath } from '../../../lib/authUtils';

export async function GET(request: Request) {
  const requestUrl = new URL(request.url);
  const code = requestUrl.searchParams.get('code');
  const tokenHash = requestUrl.searchParams.get('token_hash');
  const type = requestUrl.searchParams.get('type') as EmailOtpType | null;
  const next = requestUrl.searchParams.get('next');
  const sanitizedNext = sanitizeRedirectPath(next, '/dashboard');

  const supabase = await createServerSupabaseClient();

  if (!supabase) {
    // If Supabase is not configured on server, redirect back to login
    return NextResponse.redirect(new URL('/login?error=unconfigured', requestUrl.origin));
  }

  // 1. Handle PKCE code exchange (Standard OAuth & Modern Magic Link)
  if (code) {
    try {
      const { data, error } = await supabase.auth.exchangeCodeForSession(code);

      if (error) {
        console.error('Error exchanging auth code for session:', error.message);
        return NextResponse.redirect(new URL('/login?error=invalid_link', requestUrl.origin));
      }

      // Check if user has completed onboarding
      const user = data.session?.user;
      const onboardingCompleted = user?.user_metadata?.cyclops_profile?.onboardingCompleted;

      if (!onboardingCompleted) {
        return NextResponse.redirect(new URL('/onboarding', requestUrl.origin));
      }

      return NextResponse.redirect(new URL(sanitizedNext, requestUrl.origin));
    } catch (err: unknown) {
      console.error('Unexpected error during code exchange:', err);
      return NextResponse.redirect(new URL('/login?error=invalid_link', requestUrl.origin));
    }
  }

  // 2. Handle token hash verification (Direct OTP link)
  if (tokenHash && type) {
    try {
      const { data, error } = await supabase.auth.verifyOtp({
        token_hash: tokenHash,
        type,
      });

      if (error) {
        console.error('Error verifying OTP token hash:', error.message);
        return NextResponse.redirect(new URL('/login?error=invalid_link', requestUrl.origin));
      }

      const user = data.session?.user;
      const onboardingCompleted = user?.user_metadata?.cyclops_profile?.onboardingCompleted;

      if (!onboardingCompleted) {
        return NextResponse.redirect(new URL('/onboarding', requestUrl.origin));
      }

      return NextResponse.redirect(new URL(sanitizedNext, requestUrl.origin));
    } catch (err: unknown) {
      console.error('Unexpected error during OTP verification:', err);
      return NextResponse.redirect(new URL('/login?error=invalid_link', requestUrl.origin));
    }
  }

  // No auth code or token provided
  return NextResponse.redirect(new URL('/login?error=invalid_link', requestUrl.origin));
}
