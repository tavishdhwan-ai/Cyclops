import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';
import { sanitizeRedirectPath } from './lib/authUtils';

// Routes requiring fully verified two-channel authenticated session
const PROTECTED_PREFIXES = ['/dashboard', '/url-scanner', '/emails', '/settings', '/onboarding'];

export function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Check if requested path is protected
  const isProtected = PROTECTED_PREFIXES.some(
    (prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`)
  );

  if (!isProtected) {
    return NextResponse.next();
  }

  // Check for authoritative Sentinel AI mobile-verified session cookie
  const sentinelSession = request.cookies.get('sentinel_session')?.value;
  const hasSupabaseCookie = request.cookies
    .getAll()
    .some((cookie) => cookie.name.startsWith('sb-') && cookie.name.endsWith('-auth-token'));

  // Initial Supabase authentication alone does NOT grant access to protected content.
  // The user MUST possess a valid sentinel_session cookie issued after mobile biometric verification.
  if (!sentinelSession) {
    const loginUrl = new URL('/login', request.url);
    const sanitizedNext = sanitizeRedirectPath(pathname, '/dashboard');
    loginUrl.searchParams.set('next', sanitizedNext);

    // If initial authentication was completed (Supabase cookie present), direct to awaiting mobile authorization
    if (hasSupabaseCookie) {
      loginUrl.searchParams.set('step', 'mobile_waiting');
    }

    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    '/dashboard/:path*',
    '/url-scanner/:path*',
    '/emails/:path*',
    '/settings/:path*',
    '/onboarding/:path*',
  ],
};
