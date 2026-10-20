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

  // Check for Sentinel AI session cookie or Supabase auth token
  const sentinelSession = request.cookies.get('sentinel_session')?.value;
  const hasSupabaseCookie = request.cookies
    .getAll()
    .some((cookie) => cookie.name.startsWith('sb-') && cookie.name.endsWith('-auth-token'));

  const isAuthenticated = Boolean(sentinelSession || hasSupabaseCookie);

  if (!isAuthenticated) {
    const loginUrl = new URL('/login', request.url);
    const sanitizedNext = sanitizeRedirectPath(pathname, '/dashboard');
    loginUrl.searchParams.set('next', sanitizedNext);
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
