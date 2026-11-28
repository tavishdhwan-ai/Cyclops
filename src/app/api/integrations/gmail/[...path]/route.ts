import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';
const ALLOWED_SUBPATHS = new Set(['status', 'start', 'verify', 'reconnect', 'disconnect']);

function verifySameOriginCsrf(request: NextRequest): boolean {
  const csrfHeader = request.headers.get('x-cyclops-csrf');
  const requestedWith = request.headers.get('x-requested-with');
  if (csrfHeader !== '1' && requestedWith !== 'XMLHttpRequest') {
    return false;
  }

  const host = (request.headers.get('x-forwarded-host') || request.headers.get('host') || '').toLowerCase();
  const origin = request.headers.get('origin');
  const referer = request.headers.get('referer');

  if (origin) {
    try {
      const originHost = new URL(origin).host.toLowerCase();
      if (host && originHost !== host) return false;
    } catch {
      return false;
    }
  } else if (referer) {
    try {
      const refererHost = new URL(referer).host.toLowerCase();
      if (host && refererHost !== host) return false;
    } catch {
      return false;
    }
  } else {
    return false;
  }

  return true;
}

async function forwardGmailRequest(request: NextRequest, pathParts: string[]) {
  const path = pathParts.join('/').replace(/^\/+|\/+$/g, '');

  if (path && !ALLOWED_SUBPATHS.has(path)) {
    return NextResponse.json({ error: 'Not Found', detail: 'Unknown Gmail integration endpoint.' }, { status: 404 });
  }

  if (!path && request.method !== 'DELETE') {
    return NextResponse.json({ error: 'Method Not Allowed' }, { status: 405 });
  }

  // Enforce CSRF check on all state-changing requests
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    if (!verifySameOriginCsrf(request)) {
      return NextResponse.json(
        {
          error: 'CSRF Validation Failed',
          code: 'csrf_failed',
          detail: 'State-changing requests must originate from the Cyclops application.',
        },
        { status: 403 }
      );
    }
  }

  // Prefer HttpOnly session cookie; fall back to Bearer header if sent by client
  const sessionCookie = request.cookies.get('sentinel_session')?.value;
  const authHeader = request.headers.get('authorization') || (sessionCookie ? `Bearer ${sessionCookie}` : '');

  if (!authHeader) {
    return NextResponse.json(
      {
        error: 'Authentication Required',
        code: 'session_required',
        detail: 'Full two-channel Cyclops authentication is required.',
      },
      { status: 401 }
    );
  }

  const targetPath = path ? `/api/integrations/gmail/${path}` : '/api/integrations/gmail';
  const targetUrl = new URL(targetPath, BACKEND_URL);

  const headers = new Headers();
  headers.set('Authorization', authHeader);
  const ua = request.headers.get('user-agent');
  if (ua) headers.set('User-Agent', ua);

  let body: BodyInit | undefined = undefined;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    const contentType = request.headers.get('content-type') || 'application/json';
    headers.set('Content-Type', contentType);
    body = await request.text();
  }

  try {
    const backendRes = await fetch(targetUrl.toString(), {
      method: request.method,
      headers,
      body,
      cache: 'no-store',
    });

    const responseData = await backendRes.text();
    return new NextResponse(responseData, {
      status: backendRes.status,
      headers: {
        'Content-Type': backendRes.headers.get('content-type') || 'application/json',
        'Cache-Control': 'no-store',
      },
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        error: 'Service Unavailable',
        code: 'temporary_unavailable',
        message: 'Could not communicate with Cyclops Gmail integration service.',
        detail: err instanceof Error ? err.message : String(err),
      },
      { status: 503 }
    );
  }
}

export async function GET(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolved = await params;
  return forwardGmailRequest(request, resolved.path || []);
}

export async function POST(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolved = await params;
  return forwardGmailRequest(request, resolved.path || []);
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolved = await params;
  return forwardGmailRequest(request, resolved.path || []);
}
