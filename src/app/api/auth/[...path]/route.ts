import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

async function forwardRequest(request: NextRequest, pathParts: string[]) {
  const path = pathParts.join('/');
  const targetUrl = new URL(`/api/auth/${path}`, BACKEND_URL);

  // Copy query parameters
  request.nextUrl.searchParams.forEach((value, key) => {
    targetUrl.searchParams.set(key, value);
  });

  const headers = new Headers();
  const strippedHeaders = new Set(['host', 'content-length', 'connection', 'keep-alive', 'transfer-encoding']);
  request.headers.forEach((value, key) => {
    if (!strippedHeaders.has(key.toLowerCase())) {
      headers.set(key, value);
    }
  });

  let body: BodyInit | undefined = undefined;
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    body = await request.text();
    if (headers.get('content-type')?.includes('application/json')) {
      headers.set('Content-Type', 'application/json');
    }
  }

  try {
    const backendRes = await fetch(targetUrl.toString(), {
      method: request.method,
      headers,
      body,
      cache: 'no-store',
    });

    const responseData = await backendRes.text();
    let json: Record<string, unknown> | null = null;
    try {
      json = JSON.parse(responseData) as Record<string, unknown>;
    } catch {
      // Non-JSON response
    }

    const response = new NextResponse(responseData, {
      status: backendRes.status,
      headers: {
        'Content-Type': backendRes.headers.get('content-type') || 'application/json',
      },
    });

    // If session completion succeeded, set HttpOnly cookie
    if (path === 'complete' && backendRes.ok && typeof json?.sessionToken === 'string') {
      response.cookies.set({
        name: 'sentinel_session',
        value: json.sessionToken,
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        path: '/',
        maxAge: 60 * 60 * 24 * 7, // 7 days
      });
    }

    // If logging out, delete session cookie
    if (path === 'logout') {
      response.cookies.delete('sentinel_session');
    }

    return response;
  } catch (err: unknown) {
    const correlationId = `corr_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    console.error(`[${correlationId}] Backend communication failed for /api/auth/${path}:`, err instanceof Error ? err.message : String(err));
    return NextResponse.json(
      {
        error: 'Backend Connection Failed',
        message: 'Could not communicate with Sentinel AI backend authentication service. Please verify that the backend is running.',
        detail: 'Could not communicate with Sentinel AI backend authentication service. Please verify that the backend is running on http://127.0.0.1:8000.',
        correlationId,
      },
      { status: 503 }
    );
  }
}

export async function GET(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolved = await params;
  return forwardRequest(request, resolved.path);
}

export async function POST(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolved = await params;
  return forwardRequest(request, resolved.path);
}
