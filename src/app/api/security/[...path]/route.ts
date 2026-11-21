import { NextResponse } from 'next/server';
import type { NextRequest } from 'next/server';

const BACKEND_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

async function forwardSecurityRequest(request: NextRequest, pathParts: string[]) {
  const path = pathParts.join('/');
  const targetUrl = new URL(`/api/security/${path}`, BACKEND_URL);

  request.nextUrl.searchParams.forEach((value, key) => {
    targetUrl.searchParams.set(key, value);
  });

  const headers = new Headers();
  const strippedHeaders = new Set(['host', 'connection', 'keep-alive', 'transfer-encoding']);
  request.headers.forEach((value, key) => {
    if (!strippedHeaders.has(key.toLowerCase())) {
      headers.set(key, value);
    }
  });

  // Inject session token from cookie if Authorization header is missing
  if (!headers.get('authorization')) {
    const sessionCookie = request.cookies.get('sentinel_session');
    if (sessionCookie?.value) {
      headers.set('Authorization', `Bearer ${sessionCookie.value}`);
    }
  }

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
    return new NextResponse(responseData, {
      status: backendRes.status,
      headers: {
        'Content-Type': backendRes.headers.get('content-type') || 'application/json',
      },
    });
  } catch (err: unknown) {
    return NextResponse.json(
      {
        error: 'Backend Connection Failed',
        message: 'Could not communicate with Sentinel AI backend security service.',
        detail: err instanceof Error ? err.message : String(err),
      },
      { status: 503 }
    );
  }
}

export async function GET(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolved = await params;
  return forwardSecurityRequest(request, resolved.path);
}

export async function POST(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolved = await params;
  return forwardSecurityRequest(request, resolved.path);
}

export async function DELETE(request: NextRequest, { params }: { params: Promise<{ path: string[] }> }) {
  const resolved = await params;
  return forwardSecurityRequest(request, resolved.path);
}
