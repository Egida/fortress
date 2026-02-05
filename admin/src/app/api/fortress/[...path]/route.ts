import { NextRequest, NextResponse } from 'next/server';

const FORTRESS_URL = process.env.FORTRESS_API_URL || 'http://127.0.0.1:9090';
const FORTRESS_KEY = process.env.FORTRESS_API_KEY || '';

async function proxyRequest(req: NextRequest, params: Promise<{ path: string[] }>) {
  const { path } = await params;
  const fortressPath = '/api/fortress/' + path.join('/');
  const url = new URL(fortressPath, FORTRESS_URL);

  req.nextUrl.searchParams.forEach((value, key) => {
    url.searchParams.set(key, value);
  });

  const headers: Record<string, string> = {
    'X-Fortress-Key': FORTRESS_KEY,
    'Content-Type': 'application/json',
  };

  const fetchOptions: RequestInit = {
    method: req.method,
    headers,
  };

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    try {
      const body = await req.text();
      if (body) fetchOptions.body = body;
    } catch {
    }
  }

  try {
    const res = await fetch(url.toString(), fetchOptions);
    const data = await res.text();

    return new NextResponse(data, {
      status: res.status,
      headers: {
        'Content-Type': res.headers.get('Content-Type') || 'application/json',
      },
    });
  } catch (err) {
    return NextResponse.json(
      { error: 'Fortress API unavailable', detail: String(err) },
      { status: 502 }
    );
  }
}

export async function GET(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, ctx.params);
}

export async function POST(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, ctx.params);
}

export async function PUT(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, ctx.params);
}

export async function DELETE(req: NextRequest, ctx: { params: Promise<{ path: string[] }> }) {
  return proxyRequest(req, ctx.params);
}
