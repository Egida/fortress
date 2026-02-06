import { NextRequest, NextResponse } from 'next/server';
import { createHmac } from 'crypto';

const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'tron1010';
const AUTH_SECRET = process.env.AUTH_SECRET || 'fortress_default_secret';
const TOKEN_MAX_AGE_SECS = 60 * 60 * 24 * 7; // 7 days

// Brute-force protection: IP-based rate limiting
const MAX_ATTEMPTS = 5;
const WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const loginAttempts = new Map<string, { count: number; firstAttempt: number }>();

// Cleanup stale entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [ip, data] of loginAttempts.entries()) {
    if (now - data.firstAttempt > WINDOW_MS) {
      loginAttempts.delete(ip);
    }
  }
}, 5 * 60 * 1000);

function getClientIp(req: NextRequest): string {
  return (
    req.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ||
    req.headers.get('x-real-ip') ||
    '127.0.0.1'
  );
}

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const entry = loginAttempts.get(ip);

  if (!entry) {
    loginAttempts.set(ip, { count: 1, firstAttempt: now });
    return true;
  }

  // Reset if window expired
  if (now - entry.firstAttempt > WINDOW_MS) {
    loginAttempts.set(ip, { count: 1, firstAttempt: now });
    return true;
  }

  if (entry.count >= MAX_ATTEMPTS) {
    return false;
  }

  entry.count++;
  return true;
}

function resetRateLimit(ip: string): void {
  loginAttempts.delete(ip);
}

function generateToken(): string {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const hmac = createHmac('sha256', AUTH_SECRET)
    .update(timestamp)
    .digest('hex');
  return `${timestamp}.${hmac}`;
}

function verifyToken(token: string): boolean {
  const parts = token.split('.');
  if (parts.length !== 2) return false;

  const [timestamp, hmac] = parts;

  // Check expiry
  const ts = parseInt(timestamp, 10);
  if (isNaN(ts)) return false;
  const now = Math.floor(Date.now() / 1000);
  if (now - ts > TOKEN_MAX_AGE_SECS) return false;

  // Verify HMAC
  const expected = createHmac('sha256', AUTH_SECRET)
    .update(timestamp)
    .digest('hex');
  return hmac === expected;
}

export async function POST(req: NextRequest) {
  try {
    const ip = getClientIp(req);

    // Check rate limit before processing
    if (!checkRateLimit(ip)) {
      const entry = loginAttempts.get(ip);
      const retryAfter = entry
        ? Math.ceil((WINDOW_MS - (Date.now() - entry.firstAttempt)) / 1000)
        : 900;
      return NextResponse.json(
        { error: 'Cok fazla basarisiz giris denemesi. Lutfen bekleyin.' },
        {
          status: 429,
          headers: { 'Retry-After': retryAfter.toString() },
        }
      );
    }

    const body = await req.json();
    const { password } = body;

    if (password !== ADMIN_PASSWORD) {
      return NextResponse.json({ error: 'Yanlis parola' }, { status: 401 });
    }

    // Successful login: reset rate limit counter
    resetRateLimit(ip);

    const token = generateToken();
    const response = NextResponse.json({ success: true });

    response.cookies.set('fortress_auth', token, {
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
      path: '/',
      maxAge: TOKEN_MAX_AGE_SECS,
    });

    return response;
  } catch {
    return NextResponse.json({ error: 'Gecersiz istek' }, { status: 400 });
  }
}

export async function DELETE() {
  const response = NextResponse.json({ success: true });
  response.cookies.delete('fortress_auth');
  return response;
}

export async function GET(req: NextRequest) {
  const token = req.cookies.get('fortress_auth')?.value;
  if (token && verifyToken(token)) {
    return NextResponse.json({ authenticated: true });
  }
  return NextResponse.json({ authenticated: false }, { status: 401 });
}
