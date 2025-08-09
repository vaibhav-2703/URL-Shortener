import { NextRequest, NextResponse } from 'next/server';
import { validateRefreshToken, rotateRefreshToken, generateAccessToken, buildAuthCookies } from '@/lib/auth';
import { withSecurityHeaders } from '@/lib/security-middleware';

export async function POST(request: NextRequest) {
  try {
    const cookieHeader = request.headers.get('cookie') || '';
    const raw = cookieHeader.split(/; */).find(c => c.startsWith('refresh-token='))?.split('=')[1];
    if (!raw) {
      return withSecurityHeaders(NextResponse.json({ error: 'Missing refresh token' }, { status: 401 }));
    }
    const refreshToken = decodeURIComponent(raw);
    const user = await validateRefreshToken(refreshToken);
    if (!user) {
      return withSecurityHeaders(NextResponse.json({ error: 'Invalid refresh token' }, { status: 401 }));
    }
    const rotated = await rotateRefreshToken(refreshToken);
    if (!rotated) {
      return withSecurityHeaders(NextResponse.json({ error: 'Token rotation failed' }, { status: 401 }));
    }
    const access = generateAccessToken({ userId: user.id, email: user.email, name: user.name });
    const response = NextResponse.json({ success: true });
    for (const c of buildAuthCookies(access, rotated)) {
      response.cookies.set(c.name, c.value, c.options as any);
    }
    return withSecurityHeaders(response);
  } catch (error) {
    console.error('Refresh error:', error);
    return withSecurityHeaders(NextResponse.json({ error: 'Internal server error' }, { status: 500 }));
  }
}
