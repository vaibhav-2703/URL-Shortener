import { NextResponse } from 'next/server';
import { revokeRefreshToken } from '@/lib/auth';

export async function POST(request: Request) {
  try {
    const cookies = (request as any).cookies || {};
    // Next.js App Router exposes cookies differently in middleware vs route handlers; attempt both
    let refreshToken: string | undefined;
    try { refreshToken = (request as any).cookies?.get?.('refresh-token')?.value; } catch { /* ignore */ }
    if (!refreshToken) {
      const cookieHeader = request.headers.get('cookie');
      if (cookieHeader) {
        const match = cookieHeader.split(/; */).find(c => c.startsWith('refresh-token='));
        if (match) refreshToken = decodeURIComponent(match.split('=')[1]);
      }
    }
    if (refreshToken) {
      await revokeRefreshToken(refreshToken);
    }
    // Create response
    const response = NextResponse.json({
      success: true,
      message: 'Logged out successfully'
    });

    // Clear cookies
    response.cookies.set('auth-token', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 0 // Expire immediately
    });
    response.cookies.set('refresh-token', '', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 0,
      path: '/'
    });

    return response;
  } catch (error) {
    console.error('Logout error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
