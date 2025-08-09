import { NextRequest, NextResponse } from 'next/server';
import { createUser, generateAccessToken, createRefreshToken, buildAuthCookies } from '@/lib/auth';
import { withRateLimit, withSecurityHeaders, sanitizeInput } from '@/lib/security-middleware';
import { isValidEmail, validatePassword, validateLinkName } from '@/lib/security';

export async function POST(request: NextRequest) {
  // Apply rate limiting
  const rateLimitCheck = withRateLimit(request, 'general');
  if (!rateLimitCheck.allowed) {
    return rateLimitCheck.response!;
  }

  try {
    const body = await request.json();
    const sanitizedBody = sanitizeInput(body) as { email?: string; password?: string; name?: string };
    const { email, password, name } = sanitizedBody;

    // Validate required fields
    if (!email || !password || !name) {
      return withSecurityHeaders(NextResponse.json(
        { error: 'Email, password, and name are required' },
        { status: 400 }
      ));
    }

    // Validate email
    if (!isValidEmail(email)) {
      return withSecurityHeaders(NextResponse.json(
        { error: 'Invalid email format' },
        { status: 400 }
      ));
    }

    // Validate password strength
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return withSecurityHeaders(NextResponse.json(
        { error: passwordValidation.error },
        { status: 400 }
      ));
    }

    // Validate and sanitize name
    const nameValidation = validateLinkName(name);
    if (!nameValidation.isValid) {
      return withSecurityHeaders(NextResponse.json(
        { error: nameValidation.error },
        { status: 400 }
      ));
    }

    const user = await createUser(email, password, nameValidation.sanitized!);
    if (!user) {
      return withSecurityHeaders(NextResponse.json(
        { error: 'User already exists' },
        { status: 409 }
      ));
    }

  const token = generateAccessToken({
      userId: user.id,
      email: user.email,
      name: user.name
    });
  const refresh = await createRefreshToken(user.id);

    // Create response with token in httpOnly cookie
    const response = NextResponse.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name
      }
    });

    for (const c of buildAuthCookies(token, refresh)) {
      response.cookies.set(c.name, c.value, c.options as any);
    }

    return withSecurityHeaders(response);
  } catch (error) {
    console.error('Signup error:', error);
    return withSecurityHeaders(NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    ));
  }
}
