import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import prisma from './db';

// Generate a secure JWT secret if not provided
const generateSecureSecret = () => {
  return crypto.randomBytes(64).toString('hex');
};

const JWT_SECRET = process.env.JWT_SECRET && process.env.JWT_SECRET !== 'your-super-secret-jwt-key-change-this-in-production' 
  ? process.env.JWT_SECRET 
  : generateSecureSecret();

// Access token short lifetime (rotate via refresh token)
const ACCESS_TOKEN_EXPIRES_IN = process.env.JWT_ACCESS_EXPIRES_IN || '15m';
// Refresh token lifetime (days) used for DB expiration timestamp
const REFRESH_TOKEN_DAYS = parseInt(process.env.REFRESH_TOKEN_DAYS || '30', 10);

export interface User {
  id: string;
  email: string;
  name: string;
  password?: string;
  avatar?: string;
}

export interface JWTPayload {
  userId: string;
  email: string;
  name: string;
  iat?: number;
  exp?: number;
}

// Optional password pepper for extra defense (append to password before hashing)
const PASSWORD_PEPPER = process.env.PASSWORD_PEPPER || '';

export async function hashPassword(password: string): Promise<string> {
  return bcrypt.hash(password + PASSWORD_PEPPER, 12);
}

export async function verifyPassword(password: string, hashedPassword: string): Promise<boolean> {
  return bcrypt.compare(password + PASSWORD_PEPPER, hashedPassword);
}

export function generateAccessToken(payload: Omit<JWTPayload, 'iat' | 'exp'>): string {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: ACCESS_TOKEN_EXPIRES_IN });
}

// Backwards compatibility (deprecated)
export const generateToken = generateAccessToken;

export function verifyToken(token: string): JWTPayload | null {
  try {
    return jwt.verify(token, JWT_SECRET) as JWTPayload;
  } catch {
    return null;
  }
}

export async function authenticateUser(email: string, password: string): Promise<User | null> {
  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return null;
  const isValid = await verifyPassword(password, user.passwordHash);
  if (!isValid) return null;
  return { id: user.id, email: user.email, name: user.name, avatar: user.avatar };
}

export async function createUser(email: string, password: string, name: string): Promise<User | null> {
  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) return null;
  const passwordHash = await hashPassword(password);
  const created = await prisma.user.create({ data: { email, name, passwordHash } });
  return { id: created.id, email: created.email, name: created.name };
}

export async function getUserById(id: string): Promise<User | null> {
  const user = await prisma.user.findUnique({ where: { id } });
  if (!user) return null;
  return { id: user.id, email: user.email, name: user.name, avatar: user.avatar };
}

// --- Refresh Token Management ---

function hashRefreshToken(raw: string): string {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

export async function createRefreshToken(userId: string): Promise<{ raw: string; expiresAt: Date }> {
  const raw = crypto.randomBytes(48).toString('hex');
  const tokenHash = hashRefreshToken(raw);
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000);
  await prisma.refreshToken.create({ data: { userId, tokenHash, expiresAt } });
  return { raw, expiresAt };
}

export async function rotateRefreshToken(oldRaw: string): Promise<{ raw: string; expiresAt: Date } | null> {
  try {
    const oldHash = hashRefreshToken(oldRaw);
    const existing = await prisma.refreshToken.findUnique({ where: { tokenHash: oldHash } });
    if (!existing || existing.revoked || existing.expiresAt < new Date()) return null;
    await prisma.refreshToken.update({ where: { tokenHash: oldHash }, data: { revoked: true } });
    return createRefreshToken(existing.userId);
  } catch {
    return null;
  }
}

export async function revokeRefreshToken(raw: string): Promise<void> {
  try {
    const h = hashRefreshToken(raw);
    await prisma.refreshToken.update({ where: { tokenHash: h }, data: { revoked: true } }).catch(() => {});
  } catch {
    /* swallow */
  }
}

export async function validateRefreshToken(raw: string): Promise<User | null> {
  const h = hashRefreshToken(raw);
  const dbToken = await prisma.refreshToken.findUnique({ where: { tokenHash: h } });
  if (!dbToken || dbToken.revoked || dbToken.expiresAt < new Date()) return null;
  return getUserById(dbToken.userId);
}

export function buildAuthCookies(accessToken: string, refreshToken: { raw: string; expiresAt: Date }) {
  const secure = process.env.NODE_ENV === 'production';
  return [
    {
      name: 'auth-token',
      value: accessToken,
      options: {
        httpOnly: true,
        secure,
        sameSite: 'strict' as const,
        path: '/',
        maxAge: 60 * 15, // 15m
      }
    },
    {
      name: 'refresh-token',
      value: refreshToken.raw,
      options: {
        httpOnly: true,
        secure,
        sameSite: 'strict' as const,
        path: '/',
        maxAge: Math.floor((refreshToken.expiresAt.getTime() - Date.now()) / 1000)
      }
    }
  ];
}
