/**
 * session.ts — httpOnly 쿠키 기반 세션 (서버사이드 전용)
 * - sv_access : 단기 JWT (15분), 모든 API 인증에 사용
 * - sv_refresh: 장기 불투명 토큰 (1일 / 30일), Firestore에 저장되고 교체(rotation)됨
 */
import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";
import { randomBytes } from "crypto";

const SECRET = new TextEncoder().encode(
  process.env.SESSION_SECRET || "scivill-default-secret-change-this-in-prod"
);

export const ACCESS_COOKIE  = "sv_access";
export const REFRESH_COOKIE = "sv_refresh";

const ACCESS_TTL          = 15 * 60;           // 15분
export const REFRESH_TTL_SESSION = 24 * 60 * 60;      // 1일 (remember=false)
export const REFRESH_TTL_LONG    = 30 * 24 * 60 * 60; // 30일 (remember=true)

export type SessionPayload = {
  userId: string;
  role: string;
  sessionVersion: number;
};

// ─── Access Token (JWT, 15분) ──────────────────────────────────────────────────

export async function createAccessToken(payload: SessionPayload): Promise<string> {
  return new SignJWT({ ...payload })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime(`${ACCESS_TTL}s`)
    .sign(SECRET);
}

export async function verifySession(token: string): Promise<SessionPayload | null> {
  try {
    const { payload } = await jwtVerify(token, SECRET);
    return payload as unknown as SessionPayload;
  } catch {
    return null;
  }
}

export async function getSession(): Promise<SessionPayload | null> {
  try {
    const store = await cookies();
    const token = store.get(ACCESS_COOKIE)?.value;
    if (!token) return null;
    return verifySession(token);
  } catch { return null; }
}

export function accessCookieOptions(token: string) {
  return {
    name: ACCESS_COOKIE,
    value: token,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    maxAge: ACCESS_TTL,
    path: "/",
  };
}

// ─── Refresh Token (opaque random ID, Firestore에 저장) ───────────────────────

export function generateRefreshTokenId(): string {
  return randomBytes(32).toString("hex");
}

export function refreshCookieOptions(tokenId: string, remember = false) {
  return {
    name: REFRESH_COOKIE,
    value: tokenId,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax" as const,
    maxAge: remember ? REFRESH_TTL_LONG : REFRESH_TTL_SESSION,
    path: "/",
  };
}
