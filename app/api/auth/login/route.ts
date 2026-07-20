/**
 * POST /api/auth/login
 * 서버사이드 로그인 — creds는 Admin SDK로만 읽음 (클라이언트 노출 없음)
 */
import { NextRequest, NextResponse } from "next/server";
import { pbkdf2 } from "crypto";
import { getAdminDb, SHARED_COL } from "@/lib/firebaseAdmin";
import {
  createAccessToken, accessCookieOptions,
  generateRefreshTokenId, refreshCookieOptions,
  REFRESH_TTL_LONG, REFRESH_TTL_SESSION,
} from "@/lib/session";
import { storeRefreshToken } from "@/lib/refreshTokenStore";
import type { User, Credentials } from "@/types";

const MAX_ATTEMPTS = 5;
const BLOCK_MS = 15 * 60 * 1000; // 15분
const WINDOW_MS = 60_000;

const attempts = new Map<string, { count: number; blockedUntil: number; windowStart: number }>();

setInterval(() => {
  const now = Date.now();
  attempts.forEach((v, k) => { if (v.blockedUntil < now && now - v.windowStart > BLOCK_MS) attempts.delete(k); });
}, 300_000);

function getIp(req: NextRequest) {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
}

function hash(password: string, userId: string): Promise<string> {
  const salt = `${userId}.sv25`;
  return new Promise((resolve, reject) => {
    pbkdf2(password, salt, 100_000, 32, "sha256", (err, buf) =>
      err ? reject(err) : resolve(buf.toString("hex"))
    );
  });
}

export async function POST(req: NextRequest) {
  const ip = getIp(req);
  const now = Date.now();

  // 서버사이드 rate limit
  const entry = attempts.get(ip) ?? { count: 0, blockedUntil: 0, windowStart: now };
  if (entry.blockedUntil > now) {
    const retryAfter = Math.ceil((entry.blockedUntil - now) / 1000);
    return NextResponse.json(
      { ok: false, error: "too_many_attempts", retryAfter },
      { status: 429, headers: { "Retry-After": String(retryAfter) } }
    );
  }
  if (now - entry.windowStart > WINDOW_MS) {
    entry.count = 0; entry.windowStart = now;
  }

  const body = await req.json().catch(() => ({})) as { username?: string; email?: string; password?: string; remember?: boolean };
  const identifier = String(body.username ?? body.email ?? "").trim();
  const password = String(body.password ?? "");
  const remember  = Boolean(body.remember);

  if (!identifier || !password) {
    return NextResponse.json({ ok: false, error: "missing_fields" }, { status: 400 });
  }

  try {
    const db = getAdminDb();
    const [usersSnap, credsSnap] = await Promise.all([
      db.collection(SHARED_COL).doc("users").get(),
      db.collection(SHARED_COL).doc("creds").get(),
    ]);

    const users: User[] = usersSnap.exists ? (usersSnap.data()?.value ?? []) : [];
    const creds: Credentials = credsSnap.exists ? (credsSnap.data()?.value ?? {}) : {};

    const user = users.find((u) => u.username === identifier || u.email === identifier);
    if (!user) {
      entry.count++;
      if (entry.count >= MAX_ATTEMPTS) entry.blockedUntil = now + BLOCK_MS;
      attempts.set(ip, entry);
      return NextResponse.json({ ok: false, error: "invalid_credentials" }, { status: 401 });
    }

    if (user.isBanned) {
      return NextResponse.json({ ok: false, error: "banned" }, { status: 403 });
    }

    const newHash = await hash(password, user.id);
    const matched = creds[user.id] === newHash;
    console.log("[auth/login] user:", user.id, "hash match:", matched, "creds key:", !!creds[user.id]);

    if (!matched) {
      entry.count++;
      if (entry.count >= MAX_ATTEMPTS) entry.blockedUntil = now + BLOCK_MS;
      attempts.set(ip, entry);
      return NextResponse.json({ ok: false, error: "invalid_credentials" }, { status: 401 });
    }

    // 로그인 성공
    attempts.delete(ip);

    const aiSnap = await db.collection(SHARED_COL).doc("aiSettings").get();
    const currentSessionVersion: number = (aiSnap.exists
      ? (aiSnap.data()?.value as { sessionVersion?: number } | undefined)?.sessionVersion
      : undefined) ?? 0;

    // Access token + Refresh token 발급
    const refreshId = generateRefreshTokenId();
    const ttl = remember ? REFRESH_TTL_LONG : REFRESH_TTL_SESSION;

    const [accessToken] = await Promise.all([
      createAccessToken({ userId: user.id, role: user.role, sessionVersion: currentSessionVersion }),
      storeRefreshToken(refreshId, {
        userId: user.id,
        role: user.role,
        remember,
        sessionVersion: currentSessionVersion,
        expiresAt: Date.now() + ttl * 1000,
      }),
    ]);

    const res = NextResponse.json({ ok: true, user: { ...user }, sessionVersion: currentSessionVersion });
    res.cookies.set(accessCookieOptions(accessToken));
    res.cookies.set(refreshCookieOptions(refreshId, remember));
    return res;
  } catch (e) {
    console.error("[auth/login]", e);
    return NextResponse.json({ ok: false, error: "server_error" }, { status: 500 });
  }
}
