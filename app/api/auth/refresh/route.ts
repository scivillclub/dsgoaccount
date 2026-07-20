import { NextRequest, NextResponse } from "next/server";
import {
  createAccessToken, accessCookieOptions,
  generateRefreshTokenId, refreshCookieOptions,
  REFRESH_TTL_LONG, REFRESH_TTL_SESSION,
  REFRESH_COOKIE, ACCESS_COOKIE,
} from "@/lib/session";
import { getRefreshToken, storeRefreshToken, deleteRefreshToken } from "@/lib/refreshTokenStore";
import { getAdminDb, SHARED_COL } from "@/lib/firebaseAdmin";

export async function POST(req: NextRequest) {
  const refreshId = req.cookies.get(REFRESH_COOKIE)?.value;
  if (!refreshId) return NextResponse.json({ ok: false }, { status: 401 });

  const stored = await getRefreshToken(refreshId);
  if (!stored) return NextResponse.json({ ok: false }, { status: 401 });

  try {
    const db = getAdminDb();
    const aiSnap = await db.collection(SHARED_COL).doc("aiSettings").get();
    const currentVersion: number = aiSnap.exists
      ? ((aiSnap.data()?.value as { sessionVersion?: number } | undefined)?.sessionVersion ?? 0)
      : 0;

    // sessionVersion 변경 = 강제 로그아웃 → refresh 차단 및 토큰 폐기
    if (stored.sessionVersion !== currentVersion) {
      await deleteRefreshToken(refreshId).catch(() => {});
      const res = NextResponse.json({ ok: false, error: "session_invalidated" }, { status: 401 });
      res.cookies.delete({ name: ACCESS_COOKIE, path: "/" });
      res.cookies.delete({ name: REFRESH_COOKIE, path: "/" });
      return res;
    }

    // Refresh token rotation: 기존 폐기 + 신규 발급
    const newRefreshId = generateRefreshTokenId();
    const ttl = stored.remember ? REFRESH_TTL_LONG : REFRESH_TTL_SESSION;

    const [newAccessToken] = await Promise.all([
      createAccessToken({ userId: stored.userId, role: stored.role, sessionVersion: currentVersion }),
      deleteRefreshToken(refreshId),
      storeRefreshToken(newRefreshId, {
        userId: stored.userId,
        role: stored.role,
        remember: stored.remember,
        sessionVersion: currentVersion,
        expiresAt: Date.now() + ttl * 1000,
      }),
    ]);

    const res = NextResponse.json({ ok: true });
    res.cookies.set(accessCookieOptions(newAccessToken));
    res.cookies.set(refreshCookieOptions(newRefreshId, stored.remember));
    return res;
  } catch (e) {
    console.error("[auth/refresh]", e);
    return NextResponse.json({ ok: false }, { status: 500 });
  }
}
