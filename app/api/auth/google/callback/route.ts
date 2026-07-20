import { NextRequest, NextResponse } from "next/server";
import { getAdminDb, SHARED_COL } from "@/lib/firebaseAdmin";
import {
  createAccessToken, accessCookieOptions,
  generateRefreshTokenId, refreshCookieOptions,
  REFRESH_TTL_SESSION,
} from "@/lib/session";
import { storeRefreshToken } from "@/lib/refreshTokenStore";
import type { User } from "@/types";

export async function GET(req: NextRequest) {
  const { searchParams } = req.nextUrl;
  const origin = process.env.NEXT_PUBLIC_SITE_URL || req.nextUrl.origin;
  const code = searchParams.get("code");
  const error = searchParams.get("error");

  if (error || !code) {
    return NextResponse.redirect(`${origin}/auth?error=google_cancelled`);
  }

  const clientId = process.env.GOOGLE_CLIENT_ID!;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET!;
  const redirectUri = `${origin}/api/auth/google/callback`;

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ code, client_id: clientId, client_secret: clientSecret, redirect_uri: redirectUri, grant_type: "authorization_code" }),
  });

  if (!tokenRes.ok) {
    return NextResponse.redirect(`${origin}/auth?error=google_token`);
  }

  const { access_token } = await tokenRes.json();

  const userInfoRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
    headers: { Authorization: `Bearer ${access_token}` },
  });

  if (!userInfoRes.ok) {
    return NextResponse.redirect(`${origin}/auth?error=google_userinfo`);
  }

  const gUser = await userInfoRes.json() as { id: string; email: string; name: string; picture?: string };
  const email = String(gUser.email || "").trim().toLowerCase();
  if (!email) {
    return NextResponse.redirect(`${origin}/auth?error=google_userinfo`);
  }

  const db = getAdminDb();
  const usersRef = db.collection(SHARED_COL).doc("users");

  const user = await db.runTransaction(async (tx) => {
    const usersSnap = await tx.get(usersRef);
    const users: User[] = usersSnap.exists ? (usersSnap.data()?.value ?? []) : [];

    const existing = users.find(u => String(u.email || "").toLowerCase() === email || u.id === `g_${gUser.id}`);
    if (existing) return existing;

    const newId = `g_${gUser.id}`;
    const baseUsername = email.split("@")[0].replace(/[^a-z0-9_]/gi, "").toLowerCase() || "google";
    let username = `${baseUsername}_g`;
    let i = 2;
    while (users.some(u => u.username === username)) {
      username = `${baseUsername}_g${i++}`;
    }
    const name = String(gUser.name || email.split("@")[0] || "Google User").trim();
    const nameParts = name.split(" ");
    const newUser: User = {
      id: newId,
      username,
      studentId: "",
      name,
      nickname: nameParts[0],
      email,
      role: "pending",
      isBanned: false,
      isAiDisabled: false,
      aiUsageCount: 0,
      aiDailyCount: 0,
      aiDailyDate: "",
      theme: "dark",
      createdAt: new Date().toISOString(),
    };
    tx.set(usersRef, { value: [...users, newUser] }, { merge: true });
    return newUser;
  });

  if (user.isBanned) {
    return NextResponse.redirect(`${origin}/auth?error=banned`);
  }

  const aiSnap = await db.collection(SHARED_COL).doc("aiSettings").get();
  const currentSessionVersion: number = (aiSnap.exists
    ? (aiSnap.data()?.value as { sessionVersion?: number } | undefined)?.sessionVersion
    : undefined) ?? 0;

  const refreshId = generateRefreshTokenId();
  const [accessToken] = await Promise.all([
    createAccessToken({ userId: user.id, role: user.role, sessionVersion: currentSessionVersion }),
    storeRefreshToken(refreshId, {
      userId: user.id,
      role: user.role,
      remember: false,
      sessionVersion: currentSessionVersion,
      expiresAt: Date.now() + REFRESH_TTL_SESSION * 1000,
    }),
  ]);

  const res = NextResponse.redirect(`${origin}/`);
  res.cookies.set(accessCookieOptions(accessToken));
  res.cookies.set(refreshCookieOptions(refreshId, false));
  return res;
}
