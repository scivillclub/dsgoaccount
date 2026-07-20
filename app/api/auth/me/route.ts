import { NextRequest, NextResponse } from "next/server";
import { verifySession, ACCESS_COOKIE } from "@/lib/session";
import { getAdminDb, SHARED_COL } from "@/lib/firebaseAdmin";
import type { User } from "@/types";

export async function GET(req: NextRequest) {
  const token = req.cookies.get(ACCESS_COOKIE)?.value;
  if (!token) return NextResponse.json({ ok: false }, { status: 401 });
  const session = await verifySession(token);
  if (!session) return NextResponse.json({ ok: false }, { status: 401 });

  try {
    const db = getAdminDb();
    const [aiSnap, usersSnap] = await Promise.all([
      db.collection(SHARED_COL).doc("aiSettings").get(),
      db.collection(SHARED_COL).doc("users").get(),
    ]);

    const currentVersion: number = aiSnap.exists
      ? ((aiSnap.data()?.value as { sessionVersion?: number } | undefined)?.sessionVersion ?? 0)
      : 0;

    if (session.sessionVersion !== currentVersion) {
      return NextResponse.json({ ok: false }, { status: 401 });
    }

    const users: User[] = usersSnap.exists ? (usersSnap.data()?.value ?? []) : [];
    const user = users.find((u) => u.id === session.userId);
    if (!user || user.isBanned) return NextResponse.json({ ok: false }, { status: 401 });

    return NextResponse.json({ ok: true, user, sessionVersion: currentVersion });
  } catch (e) {
    console.error("[auth/me]", e);
    return NextResponse.json({ ok: false }, { status: 500 });
  }
}
