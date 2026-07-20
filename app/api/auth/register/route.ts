/**
 * POST /api/auth/register
 * 서버사이드 회원가입 — users/creds 쓰기를 Admin SDK로만 처리
 */
import { NextRequest, NextResponse } from "next/server";
import { pbkdf2 } from "crypto";
import { getAdminDb, SHARED_COL } from "@/lib/firebaseAdmin";
import type { User, Credentials } from "@/types";

const RATE_WINDOW = 60_000;
const RATE_LIMIT = 3;
const ipMap = new Map<string, { count: number; windowStart: number }>();

function getIp(req: NextRequest) {
  return req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ?? "unknown";
}

function hashPw(password: string, userId: string): Promise<string> {
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
  const entry = ipMap.get(ip) ?? { count: 0, windowStart: now };
  if (now - entry.windowStart > RATE_WINDOW) { entry.count = 0; entry.windowStart = now; }
  entry.count++;
  ipMap.set(ip, entry);
  if (entry.count > RATE_LIMIT) {
    return NextResponse.json({ ok: false, error: "too_many_attempts" }, { status: 429 });
  }

  const body = await req.json().catch(() => ({})) as {
    username?: string; password?: string; studentId?: string; name?: string; email?: string;
  };
  const username  = String(body.username  ?? "").trim();
  const password  = String(body.password  ?? "");
  const studentId = String(body.studentId ?? "").trim();
  const name      = String(body.name      ?? "").trim();
  const email     = String(body.email     ?? "").trim().toLowerCase();

  if (!username || !password || !studentId || !name)
    return NextResponse.json({ ok: false, error: "missing_fields" }, { status: 400 });
  if (studentId.length !== 5)
    return NextResponse.json({ ok: false, error: "invalid_student_id" }, { status: 400 });
  if (password.length < 6)
    return NextResponse.json({ ok: false, error: "password_too_short" }, { status: 400 });
  if (username.length > 30)
    return NextResponse.json({ ok: false, error: "username_too_long" }, { status: 400 });
  if (!/^[a-zA-Z0-9_가-힣]+$/.test(username))
    return NextResponse.json({ ok: false, error: "invalid_username" }, { status: 400 });

  try {
    const db = getAdminDb();
    const usersRef = db.collection(SHARED_COL).doc("users");
    const credsRef = db.collection(SHARED_COL).doc("creds");

    const result = await db.runTransaction(async (tx) => {
      const [usersSnap, credsSnap] = await Promise.all([
        tx.get(usersRef), tx.get(credsRef),
      ]);
      const users: User[]      = usersSnap.exists ? (usersSnap.data()?.value ?? []) : [];
      const creds: Credentials = credsSnap.exists ? (credsSnap.data()?.value ?? {}) : {};

      if (users.some((u) => u.username === username)) return "username_taken";
      if (users.some((u) => u.studentId === studentId)) return "student_id_taken";
      if (email && users.some((u) => u.email === email)) return "email_taken";

      const newUser: User = {
        id: `u${Date.now()}`,
        username,
        email,
        studentId,
        name,
        nickname: name,
        role: "pending",
        isBanned: false,
        isAiDisabled: false,
        aiUsageCount: 0,
        aiDailyCount: 0,
        aiDailyDate: "",
        theme: "dark",
        createdAt: new Date().toISOString(),
      };

      const hashed = await hashPw(password, newUser.id);
      tx.set(usersRef, { value: [...users, newUser] });
      tx.set(credsRef, { value: { ...creds, [newUser.id]: hashed } });
      return newUser;
    });

    if (result === "username_taken")
      return NextResponse.json({ ok: false, error: "username_taken" }, { status: 409 });
    if (result === "student_id_taken")
      return NextResponse.json({ ok: false, error: "student_id_taken" }, { status: 409 });
    if (result === "email_taken")
      return NextResponse.json({ ok: false, error: "email_taken" }, { status: 409 });

    return NextResponse.json({ ok: true, user: result });
  } catch (e) {
    console.error("[auth/register]", e);
    return NextResponse.json({ ok: false, error: "server_error" }, { status: 500 });
  }
}
