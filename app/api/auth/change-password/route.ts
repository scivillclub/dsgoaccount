import { NextRequest, NextResponse } from "next/server";
import { pbkdf2 } from "crypto";
import { getAdminDb, SHARED_COL } from "@/lib/firebaseAdmin";
import { getSession } from "@/lib/session";
import type { Credentials } from "@/types";

function hash(password: string, userId: string): Promise<string> {
  const salt = `${userId}.sv25`;
  return new Promise((resolve, reject) => {
    pbkdf2(password, salt, 100_000, 32, "sha256", (err, buf) =>
      err ? reject(err) : resolve(buf.toString("hex"))
    );
  });
}

export async function POST(req: NextRequest) {
  const session = await getSession();
  if (!session) return NextResponse.json({ ok: false, error: "unauthorized" }, { status: 401 });

  const body = await req.json().catch(() => ({})) as { currentPassword?: string; newPassword?: string };
  const currentPassword = String(body.currentPassword ?? "");
  const newPassword = String(body.newPassword ?? "");
  if (!currentPassword || !newPassword)
    return NextResponse.json({ ok: false, error: "missing_fields" }, { status: 400 });
  if (newPassword.length < 6)
    return NextResponse.json({ ok: false, error: "password_too_short" }, { status: 400 });

  try {
    const db = getAdminDb();
    const credsRef = db.collection(SHARED_COL).doc("creds");
    const credsSnap = await credsRef.get();
    const creds: Credentials = credsSnap.exists ? (credsSnap.data()?.value ?? {}) : {};

    const currentHash = await hash(currentPassword, session.userId);
    if (creds[session.userId] !== currentHash)
      return NextResponse.json({ ok: false, error: "invalid_current_password" }, { status: 401 });

    const newHash = await hash(newPassword, session.userId);
    await credsRef.set({ value: { ...creds, [session.userId]: newHash } });
    return NextResponse.json({ ok: true });
  } catch (e) {
    console.error("[change-password]", e);
    return NextResponse.json({ ok: false, error: "server_error" }, { status: 500 });
  }
}
