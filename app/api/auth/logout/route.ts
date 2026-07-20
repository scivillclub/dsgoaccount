import { NextRequest, NextResponse } from "next/server";
import { ACCESS_COOKIE, REFRESH_COOKIE } from "@/lib/session";
import { deleteRefreshToken } from "@/lib/refreshTokenStore";

export async function POST(req: NextRequest) {
  const refreshId = req.cookies.get(REFRESH_COOKIE)?.value;
  if (refreshId) {
    await deleteRefreshToken(refreshId).catch(() => {});
  }

  const res = NextResponse.json({ ok: true });
  res.cookies.delete({ name: ACCESS_COOKIE,  path: "/" });
  res.cookies.delete({ name: REFRESH_COOKIE, path: "/" });
  return res;
}
