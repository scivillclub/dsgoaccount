import { NextRequest, NextResponse } from "next/server";
import { getSession } from "@/lib/session";
import { createSSOToken } from "@/lib/ssoToken";
import { isAllowedRedirect } from "@/lib/ssoAllowlist";

export async function GET(req: NextRequest) {
  const redirectUri = req.nextUrl.searchParams.get("redirect_uri");

  if (!redirectUri || !isAllowedRedirect(redirectUri)) {
    return NextResponse.json({ error: "invalid_redirect_uri" }, { status: 400 });
  }

  const session = await getSession();
  if (!session) {
    return NextResponse.json({ error: "unauthenticated" }, { status: 401 });
  }

  try {
    const token = await createSSOToken(session.userId, session.role);
    const url = new URL(redirectUri);
    url.searchParams.set("token", token);
    return NextResponse.json({ redirectUrl: url.toString() });
  } catch (e) {
    console.error("[sso/issue]", e);
    return NextResponse.json({ error: "server_error" }, { status: 500 });
  }
}
