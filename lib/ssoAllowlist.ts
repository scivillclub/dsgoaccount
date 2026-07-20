const ALLOWED_ORIGINS = (process.env.SSO_ALLOWED_ORIGINS || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

/**
 * redirect_uri가 허용된 origin이고, SP의 SSO 콜백 경로(/api/auth/sso)를 가리키는지 검증한다.
 */
export function isAllowedRedirect(uri: string): boolean {
  try {
    const url = new URL(uri);
    return ALLOWED_ORIGINS.includes(url.origin) && url.pathname.startsWith("/api/auth/sso");
  } catch {
    return false;
  }
}
