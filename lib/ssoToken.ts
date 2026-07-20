/**
 * ssoToken.ts — scivill(IdP)이 발급하는 SP용 단회성 SSO 토큰 (60초 유효)
 * SP는 SESSION_SECRET으로 서명된 이 HS256 JWT를 검증해 자체 세션을 발급한다.
 */
import { SignJWT } from "jose";

const SECRET = new TextEncoder().encode(
  process.env.SESSION_SECRET || "scivill-default-secret-change-this-in-prod"
);

export async function createSSOToken(userId: string, role: string): Promise<string> {
  return new SignJWT({ userId, role, sso: true })
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("60s")
    .sign(SECRET);
}
