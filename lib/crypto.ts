/**
 * crypto.ts — 비밀번호 해시
 *
 * 현행: PBKDF2-SHA256, 100,000 iterations, per-user salt
 *   → GPU 브루트포스가 단순 SHA-256 대비 ~100,000배 느려집니다.
 *
 * 마이그레이션 체계 (login에서 순서대로 시도):
 *   V2 (현행) : PBKDF2(password, userId.sv25, 100_000)
 *   V1        : SHA-256(password + userId.sv25)   ← 구 per-user salt
 *   V0 legacy : SHA-256(password + 전역 salt)      ← 최초 버전
 *
 * 로그인 성공 시 V0/V1 해시를 자동으로 V2로 업그레이드합니다.
 */

const GLOBAL_SALT_LEGACY = "scivill-salt-2025";
const PBKDF2_ITERATIONS  = 100_000;

// ── V2 (현행): PBKDF2 ─────────────────────────────────────────────────────────
export async function hashPassword(password: string, userId?: string): Promise<string> {
  const enc  = new TextEncoder();
  const salt = userId ? `${userId}.sv25` : GLOBAL_SALT_LEGACY;

  const key = await crypto.subtle.importKey(
    "raw", enc.encode(password),
    "PBKDF2", false, ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: enc.encode(salt), iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    key, 256,
  );
  return Array.from(new Uint8Array(bits))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── V1 마이그레이션: SHA-256 per-user salt ────────────────────────────────────
export async function hashPasswordV1(password: string, userId?: string): Promise<string> {
  const enc  = new TextEncoder();
  const salt = userId ? `${userId}.sv25` : GLOBAL_SALT_LEGACY;
  const buf  = await crypto.subtle.digest("SHA-256", enc.encode(password + salt));
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── V0 마이그레이션: SHA-256 전역 salt ───────────────────────────────────────
export async function hashPasswordLegacy(password: string): Promise<string> {
  return hashPasswordV1(password, undefined);
}
