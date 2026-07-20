/**
 * refreshTokenStore.ts — Firestore 기반 refresh token 저장소 (Admin SDK 전용)
 */
import { FieldValue } from "firebase-admin/firestore";
import { getAdminDb, SHARED_COL } from "./firebaseAdmin";

const DOC = "refreshTokens";

export type StoredRefreshToken = {
  userId: string;
  role: string;
  remember: boolean;
  sessionVersion: number;
  expiresAt: number; // Unix ms
};

type TokenMap = Record<string, StoredRefreshToken>;

async function getMap(): Promise<TokenMap> {
  const snap = await getAdminDb().collection(SHARED_COL).doc(DOC).get();
  return snap.exists ? (snap.data()?.value ?? {}) : {};
}

export async function storeRefreshToken(id: string, data: StoredRefreshToken): Promise<void> {
  await getAdminDb().collection(SHARED_COL).doc(DOC).set(
    { value: { [id]: data } },
    { merge: true },
  );
}

export async function getRefreshToken(id: string): Promise<StoredRefreshToken | null> {
  const map = await getMap();
  const data = map[id];
  if (!data) return null;
  if (Date.now() > data.expiresAt) {
    deleteRefreshToken(id).catch(() => {}); // lazy cleanup
    return null;
  }
  return data;
}

export async function deleteRefreshToken(id: string): Promise<void> {
  try {
    await getAdminDb().collection(SHARED_COL).doc(DOC).update({
      [`value.${id}`]: FieldValue.delete(),
    });
  } catch {
    // 문서가 없으면 무시
  }
}

export async function deleteUserRefreshTokens(userId: string): Promise<void> {
  const map = await getMap();
  const updates: Record<string, unknown> = {};
  for (const [id, data] of Object.entries(map)) {
    if (data.userId === userId) updates[`value.${id}`] = FieldValue.delete();
  }
  if (Object.keys(updates).length === 0) return;
  try {
    await getAdminDb().collection(SHARED_COL).doc(DOC).update(updates);
  } catch {
    // 문서가 없으면 무시
  }
}
