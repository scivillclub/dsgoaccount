/**
 * firebaseAdmin.ts — Firebase Admin SDK (서버사이드 전용)
 * 절대 클라이언트에 import하지 마세요.
 */
import { getApps, initializeApp, cert, App } from "firebase-admin/app";
import { getFirestore, Firestore } from "firebase-admin/firestore";

export const SHARED_COL = "scivill2";

let adminApp: App;
let adminDb: Firestore;

function getAdminApp(): App {
  if (adminApp) return adminApp;

  const existing = getApps().find((a) => a.name === "admin");
  if (existing) { adminApp = existing; return adminApp; }

  const sa = process.env.FIREBASE_SERVICE_ACCOUNT;
  if (!sa) throw new Error("FIREBASE_SERVICE_ACCOUNT 환경변수가 없습니다.");

  let parsed: object;
  try { parsed = JSON.parse(sa); }
  catch { parsed = JSON.parse(sa.replace(/\n/g, "\\n")); }

  adminApp = initializeApp({ credential: cert(parsed as Parameters<typeof cert>[0]) }, "admin");
  return adminApp;
}

export function getAdminDb(): Firestore {
  if (adminDb) return adminDb;
  adminDb = getFirestore(getAdminApp());
  return adminDb;
}
