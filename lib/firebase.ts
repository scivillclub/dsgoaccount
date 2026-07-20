import { initializeApp, getApps } from "firebase/app";
import { initializeFirestore, getFirestore } from "firebase/firestore";
import { FirestoreAdapter, sharedPool, adminPool } from "./dbPool";

// 계정 DB (scivill-account-3c5c5) — Admin proxy가 여기에 쓰므로 읽기도 여기서
const accountsConfig = {
  apiKey:            process.env.NEXT_PUBLIC_ACCOUNTS_FIREBASE_API_KEY,
  authDomain:        process.env.NEXT_PUBLIC_ACCOUNTS_FIREBASE_AUTH_DOMAIN,
  projectId:         process.env.NEXT_PUBLIC_ACCOUNTS_FIREBASE_PROJECT_ID,
  storageBucket:     process.env.NEXT_PUBLIC_ACCOUNTS_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.NEXT_PUBLIC_ACCOUNTS_FIREBASE_MESSAGING_SENDER_ID,
  appId:             process.env.NEXT_PUBLIC_ACCOUNTS_FIREBASE_APP_ID,
};

// 콘텐츠 DB (scivill-2c3c4) — deepthink/nodetask 공유 콘텐츠용
const mainConfig = {
  apiKey:            process.env.NEXT_PUBLIC_FIREBASE_API_KEY,
  authDomain:        process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN,
  projectId:         process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
  storageBucket:     process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID,
  appId:             process.env.NEXT_PUBLIC_FIREBASE_APP_ID,
};

// WebChannel 'Listen' 스트림이 차단되는 네트워크(VPN/사내망 등)에서도 동작하도록
// long-polling으로 자동 폴백 (Firestore 공식 권장 안전한 기본값)
const firestoreOptions = { experimentalAutoDetectLongPolling: true } as const;

// 계정 DB 앱 초기화
const existingAccounts = getApps().find((a) => a.name === "accounts");
const accountsApp = existingAccounts ?? initializeApp(accountsConfig, "accounts");
export const accountsDb = existingAccounts
  ? getFirestore(accountsApp)
  : initializeFirestore(accountsApp, firestoreOptions);

// 콘텐츠 DB 앱 초기화
const existingMain = getApps().find((a) => a.name === "[DEFAULT]");
const mainApp = existingMain ?? initializeApp(mainConfig);
export const db = existingMain
  ? getFirestore(mainApp)
  : initializeFirestore(mainApp, firestoreOptions);

export const SHARED_COL = "scivill2";
export const usesSeparateAdminDb = true;

// 계정 어댑터 — users, creds, aiSettings 등 Admin SDK가 쓰는 곳
const accountsAdapter = new FirestoreAdapter(
  `계정 DB (${accountsConfig.projectId ?? "accounts"})`,
  accountsDb,
  SHARED_COL,
);

// sharedPool과 adminPool 모두 계정 DB로 통일
// (Admin proxy도 scivill-account-3c5c5에 쓰므로 읽기도 여기서 해야 동기화됨)
sharedPool.setup([accountsAdapter]);
adminPool.setup([accountsAdapter]);
