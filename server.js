'use strict';
require('dotenv').config({ path: '.env.local' });

const express     = require('express');
const path        = require('path');
const crypto      = require('crypto');
const bcrypt      = require('bcryptjs');
const { v4: uuid } = require('uuid');
const helmet      = require('helmet');
const rateLimit   = require('express-rate-limit');
const cors        = require('cors');
const { SignJWT, jwtVerify } = require('jose');
const admin       = require('firebase-admin');

// ── Firebase 초기화 ──────────────────────────────────────────────────────────
const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT);
admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
const db = admin.firestore();
const SHARED_COL = 'shared';

// ── 설정 ─────────────────────────────────────────────────────────────────────
const app  = express();
const PORT = process.env.PORT || 3000;
const PUB  = path.join(__dirname, 'public');

const SESSION_SECRET = new TextEncoder().encode(
  process.env.SESSION_SECRET || (() => { throw new Error('SESSION_SECRET 없음'); })()
);
const SSO_SECRET = new TextEncoder().encode(process.env.SESSION_SECRET);

const DEFAULT_ALLOWED_ORIGINS = [
  'https://dsgo.vercel.app',
  'https://scivill.vercel.app',
  'https://scivill-deepthink.vercel.app',
  'https://scivill-nodetask.vercel.app',
  'https://scivill-sheet.vercel.app',
  'https://scivill-oryaform.vercel.app',
  'https://scivill-qrlink.vercel.app',
];
const ALLOWED_ORIGINS = Array.from(new Set([
  ...DEFAULT_ALLOWED_ORIGINS,
  ...(process.env.SSO_ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean),
]));
const ACCOUNT_SETTINGS_ORIGIN = new URL(
  process.env.ACCOUNT_SETTINGS_ORIGIN || 'https://dsgo.vercel.app'
).origin;

function isAllowedSSORedirect(redirectUri) {
  try {
    const url = new URL(String(redirectUri || ''));
    const isLocal = process.env.NODE_ENV !== 'production'
      && /^(localhost|127\.0\.0\.1)$/.test(url.hostname);
    return (ALLOWED_ORIGINS.includes(url.origin) || isLocal)
      && url.pathname === '/api/auth/sso';
  } catch {
    return false;
  }
}

// ── 미들웨어 ─────────────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc:    ["'self'"],
      scriptSrc:     ["'self'", "'unsafe-inline'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc:      ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:       ["'self'", "https://fonts.gstatic.com"],
      imgSrc:        ["'self'", "data:"],
    }
  }
}));
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin) || process.env.NODE_ENV !== 'production') cb(null, true);
    else cb(new Error('CORS 차단'));
  },
  credentials: true,
}));
app.use(express.json({ limit: '128kb' }));

// 인증 응답은 절대 캐시되면 안 된다 (Vercel 엣지/브라우저 캐시가 로그아웃 이전의
// 로그인 상태 응답을 그대로 재사용하면 "로그아웃해도 다시 로그인된 것처럼 보이는" 문제가 생긴다)
app.use('/api/auth', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

app.use(express.static(PUB));

// ── 쿠키 파싱 (의존성 없이) ──────────────────────────────────────────────────
function parseCookies(req) {
  const raw = req.headers.cookie || '';
  const cookies = {};
  for (const part of raw.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;
    try {
      const name = decodeURIComponent(part.slice(0, separator).trim());
      const value = decodeURIComponent(part.slice(separator + 1).trim());
      cookies[name] = value;
    } catch {
      // Ignore malformed cookie pairs instead of failing the whole auth request.
    }
  }
  return cookies;
}

function bytenodeCallbackUrl() {
  return new URL('/api/auth/bytenode/callback', process.env.BASE_URL || 'https://dsgoaccount.vercel.app').toString();
}

// ── Rate Limiter ──────────────────────────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 60_000, max: 10,
  message: { ok: false, error: 'too_many_requests' },
  standardHeaders: true, legacyHeaders: false,
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60_000, max: 5,
  message: { ok: false, error: 'too_many_attempts', retryAfter: 900 },
  standardHeaders: true, legacyHeaders: false,
  skipSuccessfulRequests: true,
});

// ── JWT 헬퍼 ─────────────────────────────────────────────────────────────────
const ACCESS_TTL         = 15 * 60;
const REFRESH_TTL_SHORT  = 24 * 60 * 60;
const REFRESH_TTL_LONG   = 30 * 24 * 60 * 60;

async function signAccess(payload) {
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${ACCESS_TTL}s`)
    .sign(SESSION_SECRET);
}

async function verifyAccess(token) {
  try {
    const { payload } = await jwtVerify(token, SESSION_SECRET);
    return payload;
  } catch { return null; }
}

async function signSSO(userId, role, audience) {
  return new SignJWT({ userId, role, sso: true })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setAudience(audience)
    .setExpirationTime('60s')
    .sign(SSO_SECRET);
}

async function verifySSO(token, audience) {
  try {
    const { payload } = await jwtVerify(token, SSO_SECRET, {
      algorithms: ['HS256'],
      audience,
    });
    if (!payload.sso || typeof payload.userId !== 'string' || !payload.userId) return null;
    return payload;
  } catch { return null; }
}

async function signOAuthState({ redirectUri = '', mode = 'login', linkUserId = '' }) {
  return new SignJWT({ redirectUri, mode, linkUserId, oauthState: true })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('10m')
    .sign(SSO_SECRET);
}

async function verifyOAuthState(token) {
  try {
    const { payload } = await jwtVerify(String(token || ''), SSO_SECRET, { algorithms: ['HS256'] });
    if (!payload.oauthState) return null;
    return {
      redirectUri: typeof payload.redirectUri === 'string' ? payload.redirectUri : '',
      mode: ['register', 'link'].includes(payload.mode) ? payload.mode : 'login',
      linkUserId: typeof payload.linkUserId === 'string' ? payload.linkUserId : '',
    };
  } catch {
    return null;
  }
}

function setOAuthStateCookie(res, state) {
  res.cookie('sv_oauth_state', state, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 10 * 60 * 1000,
    path: '/api/auth/bytenode/callback',
  });
}

function hasMatchingOAuthState(req, state) {
  const stored = parseCookies(req).sv_oauth_state;
  if (!stored || !state) return false;
  const left = Buffer.from(stored);
  const right = Buffer.from(String(state));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

// ── Refresh Token (Firestore) ─────────────────────────────────────────────────
function newRefreshId() { return crypto.randomBytes(32).toString('hex'); }

async function storeRefresh(id, data) {
  await db.collection('refreshTokens').doc(id).set(data);
}
async function getRefresh(id) {
  const snap = await db.collection('refreshTokens').doc(id).get();
  return snap.exists ? snap.data() : null;
}
async function deleteRefresh(id) {
  await db.collection('refreshTokens').doc(id).delete();
}

// ── 쿠키 세터 ────────────────────────────────────────────────────────────────
function setAccessCookie(res, token) {
  res.cookie('sv_access', token, {
    httpOnly: true, secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax', maxAge: ACCESS_TTL * 1000, path: '/',
  });
}
function setRefreshCookie(res, id, remember) {
  res.cookie('sv_refresh', id, {
    httpOnly: true, secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax', maxAge: (remember ? REFRESH_TTL_LONG : REFRESH_TTL_SHORT) * 1000, path: '/',
  });
}

// ── 세션 확인 미들웨어 ────────────────────────────────────────────────────────
async function requireAuth(req, res, next) {
  const cookies = parseCookies(req);
  const token = cookies['sv_access'];
  if (!token) return res.status(401).json({ ok: false, error: 'unauthenticated' });
  const payload = await verifyAccess(token);
  if (!payload) return res.status(401).json({ ok: false, error: 'token_expired' });
  req.session = payload;
  next();
}

// ── PBKDF2 해시 ──────────────────────────────────────────────────────────────
function hashPw(password, userId) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(password, `${userId}.sv25`, 100_000, 32, 'sha256', (err, buf) =>
      err ? reject(err) : resolve(buf.toString('hex'))
    );
  });
}

// ── DB 헬퍼 ──────────────────────────────────────────────────────────────────
async function getUsers()  {
  const s = await db.collection(SHARED_COL).doc('users').get();
  return s.exists ? (s.data()?.value ?? []) : [];
}
async function getCreds()  {
  const s = await db.collection(SHARED_COL).doc('creds').get();
  return s.exists ? (s.data()?.value ?? {}) : {};
}
async function saveUsers(users) {
  await db.collection(SHARED_COL).doc('users').set({ value: users });
}
async function saveCreds(creds) {
  await db.collection(SHARED_COL).doc('creds').set({ value: creds });
}
async function getSessionVersion() {
  const s = await db.collection(SHARED_COL).doc('aiSettings').get();
  return s.exists ? (s.data()?.value?.sessionVersion ?? 0) : 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
// API 라우트
// ═══════════════════════════════════════════════════════════════════════════════

// POST /api/auth/register
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { username, email, password, displayName } = req.body || {};
  if (!username || !password || !displayName)
    return res.status(400).json({ ok: false, error: 'missing_fields' });
  if (password.length < 6 || password.length > 128)
    return res.status(400).json({ ok: false, error: 'invalid_password' });
  if (!/^[a-zA-Z0-9_]{3,20}$/.test(username))
    return res.status(400).json({ ok: false, error: 'invalid_username' });

  try {
    const users = await getUsers();
    if (users.find(u => u.username === username || (email && u.email === email)))
      return res.status(409).json({ ok: false, error: 'already_exists' });

    const id = uuid();
    const pw = await hashPw(password, id);
    const user = {
      id, username, email: email || '', displayName, nickname: displayName, name: displayName,
      role: 'user', isBanned: false, createdAt: Date.now(),
    };
    const creds = await getCreds();
    creds[id] = pw;
    await Promise.all([
      saveUsers([...users, user]),
      saveCreds(creds),
    ]);

    const sv = await getSessionVersion();
    const refreshId = newRefreshId();
    const [accessToken] = await Promise.all([
      signAccess({ userId: id, role: 'user', sessionVersion: sv, authVersion: 0 }),
      storeRefresh(refreshId, { userId: id, role: 'user', remember: false, authVersion: 0,
        sessionVersion: sv, expiresAt: Date.now() + REFRESH_TTL_SHORT * 1000 }),
    ]);
    setAccessCookie(res, accessToken);
    setRefreshCookie(res, refreshId, false);
    res.json({ ok: true, user: { id, username, displayName, role: 'user' } });
  } catch (e) {
    console.error('[register]', e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', loginLimiter, async (req, res) => {
  const { username, email, password, remember } = req.body || {};
  const identifier = String(username ?? email ?? '').trim();
  if (!identifier || !password)
    return res.status(400).json({ ok: false, error: 'missing_fields' });

  try {
    const [users, creds] = await Promise.all([getUsers(), getCreds()]);
    const user = users.find(u => u.username === identifier || u.email === identifier);
    if (!user) return res.status(401).json({ ok: false, error: 'invalid_credentials' });
    if (user.isBanned) return res.status(403).json({ ok: false, error: 'banned' });

    const hashed = await hashPw(password, user.id);
    if (creds[user.id] !== hashed)
      return res.status(401).json({ ok: false, error: 'invalid_credentials' });

    const sv = await getSessionVersion();
    const refreshId = newRefreshId();
    const ttl = remember ? REFRESH_TTL_LONG : REFRESH_TTL_SHORT;
    const [accessToken] = await Promise.all([
      signAccess({ userId: user.id, role: user.role, sessionVersion: sv, authVersion: user.authVersion || 0 }),
      storeRefresh(refreshId, { userId: user.id, role: user.role,
        remember: !!remember, sessionVersion: sv, authVersion: user.authVersion || 0, expiresAt: Date.now() + ttl * 1000 }),
    ]);
    setAccessCookie(res, accessToken);
    setRefreshCookie(res, refreshId, !!remember);
    const { id, username: un, displayName, role } = user;
    res.json({ ok: true, user: { id, username: un, displayName, role } });
  } catch (e) {
    console.error('[login]', e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// POST /api/auth/logout
app.post('/api/auth/logout', async (req, res) => {
  const cookies = parseCookies(req);
  const refreshId = cookies['sv_refresh'];
  if (refreshId) await deleteRefresh(refreshId).catch(() => {});
  const cookieOpts = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' };
  res.clearCookie('sv_access',  cookieOpts);
  res.clearCookie('sv_refresh', cookieOpts);
  res.json({ ok: true });
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const [users, sessionVersion] = await Promise.all([getUsers(), getSessionVersion()]);
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ ok: false, error: 'not_found' });
    if (user.isBanned) return res.status(403).json({ ok: false, error: 'banned' });
    if (req.session.sessionVersion !== sessionVersion) {
      return res.status(401).json({ ok: false, error: 'session_invalidated' });
    }
    if ((req.session.authVersion || 0) !== (user.authVersion || 0)) {
      return res.status(401).json({ ok: false, error: 'account_session_invalidated' });
    }
    const { id, username, displayName, role, email } = user;
    res.json({ ok: true, user: { id, username, displayName, role, email } });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// POST /api/auth/refresh
app.post('/api/auth/refresh', async (req, res) => {
  const cookies = parseCookies(req);
  const refreshId = cookies['sv_refresh'];
  if (!refreshId) return res.status(401).json({ ok: false });

  const stored = await getRefresh(refreshId).catch(() => null);
  if (!stored || stored.expiresAt < Date.now())
    return res.status(401).json({ ok: false, error: 'refresh_expired' });

  try {
    const [sv, users] = await Promise.all([getSessionVersion(), getUsers()]);
    if (stored.sessionVersion !== sv) {
      await deleteRefresh(refreshId).catch(() => {});
      res.clearCookie('sv_access',  { path: '/' });
      res.clearCookie('sv_refresh', { path: '/' });
      return res.status(401).json({ ok: false, error: 'session_invalidated' });
    }

    const user = users.find(u => u.id === stored.userId);
    if (!user || user.isBanned) {
      await deleteRefresh(refreshId).catch(() => {});
      res.clearCookie('sv_access',  { path: '/' });
      res.clearCookie('sv_refresh', { path: '/' });
      return res.status(401).json({ ok: false, error: user ? 'banned' : 'not_found' });
    }
    if ((stored.authVersion || 0) !== (user.authVersion || 0)) {
      await deleteRefresh(refreshId).catch(() => {});
      res.clearCookie('sv_access',  { path: '/' });
      res.clearCookie('sv_refresh', { path: '/' });
      return res.status(401).json({ ok: false, error: 'account_session_invalidated' });
    }

    const newId = newRefreshId();
    const ttl = stored.remember ? REFRESH_TTL_LONG : REFRESH_TTL_SHORT;
    const [accessToken] = await Promise.all([
      signAccess({ userId: stored.userId, role: user.role, sessionVersion: sv, authVersion: user.authVersion || 0 }),
      deleteRefresh(refreshId),
      storeRefresh(newId, { ...stored, role: user.role, sessionVersion: sv,
        authVersion: user.authVersion || 0, expiresAt: Date.now() + ttl * 1000 }),
    ]);
    setAccessCookie(res, accessToken);
    setRefreshCookie(res, newId, stored.remember);
    res.json({ ok: true });
  } catch (e) {
    console.error('[refresh]', e);
    res.status(500).json({ ok: false });
  }
});

// GET /api/auth/sso/issue?redirect_uri=...
app.get('/api/auth/sso/issue', requireAuth, async (req, res) => {
  const redirectUri = req.query.redirect_uri;
  if (!redirectUri) return res.status(400).json({ ok: false, error: 'missing_redirect_uri' });

  try {
    if (!isAllowedSSORedirect(redirectUri))
      return res.status(400).json({ ok: false, error: 'invalid_redirect_uri' });

    const [users, sessionVersion] = await Promise.all([getUsers(), getSessionVersion()]);
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(401).json({ ok: false, error: 'not_found' });
    if (user.isBanned) return res.status(403).json({ ok: false, error: 'banned' });
    if (req.session.sessionVersion !== sessionVersion) {
      return res.status(401).json({ ok: false, error: 'session_invalidated' });
    }
    if ((req.session.authVersion || 0) !== (user.authVersion || 0)) {
      return res.status(401).json({ ok: false, error: 'account_session_invalidated' });
    }

    const url = new URL(redirectUri);
    const token = await signSSO(user.id, user.role, url.origin);
    url.searchParams.set('token', token);
    res.json({ ok: true, redirectUrl: url.toString() });
  } catch (e) {
    console.error('[sso/issue]', e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// SP가 서버 간 호출로 SSO 토큰을 검증한다. POST를 기본으로 두어 토큰이 URL 로그에 남지 않게 한다.
async function handleSSOVerify(req, res) {
  const token = req.body?.token || req.query.token;
  const requestedAudience = req.body?.audience || req.query.audience;
  if (!token || !requestedAudience) {
    return res.status(400).json({ ok: false, error: 'missing_token_or_audience' });
  }

  let audience;
  try {
    const parsed = new URL(String(requestedAudience));
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error('invalid protocol');
    audience = parsed.origin;
  } catch {
    return res.status(400).json({ ok: false, error: 'invalid_audience' });
  }

  const payload = await verifySSO(token, audience);
  if (!payload) return res.status(401).json({ ok: false, error: 'invalid_token' });

  try {
    const users = await getUsers();
    const user = users.find(u => u.id === payload.userId);
    if (!user) return res.status(401).json({ ok: false, error: 'user_not_found' });
    if (user.isBanned) return res.status(403).json({ ok: false, error: 'user_banned' });

    res.json({
      ok: true,
      userId: user.id,
      role: user.role || 'user',
      user: {
        id: user.id,
        username: user.username || '',
        email: user.email || '',
        displayName: user.displayName || user.nickname || user.name || user.username || '',
        role: user.role || 'user',
      },
    });
  } catch (e) {
    console.error('[sso/verify]', e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
}
app.post('/api/auth/sso/verify', handleSSOVerify);
app.get('/api/auth/sso/verify', handleSSOVerify); // 이전 배포와의 호환

// ── 통합 계정 설정 API ───────────────────────────────────────────────────────
function requireAccountOrigin(req, res, next) {
  const origin = req.get('origin');
  const isLocal = process.env.NODE_ENV !== 'production'
    && origin && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin);
  if (origin !== ACCOUNT_SETTINGS_ORIGIN && !isLocal) {
    return res.status(403).json({ ok: false, error: 'invalid_origin' });
  }
  next();
}

async function loadCurrentAccount(req) {
  const [users, creds, sessionVersion] = await Promise.all([
    getUsers(), getCreds(), getSessionVersion(),
  ]);
  const user = users.find(u => u.id === req.session.userId);
  if (!user || user.isBanned || req.session.sessionVersion !== sessionVersion
    || (req.session.authVersion || 0) !== (user.authVersion || 0)) return null;
  return { user, hasPassword: typeof creds[user.id] === 'string' && !!creds[user.id] };
}

function publicAccountProfile(user, hasPassword) {
  return {
    id: user.id,
    username: user.username || '',
    displayName: user.displayName || user.nickname || user.name || user.username || '',
    email: user.email || '',
    role: user.role || 'user',
    hasPassword,
    hasBytenode: !!user.bytenodeId,
    needsLocalCredentials: !!user.bytenodeId && !hasPassword,
  };
}

app.get('/api/account/profile', requireAuth, async (req, res) => {
  try {
    const account = await loadCurrentAccount(req);
    if (!account) return res.status(401).json({ ok: false, error: 'invalid_session' });
    res.json({ ok: true, profile: publicAccountProfile(account.user, account.hasPassword) });
  } catch (e) {
    console.error('[account/profile:get]', e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

app.patch('/api/account/profile', requireAuth, requireAccountOrigin, authLimiter, async (req, res) => {
  const displayName = String(req.body?.displayName || '').trim();
  const email = String(req.body?.email || '').trim().toLowerCase();
  if (displayName.length < 1 || displayName.length > 40) {
    return res.status(400).json({ ok: false, error: 'invalid_display_name' });
  }
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ ok: false, error: 'invalid_email' });
  }
  try {
    let updated;
    await db.runTransaction(async tx => {
      const ref = db.collection(SHARED_COL).doc('users');
      const snap = await tx.get(ref);
      const users = snap.exists ? (snap.data()?.value ?? []) : [];
      const index = users.findIndex(u => u.id === req.session.userId);
      if (index < 0 || users[index].isBanned) throw new Error('invalid_session');
      if (email && users.some((u, i) => i !== index && String(u.email || '').toLowerCase() === email)) {
        throw new Error('email_taken');
      }
      updated = { ...users[index], displayName, nickname: displayName, email };
      users[index] = updated;
      tx.set(ref, { value: users });
    });
    const creds = await getCreds();
    res.json({ ok: true, profile: publicAccountProfile(updated, !!creds[updated.id]) });
  } catch (e) {
    const error = e?.message === 'email_taken' ? 'email_taken'
      : e?.message === 'invalid_session' ? 'invalid_session' : 'server_error';
    res.status(error === 'server_error' ? 500 : error === 'email_taken' ? 409 : 401).json({ ok: false, error });
  }
});

app.post('/api/account/local-credentials', requireAuth, requireAccountOrigin, authLimiter, async (req, res) => {
  const username = String(req.body?.username || '').trim();
  const currentPassword = String(req.body?.currentPassword || '');
  const newPassword = String(req.body?.newPassword || '');
  if (newPassword.length < 8 || newPassword.length > 128 || !/[A-Za-z]/.test(newPassword) || !/\d/.test(newPassword)) {
    return res.status(400).json({ ok: false, error: 'weak_password' });
  }

  try {
    const account = await loadCurrentAccount(req);
    if (!account) return res.status(401).json({ ok: false, error: 'invalid_session' });
    if (!account.hasPassword && !/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
      return res.status(400).json({ ok: false, error: 'invalid_username' });
    }
    const credsBefore = await getCreds();
    if (account.hasPassword) {
      const currentHash = await hashPw(currentPassword, account.user.id);
      const stored = String(credsBefore[account.user.id] || '');
      const left = Buffer.from(currentHash);
      const right = Buffer.from(stored);
      if (left.length !== right.length || !crypto.timingSafeEqual(left, right)) {
        return res.status(403).json({ ok: false, error: 'invalid_current_password' });
      }
    }

    const newHash = await hashPw(newPassword, account.user.id);
    let updatedUser;
    await db.runTransaction(async tx => {
      const usersRef = db.collection(SHARED_COL).doc('users');
      const credsRef = db.collection(SHARED_COL).doc('creds');
      const [usersSnap, credsSnap] = await Promise.all([tx.get(usersRef), tx.get(credsRef)]);
      const users = usersSnap.exists ? (usersSnap.data()?.value ?? []) : [];
      const creds = credsSnap.exists ? (credsSnap.data()?.value ?? {}) : {};
      const index = users.findIndex(u => u.id === req.session.userId);
      if (index < 0 || users[index].isBanned) throw new Error('invalid_session');
      if (!creds[req.session.userId]) {
        const normalized = username.toLowerCase();
        if (users.some((u, i) => i !== index && String(u.username || '').toLowerCase() === normalized)) {
          throw new Error('username_taken');
        }
        users[index] = { ...users[index], username };
      }
      users[index] = { ...users[index], authVersion: (users[index].authVersion || 0) + 1 };
      creds[req.session.userId] = newHash;
      updatedUser = users[index];
      tx.set(usersRef, { value: users });
      tx.set(credsRef, { value: creds });
    });

    // Password changes invalidate other central refresh sessions but keep this browser signed in.
    const currentRefresh = parseCookies(req).sv_refresh;
    const refreshSnap = await db.collection('refreshTokens').where('userId', '==', req.session.userId).get();
    const sessionVersion = await getSessionVersion();
    const freshAccess = await signAccess({
      userId: updatedUser.id,
      role: updatedUser.role,
      sessionVersion,
      authVersion: updatedUser.authVersion,
    });
    await Promise.all(refreshSnap.docs.map(doc => {
      if (doc.id === currentRefresh) {
        return doc.ref.update({ authVersion: updatedUser.authVersion, role: updatedUser.role, sessionVersion });
      }
      return doc.ref.delete();
    }));
    setAccessCookie(res, freshAccess);
    res.json({ ok: true, profile: publicAccountProfile(updatedUser, true) });
  } catch (e) {
    const error = ['username_taken', 'invalid_session'].includes(e?.message) ? e.message : 'server_error';
    res.status(error === 'server_error' ? 500 : error === 'username_taken' ? 409 : 401).json({ ok: false, error });
  }
});

app.post('/api/account/bytenode/unlink', requireAuth, requireAccountOrigin, authLimiter, async (req, res) => {
  try {
    const account = await loadCurrentAccount(req);
    if (!account) return res.status(401).json({ ok: false, error: 'invalid_session' });
    if (!account.hasPassword) return res.status(409).json({ ok: false, error: 'local_credentials_required' });
    let updated;
    await db.runTransaction(async tx => {
      const ref = db.collection(SHARED_COL).doc('users');
      const snap = await tx.get(ref);
      const users = snap.exists ? (snap.data()?.value ?? []) : [];
      const index = users.findIndex(u => u.id === req.session.userId);
      if (index < 0) throw new Error('invalid_session');
      updated = { ...users[index] };
      delete updated.bytenodeId;
      users[index] = updated;
      tx.set(ref, { value: users });
    });
    res.json({ ok: true, profile: publicAccountProfile(updated, true) });
  } catch (e) {
    res.status(e?.message === 'invalid_session' ? 401 : 500).json({ ok: false, error: e?.message || 'server_error' });
  }
});

app.get('/api/account/bytenode/link', requireAuth, async (req, res) => {
  if (!BYTENODE_CLIENT_ID || !BYTENODE_CLIENT_SECRET) {
    return res.redirect(`${ACCOUNT_SETTINGS_ORIGIN}/settings?bytenode=config_error`);
  }
  try {
    const account = await loadCurrentAccount(req);
    if (!account) return res.redirect(`${ACCOUNT_SETTINGS_ORIGIN}/api/auth/login?return_to=%2Fsettings`);
    const state = await signOAuthState({ mode: 'link', linkUserId: account.user.id });
    setOAuthStateCookie(res, state);
    const redirectUri = bytenodeCallbackUrl();
    const url = new URL(BYTENODE_AUTH_URL);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('client_id', BYTENODE_CLIENT_ID);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('state', state);
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.redirect(url.toString());
  } catch (e) {
    console.error('[account/bytenode/link]', e);
    res.redirect(`${ACCOUNT_SETTINGS_ORIGIN}/settings?bytenode=error`);
  }
});

// ── Bytenode OAuth ────────────────────────────────────────────────────────────
const BYTENODE_CLIENT_ID     = process.env.BYTENODE_CLIENT_ID;
const BYTENODE_CLIENT_SECRET = process.env.BYTENODE_CLIENT_SECRET;
const BYTENODE_AUTH_URL      = 'https://bytenode-account.vercel.app/authorize';
const BYTENODE_TOKEN_URL     = 'https://bytenode-account.vercel.app/token';
const BYTENODE_USERINFO_URL  = 'https://bytenode-account.vercel.app/userinfo';

// GET /api/auth/bytenode — bytenode authorize로 리다이렉트
app.get('/api/auth/bytenode', async (req, res) => {
  if (!BYTENODE_CLIENT_ID || !BYTENODE_CLIENT_SECRET) {
    return res.redirect('/?bn_error=bytenode_config');
  }
  const redirect_uri = bytenodeCallbackUrl();
  const mode = req.query.mode === 'register' ? 'register' : 'login';
  const requestedRedirect = String(req.query.redirect_uri || '');
  const originalRedirectUri = isAllowedSSORedirect(requestedRedirect) ? requestedRedirect : '';
  const state = await signOAuthState({ redirectUri: originalRedirectUri, mode });
  setOAuthStateCookie(res, state);
  const url = `${BYTENODE_AUTH_URL}?response_type=code&client_id=${BYTENODE_CLIENT_ID}&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${state}`;
  res.redirect(url);
});

// GET /api/auth/bytenode/callback — 코드 교환 후 로그인 처리
app.get('/api/auth/bytenode/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.status(400).send('missing code');

  const redirect_uri = bytenodeCallbackUrl();

  // 서명된 state에서 원래 redirect_uri + 로그인/가입 의도(mode) 복원
  const oauthState = await verifyOAuthState(state);
  if (!oauthState || !hasMatchingOAuthState(req, state)) return res.redirect('/?bn_error=invalid_state');
  res.clearCookie('sv_oauth_state', { path: '/api/auth/bytenode/callback' });
  const { redirectUri: originalRedirectUri, mode, linkUserId } = oauthState;

  function backToLogin(bnError) {
    if (mode === 'link') {
      return res.redirect(`${ACCOUNT_SETTINGS_ORIGIN}/settings?bytenode=${encodeURIComponent(bnError)}`);
    }
    const qs = new URLSearchParams({ bn_error: bnError });
    if (originalRedirectUri && originalRedirectUri !== '/') qs.set('redirect_uri', originalRedirectUri);
    return res.redirect('/?' + qs.toString());
  }

  try {
    // 1) 코드 → 토큰
    const tokenRes = await fetch(BYTENODE_TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ grant_type: 'authorization_code', code, client_id: BYTENODE_CLIENT_ID, client_secret: BYTENODE_CLIENT_SECRET, redirect_uri }),
    });
    const tokenData = await tokenRes.json().catch(() => null);
    const accessToken = tokenData && (tokenData.access_token || tokenData.token);
    if (!tokenRes.ok || !accessToken) {
      console.error('[bytenode/callback] token response:', JSON.stringify(tokenData));
      return backToLogin('bytenode_error');
    }

    // 2) 유저 정보
    const userRes = await fetch(BYTENODE_USERINFO_URL, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const bnUser = await userRes.json().catch(() => null);
    const bnId = String(bnUser?.id || bnUser?.userId || bnUser?.sub || bnUser?.user?.id || '');
    if (!userRes.ok || !bnId) {
      console.error('[bytenode/callback] userinfo error:', JSON.stringify(bnUser));
      return backToLogin('bytenode_error');
    }

    // 3) Firestore에서 기존 계정 찾기
    const users = await getUsers();
    let user = users.find(u => u.bytenodeId === bnId);

    if (mode === 'link') {
      if (!linkUserId) return backToLogin('invalid_state');
      if (user && user.id !== linkUserId) return backToLogin('already_linked');
      const linkIndex = users.findIndex(u => u.id === linkUserId);
      if (linkIndex < 0 || users[linkIndex].isBanned) return backToLogin('invalid_session');
      user = {
        ...users[linkIndex],
        bytenodeId: bnId,
        email: users[linkIndex].email || bnUser.email || '',
      };
      users[linkIndex] = user;
      await saveUsers(users);
    } else if (mode === 'login') {
      // 로그인 의도인데 연결된 계정이 없으면 새로 만들지 않고 에러로 돌려보낸다
      if (!user) return backToLogin('not_registered');
    } else {
      // 가입 의도인데 이미 연결된 계정이 있으면 그냥 로그인만 시켜준다
      if (!user) {
        const id = uuid();
        const username = `bn_${bnId}`.slice(0, 20).replace(/[^a-zA-Z0-9_]/g, '_');
        const displayName = bnUser.displayName || bnUser.username || username;
        user = {
          id,
          username,
          email: bnUser.email || '',
          displayName,
          nickname: displayName,
          name: displayName,
          role: 'user',
          isBanned: false,
          createdAt: Date.now(),
          bytenodeId: bnId,
        };
        await saveUsers([...users, user]);
      }
    }

    if (user.isBanned) return res.status(403).send('계정이 정지되었습니다.');

    // 4) 세션 발급
    const sv = await getSessionVersion();
    const refreshId = newRefreshId();
    const [svAccessToken] = await Promise.all([
      signAccess({ userId: user.id, role: user.role, sessionVersion: sv, authVersion: user.authVersion || 0 }),
      storeRefresh(refreshId, { userId: user.id, role: user.role, remember: true,
        sessionVersion: sv, authVersion: user.authVersion || 0, expiresAt: Date.now() + REFRESH_TTL_LONG * 1000 }),
    ]);
    setAccessCookie(res, svAccessToken);
    setRefreshCookie(res, refreshId, true);

    // 5) 원래 redirect_uri로 복귀
    if (mode === 'link') {
      return res.redirect(`${ACCOUNT_SETTINGS_ORIGIN}/settings?bytenode=linked`);
    }
    if (originalRedirectUri) {
      // SSO 콜백 URL이면 토큰 직접 발급
      const url = new URL(originalRedirectUri);
      const ssoToken = await signSSO(user.id, user.role, url.origin);
      url.searchParams.set('token', ssoToken);
      res.setHeader('Referrer-Policy', 'no-referrer');
      return res.redirect(url.toString());
    }
    res.redirect('/');
  } catch (e) {
    console.error('[bytenode/callback]', e);
    res.status(500).send('server error');
  }
});

// ── 정적 페이지 폴백 ─────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(PUB, 'index.html'));
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`[dsgoaccount] http://localhost:${PORT}`));
}

module.exports = app;
