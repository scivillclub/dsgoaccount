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

const ALLOWED_ORIGINS = (process.env.SSO_ALLOWED_ORIGINS || '')
  .split(',').map(s => s.trim()).filter(Boolean);

// ── 미들웨어 ─────────────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      styleSrc:   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc:    ["'self'", "https://fonts.gstatic.com"],
      imgSrc:     ["'self'", "data:"],
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
app.use(express.static(PUB));

// ── 쿠키 파싱 (의존성 없이) ──────────────────────────────────────────────────
function parseCookies(req) {
  const raw = req.headers.cookie || '';
  return Object.fromEntries(raw.split(';').map(c => c.trim().split('=').map(decodeURIComponent)));
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

async function signSSO(userId, role) {
  return new SignJWT({ userId, role, sso: true })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('60s')
    .sign(SSO_SECRET);
}

async function verifySSO(token) {
  try {
    const { payload } = await jwtVerify(token, SSO_SECRET);
    if (!payload.sso) return null;
    return payload;
  } catch { return null; }
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
      id, username, email: email || '', displayName,
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
      signAccess({ userId: id, role: 'user', sessionVersion: sv }),
      storeRefresh(refreshId, { userId: id, role: 'user', remember: false,
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
      signAccess({ userId: user.id, role: user.role, sessionVersion: sv }),
      storeRefresh(refreshId, { userId: user.id, role: user.role,
        remember: !!remember, sessionVersion: sv, expiresAt: Date.now() + ttl * 1000 }),
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
  res.clearCookie('sv_access',  { path: '/' });
  res.clearCookie('sv_refresh', { path: '/' });
  res.json({ ok: true });
});

// GET /api/auth/me
app.get('/api/auth/me', requireAuth, async (req, res) => {
  try {
    const users = await getUsers();
    const user = users.find(u => u.id === req.session.userId);
    if (!user) return res.status(404).json({ ok: false, error: 'not_found' });
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
    const sv = await getSessionVersion();
    if (stored.sessionVersion !== sv) {
      await deleteRefresh(refreshId).catch(() => {});
      res.clearCookie('sv_access',  { path: '/' });
      res.clearCookie('sv_refresh', { path: '/' });
      return res.status(401).json({ ok: false, error: 'session_invalidated' });
    }

    const newId = newRefreshId();
    const ttl = stored.remember ? REFRESH_TTL_LONG : REFRESH_TTL_SHORT;
    const [accessToken] = await Promise.all([
      signAccess({ userId: stored.userId, role: stored.role, sessionVersion: sv }),
      deleteRefresh(refreshId),
      storeRefresh(newId, { ...stored, sessionVersion: sv, expiresAt: Date.now() + ttl * 1000 }),
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
    const url = new URL(redirectUri);
    const allowed = ALLOWED_ORIGINS.includes(url.origin)
      && url.pathname.startsWith('/api/auth/sso');
    if (!allowed && process.env.NODE_ENV === 'production')
      return res.status(400).json({ ok: false, error: 'invalid_redirect_uri' });

    const token = await signSSO(req.session.userId, req.session.role);
    url.searchParams.set('token', token);
    res.json({ ok: true, redirectUrl: url.toString() });
  } catch (e) {
    console.error('[sso/issue]', e);
    res.status(500).json({ ok: false, error: 'server_error' });
  }
});

// GET /api/auth/sso/verify (SP가 토큰 검증용으로 직접 호출)
app.get('/api/auth/sso/verify', async (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).json({ ok: false });
  const payload = await verifySSO(token);
  if (!payload) return res.status(401).json({ ok: false, error: 'invalid_token' });
  res.json({ ok: true, userId: payload.userId, role: payload.role });
});

// ── 정적 페이지 폴백 ─────────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(PUB, 'index.html'));
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`[dsgoaccount] http://localhost:${PORT}`));
}

module.exports = app;
