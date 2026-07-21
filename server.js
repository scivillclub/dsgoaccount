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
  const cookieOpts = { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', path: '/' };
  res.clearCookie('sv_access',  cookieOpts);
  res.clearCookie('sv_refresh', cookieOpts);
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

// ── Bytenode OAuth ────────────────────────────────────────────────────────────
const BYTENODE_CLIENT_ID     = process.env.BYTENODE_CLIENT_ID;
const BYTENODE_CLIENT_SECRET = process.env.BYTENODE_CLIENT_SECRET;
const BYTENODE_AUTH_URL      = 'https://bytenode-account.vercel.app/authorize';
const BYTENODE_TOKEN_URL     = 'https://bytenode-account.vercel.app/token';
const BYTENODE_USERINFO_URL  = 'https://bytenode-account.vercel.app/userinfo';

// GET /api/auth/bytenode — bytenode authorize로 리다이렉트
app.get('/api/auth/bytenode', (req, res) => {
  const redirect_uri = `${process.env.BASE_URL || 'https://dsgoaccount.vercel.app'}/api/auth/bytenode/callback`;
  const mode = req.query.mode === 'register' ? 'register' : 'login';
  const state = Buffer.from(JSON.stringify({ r: req.query.redirect_uri || '/', mode })).toString('base64url');
  const url = `${BYTENODE_AUTH_URL}?response_type=code&client_id=${BYTENODE_CLIENT_ID}&redirect_uri=${encodeURIComponent(redirect_uri)}&state=${state}`;
  res.redirect(url);
});

// GET /api/auth/bytenode/callback — 코드 교환 후 로그인 처리
app.get('/api/auth/bytenode/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code) return res.status(400).send('missing code');

  const redirect_uri = `${process.env.BASE_URL || 'https://dsgoaccount.vercel.app'}/api/auth/bytenode/callback`;

  // state에서 원래 redirect_uri + 로그인/가입 의도(mode) 복원
  let originalRedirectUri = '';
  let mode = 'login';
  try {
    const parsed = JSON.parse(Buffer.from(state, 'base64url').toString());
    originalRedirectUri = parsed.r || '';
    mode = parsed.mode === 'register' ? 'register' : 'login';
  } catch {}

  function backToLogin(bnError) {
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
    if (!accessToken) {
      console.error('[bytenode/callback] token response:', JSON.stringify(tokenData));
      return backToLogin('bytenode_error');
    }

    // 2) 유저 정보
    const userRes = await fetch(BYTENODE_USERINFO_URL, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const bnUser = await userRes.json().catch(() => null);
    const bnId = String(bnUser?.id || bnUser?.userId || bnUser?.sub || bnUser?.user?.id || '');
    if (!bnId) {
      console.error('[bytenode/callback] userinfo error:', JSON.stringify(bnUser));
      return backToLogin('bytenode_error');
    }

    // 3) Firestore에서 기존 계정 찾기
    const users = await getUsers();
    let user = users.find(u => u.bytenodeId === bnId);

    if (mode === 'login') {
      // 로그인 의도인데 연결된 계정이 없으면 새로 만들지 않고 에러로 돌려보낸다
      if (!user) return backToLogin('not_registered');
    } else {
      // 가입 의도인데 이미 연결된 계정이 있으면 그냥 로그인만 시켜준다
      if (!user) {
        const id = uuid();
        const username = `bn_${bnId}`.slice(0, 20).replace(/[^a-zA-Z0-9_]/g, '_');
        user = {
          id,
          username,
          email: bnUser.email || '',
          displayName: bnUser.displayName || bnUser.username || username,
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
      signAccess({ userId: user.id, role: user.role, sessionVersion: sv }),
      storeRefresh(refreshId, { userId: user.id, role: user.role, remember: true,
        sessionVersion: sv, expiresAt: Date.now() + REFRESH_TTL_LONG * 1000 }),
    ]);
    setAccessCookie(res, svAccessToken);
    setRefreshCookie(res, refreshId, true);

    // 5) 원래 redirect_uri로 복귀
    if (originalRedirectUri && originalRedirectUri !== '/') {
      // SSO 콜백 URL이면 토큰 직접 발급
      try {
        const url = new URL(originalRedirectUri);
        if (url.pathname.startsWith('/api/auth/sso')) {
          const ssoToken = await signSSO(user.id, user.role);
          url.searchParams.set('token', ssoToken);
          return res.redirect(url.toString());
        }
      } catch {}
      // 그 외 → redirect_uri 유지하며 홈으로 (프론트가 afterAuth로 처리)
      return res.redirect('/?redirect_uri=' + encodeURIComponent(originalRedirectUri));
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
