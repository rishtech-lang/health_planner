const path = require('path');
const crypto = require('crypto');
require('dotenv').config();

const compression = require('compression');
const cookieParser = require('cookie-parser');
const express = require('express');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const { OAuth2Client } = require('google-auth-library');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const IS_PROD = process.env.NODE_ENV === 'production';
const ROOT = __dirname;

const CONFIG = {
  googleClientId: process.env.GOOGLE_CLIENT_ID || '',
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
  googleRedirectUri: process.env.GOOGLE_REDIRECT_URI || `http://localhost:${PORT}/auth/google/callback`,
  sessionSecret: process.env.SESSION_SECRET || 'dev-only-change-me',
  allowedOrigins: (process.env.ALLOWED_ORIGINS || `http://localhost:${PORT}`).split(',').map(v => v.trim()).filter(Boolean)
};

const COOKIE = {
  session: 'bodyxp_server_session',
  oauthState: 'bodyxp_oauth_state',
  oauthNonce: 'bodyxp_oauth_nonce'
};

const oauth2Client = new OAuth2Client(
  CONFIG.googleClientId,
  CONFIG.googleClientSecret,
  CONFIG.googleRedirectUri
);

function base64url(input) {
  return Buffer.from(input).toString('base64url');
}

function sign(value) {
  return crypto.createHmac('sha256', CONFIG.sessionSecret).update(value).digest('base64url');
}

function createSignedSession(payload) {
  const body = base64url(JSON.stringify(payload));
  return `${body}.${sign(body)}`;
}

function readSignedSession(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [body, signature] = token.split('.');
  const expected = sign(body);
  const actualBuffer = Buffer.from(signature);
  const expectedBuffer = Buffer.from(expected);
  if (actualBuffer.length !== expectedBuffer.length) return null;
  if (!crypto.timingSafeEqual(actualBuffer, expectedBuffer)) return null;
  const parsed = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  if (!parsed.expiresAt || Date.now() > parsed.expiresAt) return null;
  return parsed;
}

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function initialsFor(name) {
  const clean = String(name || '').trim();
  if (!clean) return 'GU';
  const parts = clean.split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return `${parts[0][0]}${parts[1][0]}`.toUpperCase();
  return clean.slice(0, 2).toUpperCase();
}

function publicSessionFromGoogle(payload, displayName = payload.name) {
  const name = String(displayName || payload.name || 'User').trim() || 'User';
  return {
    mode: 'google',
    googleSub: payload.sub,
    name,
    email: payload.email || '',
    picture: payload.picture || '',
    initials: initialsFor(name),
    createdAt: new Date().toISOString(),
    expiresAt: Date.now() + 1000 * 60 * 60 * 24 * 7
  };
}

function setSessionCookie(res, session) {
  res.cookie(COOKIE.session, createSignedSession(session), {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    maxAge: 1000 * 60 * 60 * 24 * 7,
    path: '/'
  });
}

function clearAuthCookies(res) {
  const options = { httpOnly: true, secure: IS_PROD, sameSite: 'lax', path: '/' };
  res.clearCookie(COOKIE.session, options);
  res.clearCookie(COOKIE.oauthState, options);
  res.clearCookie(COOKIE.oauthNonce, options);
}

function requireAuth(req, res, next) {
  const session = readSignedSession(req.cookies[COOKIE.session]);
  if (!session) return res.status(401).json({ authenticated: false });
  req.session = session;
  next();
}

function verifySameOrigin(req, res, next) {
  const origin = req.get('origin');
  if (origin && !CONFIG.allowedOrigins.includes(origin)) {
    return res.status(403).json({ error: 'Origin is not allowed.' });
  }
  next();
}

app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", 'https://accounts.google.com'],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https://lh3.googleusercontent.com'],
      connectSrc: ["'self'", 'https://accounts.google.com', 'https://oauth2.googleapis.com'],
      frameSrc: ['https://accounts.google.com'],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"]
    }
  }
}));
app.use(compression());
app.use(express.json({ limit: '10kb' }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false }));

app.get('/api/health', (_req, res) => {
  res.json({ ok: true, service: 'bodyxp', time: new Date().toISOString() });
});

app.get('/api/session', (req, res) => {
  const session = readSignedSession(req.cookies[COOKIE.session]);
  res.json({ authenticated: Boolean(session), session: session || null });
});

app.post('/api/profile', verifySameOrigin, requireAuth, (req, res) => {
  const name = String(req.body.name || '').trim();
  if (name.length < 1 || name.length > 80) return res.status(400).json({ error: 'Name must be 1-80 characters.' });
  const updated = { ...req.session, name, initials: initialsFor(name) };
  setSessionCookie(res, updated);
  res.json({ ok: true, session: updated });
});

app.post('/auth/guest', verifySameOrigin, (req, res) => {
  const name = String(req.body.name || 'Guest').trim().slice(0, 80) || 'Guest';
  const session = {
    mode: 'guest',
    name,
    initials: initialsFor(name),
    createdAt: new Date().toISOString(),
    expiresAt: Date.now() + 1000 * 60 * 60 * 24 * 7
  };
  setSessionCookie(res, session);
  res.json({ ok: true, session });
});

app.get('/auth/google', (req, res) => {
  if (!CONFIG.googleClientId || !CONFIG.googleClientSecret) {
    return res.status(500).send('Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.');
  }

  const state = randomToken();
  const nonce = randomToken();
  const cookieOptions = { httpOnly: true, secure: IS_PROD, sameSite: 'lax', maxAge: 10 * 60 * 1000, path: '/' };
  res.cookie(COOKIE.oauthState, state, cookieOptions);
  res.cookie(COOKIE.oauthNonce, nonce, cookieOptions);

  const url = oauth2Client.generateAuthUrl({
    access_type: 'online',
    include_granted_scopes: false,
    prompt: 'select_account',
    scope: ['openid', 'email', 'profile'],
    state,
    nonce
  });

  res.redirect(url);
});

app.get('/auth/google/callback', async (req, res, next) => {
  try {
    if (req.query.error) return res.redirect(`/signin.html?error=${encodeURIComponent(req.query.error)}`);
    if (!req.query.code || !req.query.state) return res.redirect('/signin.html?error=missing_oauth_response');
    if (req.query.state !== req.cookies[COOKIE.oauthState]) return res.redirect('/signin.html?error=invalid_state');

    const { tokens } = await oauth2Client.getToken(String(req.query.code));
    if (!tokens.id_token) return res.redirect('/signin.html?error=missing_id_token');

    const ticket = await oauth2Client.verifyIdToken({ idToken: tokens.id_token, audience: CONFIG.googleClientId });
    const payload = ticket.getPayload();
    if (!payload || payload.nonce !== req.cookies[COOKIE.oauthNonce]) return res.redirect('/signin.html?error=invalid_nonce');

    const session = publicSessionFromGoogle(payload);
    setSessionCookie(res, session);
    res.clearCookie(COOKIE.oauthState, { path: '/' });
    res.clearCookie(COOKIE.oauthNonce, { path: '/' });
    res.redirect('/signin.html?completeProfile=1');
  } catch (err) {
    next(err);
  }
});

app.post('/auth/logout', verifySameOrigin, (req, res) => {
  clearAuthCookies(res);
  res.json({ ok: true });
});

app.use(express.static(ROOT, { extensions: ['html'], maxAge: IS_PROD ? '1h' : 0 }));
app.get('/', (_req, res) => res.sendFile(path.join(ROOT, 'index.html')));

app.use((err, _req, res, _next) => {
  console.error('[bodyxp:error]', err);
  res.status(500).json({ error: 'Internal server error.' });
});

app.listen(PORT, () => {
  console.log(`BodyXP listening on http://localhost:${PORT}`);
});
