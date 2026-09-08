const {
  b64urlDecode, signSession, verifySession, parseCookies,
  serializeCookie, clearCookie, COOKIE_NAME, STATE_COOKIE,
} = require('../../lib/session');
const { redirectUriFor } = require('./login');

const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';

function decodeIdToken(idToken) {
  const parts = String(idToken).split('.');
  if (parts.length !== 3) throw new Error('Malformed ID token');
  return JSON.parse(b64urlDecode(parts[1]).toString('utf8'));
}

function assertAllowedDomain(claims, allowedHd) {
  const ok = claims
    && claims.hd === allowedHd
    && claims.email_verified === true
    && typeof claims.email === 'string'
    && claims.email.toLowerCase().endsWith(`@${allowedHd.toLowerCase()}`);
  if (!ok) {
    const err = new Error('This app is limited to LifeSwitch staff accounts.');
    err.status = 403;
    throw err;
  }
}

module.exports = async function handler(req, res) {
  const clientId     = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  const secret       = process.env.SESSION_SECRET;
  const allowedHd    = process.env.ALLOWED_HD;

  if (!clientId || !clientSecret || !secret || !allowedHd) {
    return res.status(500).json({ error: 'Google OAuth environment variables are not fully configured in Vercel.' });
  }

  const url   = new URL(req.url, 'http://localhost');
  const code  = url.searchParams.get('code');
  const state = url.searchParams.get('state');

  if (url.searchParams.get('error')) {
    return res.status(400).send(`Sign-in was cancelled or refused: ${url.searchParams.get('error')}`);
  }
  if (!code || !state) return res.status(400).send('Missing code or state.');

  const cookies    = parseCookies(req.headers.cookie);
  const stateClaim = verifySession(cookies[STATE_COOKIE], secret);
  if (!stateClaim || stateClaim.state !== state) {
    return res.status(400).send('Invalid sign-in state. Please try signing in again.');
  }

  let redirectUri;
  try {
    redirectUri = redirectUriFor(req);
  } catch (err) {
    return res.status(err.status || 500).json({ error: err.message });
  }

  let tokens;
  try {
    const body = new URLSearchParams({
      code,
      client_id:     clientId,
      client_secret: clientSecret,
      redirect_uri:  redirectUri,
      grant_type:    'authorization_code',
    });
    const resp = await fetch(TOKEN_ENDPOINT, {
      method:  'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
    if (!resp.ok) {
      const detail = await resp.text();
      return res.status(502).send(`Google token exchange failed (${resp.status}): ${detail.slice(0, 300)}`);
    }
    tokens = await resp.json();
  } catch (err) {
    return res.status(502).send(`Could not reach Google to complete sign-in: ${err.message}`);
  }

  let claims;
  try {
    claims = decodeIdToken(tokens.id_token);
    assertAllowedDomain(claims, allowedHd);
  } catch (err) {
    return res.status(err.status || 400).send(err.message);
  }

  const lifetimeSec = Math.max(60, (tokens.expires_in || 3600) - 60);
  const session = signSession({
    email:       claims.email,
    name:        claims.name || claims.email,
    accessToken: tokens.access_token,
    exp:         Date.now() + lifetimeSec * 1000,
  }, secret);

  res.setHeader('Set-Cookie', [
    serializeCookie(COOKIE_NAME, session, { maxAge: lifetimeSec }),
    clearCookie(STATE_COOKIE),
  ]);
  res.writeHead(302, { Location: '/' });
  return res.end();
};

module.exports.decodeIdToken      = decodeIdToken;
module.exports.assertAllowedDomain = assertAllowedDomain;
