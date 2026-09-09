const {
  b64urlDecode, signSession, verifySession, parseCookies,
  serializeCookie, clearCookie, COOKIE_NAME, STATE_COOKIE,
} = require('../../lib/session');
const { redirectUriFor, sanitizeRedirectPath } = require('./login');

const TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token';
const DEFAULT_TOKEN_LIFETIME_SEC = 3600;

function decodeIdToken(idToken) {
  const parts = String(idToken).split('.');
  if (parts.length !== 3) throw new Error('Malformed ID token');
  return JSON.parse(b64urlDecode(parts[1]).toString('utf8'));
}

function assertAllowedDomain(claims, allowedHd) {
  const ok = claims
    && typeof claims.hd === 'string'
    && claims.hd.toLowerCase() === allowedHd.toLowerCase()
    && claims.email_verified === true
    && typeof claims.email === 'string'
    && claims.email.toLowerCase().endsWith(`@${allowedHd.toLowerCase()}`);
  if (!ok) {
    const err = new Error('This app is limited to LifeSwitch staff accounts.');
    err.status = 403;
    throw err;
  }
}

// Redirects to the sign-in card with a short, fixed error code — never with
// attacker- or Google-controlled text. `code` must come from a hardcoded
// call site below, never from a query parameter or response body, so this
// can never become a reflected-XSS vector.
function redirectToAuthError(res, code) {
  res.writeHead(302, { Location: `/?authError=${encodeURIComponent(code)}` });
  return res.end();
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
    return redirectToAuthError(res, 'cancelled');
  }
  if (!code || !state) return redirectToAuthError(res, 'badstate');

  const cookies    = parseCookies(req.headers.cookie);
  const stateClaim = verifySession(cookies[STATE_COOKIE], secret);
  if (!stateClaim || stateClaim.typ !== 'state' || stateClaim.state !== state) {
    return redirectToAuthError(res, 'badstate');
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
      return redirectToAuthError(res, 'exchange');
    }
    tokens = await resp.json();
  } catch {
    return redirectToAuthError(res, 'exchange');
  }

  let claims;
  try {
    claims = decodeIdToken(tokens.id_token);
    assertAllowedDomain(claims, allowedHd);
  } catch (err) {
    return redirectToAuthError(res, err.status === 403 ? 'domain' : 'exchange');
  }

  const rawLifetime = Math.max(60, (tokens.expires_in || DEFAULT_TOKEN_LIFETIME_SEC) - 60);
  const lifetimeSec = Number.isFinite(rawLifetime) ? rawLifetime : DEFAULT_TOKEN_LIFETIME_SEC;
  const session = signSession({
    typ:         'session',
    email:       claims.email,
    name:        claims.name || claims.email,
    accessToken: tokens.access_token,
    exp:         Date.now() + lifetimeSec * 1000,
  }, secret);

  res.setHeader('Set-Cookie', [
    serializeCookie(COOKIE_NAME, session, { maxAge: lifetimeSec }),
    clearCookie(STATE_COOKIE),
  ]);
  // Re-validate even though login.js already sanitized this before signing
  // it into the state cookie — never trust a redirect target on use alone
  // because it was validated somewhere upstream.
  res.writeHead(302, { Location: sanitizeRedirectPath(stateClaim.next) });
  return res.end();
};

module.exports.decodeIdToken      = decodeIdToken;
module.exports.assertAllowedDomain = assertAllowedDomain;
