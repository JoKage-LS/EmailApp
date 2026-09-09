const crypto = require('crypto');
const { signSession, serializeCookie, STATE_COOKIE } = require('../../lib/session');

const AUTH_ENDPOINT = 'https://accounts.google.com/o/oauth2/v2/auth';
const SCOPE = 'openid email profile https://www.googleapis.com/auth/gmail.send';

function buildAuthUrl({ clientId, redirectUri, state, hd }) {
  const params = new URLSearchParams({
    client_id:     clientId,
    redirect_uri:  redirectUri,
    response_type: 'code',
    scope:         SCOPE,
    access_type:   'online',
    prompt:        'select_account',
    state,
    hd,
  });
  return `${AUTH_ENDPOINT}?${params.toString()}`;
}

function redirectUriFor(req) {
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const host  = req.headers['x-forwarded-host'] || req.headers.host;
  if (!host) {
    const err = new Error('No host header provided: unable to construct redirect URI (x-forwarded-host and host both missing)');
    err.status = 500;
    throw err;
  }
  return `${proto}://${host}/api/auth/callback`;
}

// Validates a post-login redirect target as a same-origin relative path.
// Only a path starting with a single '/' (not '//' or '/\', both of which
// browsers can resolve to a different origin) is accepted; anything else —
// including absolute URLs like 'https://evil.com' — falls back to '/'. This
// guards against an open redirect via a crafted `next` value, since that
// value round-trips through an attacker-shareable link and a signed cookie
// before it is ever used as a redirect target.
function sanitizeRedirectPath(path) {
  if (typeof path !== 'string' || path.length === 0) return '/';
  if (path[0] !== '/') return '/';
  if (path.length > 1 && (path[1] === '/' || path[1] === '\\')) return '/';
  if (/[\x00-\x1f]/.test(path)) return '/'; // no CR/LF or other control chars (header injection)
  return path;
}

module.exports = async function handler(req, res) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const secret   = process.env.SESSION_SECRET;
  const hd       = process.env.ALLOWED_HD;

  if (!clientId) return res.status(500).json({ error: 'GOOGLE_CLIENT_ID not configured in Vercel environment variables.' });
  if (!secret)   return res.status(500).json({ error: 'SESSION_SECRET not configured in Vercel environment variables.' });
  if (!hd)       return res.status(500).json({ error: 'ALLOWED_HD not configured in Vercel environment variables.' });

  let redirectUri;
  try {
    redirectUri = redirectUriFor(req);
  } catch (err) {
    return res.status(err.status || 500).json({ error: err.message });
  }

  const url  = new URL(req.url, 'http://localhost');
  const next = sanitizeRedirectPath(url.searchParams.get('next'));

  const state = crypto.randomBytes(16).toString('hex');
  const stateCookie = signSession({ typ: 'state', state, next, exp: Date.now() + 10 * 60 * 1000 }, secret);

  res.setHeader('Set-Cookie', serializeCookie(STATE_COOKIE, stateCookie, { maxAge: 600 }));
  res.writeHead(302, { Location: buildAuthUrl({ clientId, redirectUri, state, hd }) });
  return res.end();
};

module.exports.buildAuthUrl        = buildAuthUrl;
module.exports.redirectUriFor      = redirectUriFor;
module.exports.sanitizeRedirectPath = sanitizeRedirectPath;
