const crypto = require('crypto');

const COOKIE_NAME  = 'ls_session';
const STATE_COOKIE = 'ls_oauth_state';

function b64urlEncode(input) {
  return Buffer.from(input).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function b64urlDecode(str) {
  const s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  const pad = s.length % 4 === 0 ? '' : '='.repeat(4 - (s.length % 4));
  return Buffer.from(s + pad, 'base64');
}

function hmac(payloadB64, secret) {
  return b64urlEncode(crypto.createHmac('sha256', secret).update(payloadB64).digest());
}

function signSession(payload, secret) {
  const p = b64urlEncode(JSON.stringify(payload));
  return `${p}.${hmac(p, secret)}`;
}

function verifySession(token, secret, now = Date.now()) {
  if (typeof token !== 'string' || !token) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;

  const given    = Buffer.from(parts[1]);
  const expected = Buffer.from(hmac(parts[0], secret));
  if (given.length !== expected.length) return null;
  if (!crypto.timingSafeEqual(given, expected)) return null;

  let payload;
  try {
    payload = JSON.parse(b64urlDecode(parts[0]).toString('utf8'));
  } catch {
    return null;
  }
  if (!payload || typeof payload !== 'object') return null;
  if (typeof payload.exp !== 'number' || payload.exp <= now) return null;
  return payload;
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i === -1) continue;
    const name = part.slice(0, i).trim();
    const rawValue = part.slice(i + 1).trim();
    let value;
    try {
      value = decodeURIComponent(rawValue);
    } catch {
      // Malformed percent-encoding (e.g. '%zz' or a trailing bare '%') must
      // not crash cookie parsing (and therefore auth) for the whole request.
      // Drop just this cookie; other well-formed cookies are unaffected.
      continue;
    }
    out[name] = value;
  }
  return out;
}

function serializeCookie(name, value, opts = {}) {
  const bits = [`${name}=${encodeURIComponent(value)}`];
  bits.push(`Path=${opts.path || '/'}`);
  if (opts.maxAge != null) bits.push(`Max-Age=${opts.maxAge}`);
  bits.push('HttpOnly');
  bits.push('Secure');
  bits.push(`SameSite=${opts.sameSite || 'Lax'}`);
  return bits.join('; ');
}

function clearCookie(name) {
  return serializeCookie(name, '', { maxAge: 0 });
}

function getSession(req) {
  const secret = process.env.SESSION_SECRET;
  if (!secret) return null;
  const cookies = parseCookies(req.headers && req.headers.cookie);
  return verifySession(cookies[COOKIE_NAME], secret);
}

function requireSession(req, res) {
  const session = getSession(req);
  if (!session) {
    res.status(401).json({ error: 'Not signed in' });
    return null;
  }
  return session;
}

module.exports = {
  COOKIE_NAME, STATE_COOKIE,
  b64urlEncode, b64urlDecode,
  signSession, verifySession,
  parseCookies, serializeCookie, clearCookie,
  getSession, requireSession,
};
