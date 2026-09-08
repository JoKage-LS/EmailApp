const test = require('node:test');
const assert = require('node:assert');
const {
  signSession, verifySession, parseCookies, serializeCookie, clearCookie,
  getSession, requireSession, COOKIE_NAME,
} = require('../lib/session');

const SECRET = 'test-secret-value-do-not-use-in-production';

test('signSession/verifySession round-trips a payload', () => {
  const exp = Date.now() + 60000;
  const token = signSession({ email: 'a@b.nz', name: 'A B', exp }, SECRET);
  const out = verifySession(token, SECRET);
  assert.strictEqual(out.email, 'a@b.nz');
  assert.strictEqual(out.name, 'A B');
  assert.strictEqual(out.exp, exp);
});

test('verifySession rejects a tampered payload', () => {
  const token = signSession({ email: 'a@b.nz', exp: Date.now() + 60000 }, SECRET);
  const forged = signSession({ email: 'evil@x.com', exp: Date.now() + 60000 }, SECRET);
  const spliced = `${forged.split('.')[0]}.${token.split('.')[1]}`;
  assert.strictEqual(verifySession(spliced, SECRET), null);
});

test('verifySession rejects a wrong secret', () => {
  const token = signSession({ email: 'a@b.nz', exp: Date.now() + 60000 }, SECRET);
  assert.strictEqual(verifySession(token, 'other-secret'), null);
});

test('verifySession rejects an expired session', () => {
  const token = signSession({ email: 'a@b.nz', exp: Date.now() - 1 }, SECRET);
  assert.strictEqual(verifySession(token, SECRET), null);
});

test('verifySession rejects malformed input', () => {
  assert.strictEqual(verifySession('', SECRET), null);
  assert.strictEqual(verifySession('no-dot', SECRET), null);
  assert.strictEqual(verifySession('a.b.c', SECRET), null);
  assert.strictEqual(verifySession(undefined, SECRET), null);
});

test('verifySession rejects a payload with no exp', () => {
  const token = signSession({ email: 'a@b.nz' }, SECRET);
  assert.strictEqual(verifySession(token, SECRET), null);
});

test('parseCookies handles multiple cookies and empty input', () => {
  assert.deepStrictEqual(parseCookies('a=1; b=2'), { a: '1', b: '2' });
  assert.deepStrictEqual(parseCookies(undefined), {});
  assert.deepStrictEqual(parseCookies(''), {});
});

test('serializeCookie sets the security flags', () => {
  const c = serializeCookie('n', 'v', { maxAge: 30 });
  assert.match(c, /^n=v;/);
  assert.match(c, /HttpOnly/);
  assert.match(c, /Secure/);
  assert.match(c, /SameSite=Lax/);
  assert.match(c, /Max-Age=30/);
});

test('clearCookie expires the cookie immediately', () => {
  assert.match(clearCookie('n'), /Max-Age=0/);
});

test('parseCookies does not throw on malformed percent-encoding, and keeps well-formed neighbours', () => {
  assert.doesNotThrow(() => parseCookies('ls_session=%zz'));
  assert.deepStrictEqual(parseCookies('ls_session=%zz'), {});

  let result;
  assert.doesNotThrow(() => {
    result = parseCookies('a=1; ls_session=%zz; b=2');
  });
  assert.deepStrictEqual(result, { a: '1', b: '2' });

  // Value ending in a bare '%' is also malformed percent-encoding.
  assert.doesNotThrow(() => parseCookies('x=abc%'));
  assert.deepStrictEqual(parseCookies('x=abc%'), {});

  // Splitting still happens on the FIRST '=' only, and whitespace is trimmed,
  // for values that decode cleanly.
  assert.deepStrictEqual(parseCookies(' a = b=c '), { a: 'b=c' });
});

test('getSession/requireSession do not throw on a malformed Cookie header and report unauthenticated', () => {
  const prevSecret = process.env.SESSION_SECRET;
  process.env.SESSION_SECRET = 'test-secret-value-do-not-use-in-production';
  try {
    const req = { headers: { cookie: `${COOKIE_NAME}=%zz` } };

    let session;
    assert.doesNotThrow(() => {
      session = getSession(req);
    });
    assert.strictEqual(session, null);

    let statusCode;
    let body;
    const res = {
      status(code) { statusCode = code; return this; },
      json(payload) { body = payload; return this; },
    };
    let result;
    assert.doesNotThrow(() => {
      result = requireSession(req, res);
    });
    assert.strictEqual(result, null);
    assert.strictEqual(statusCode, 401);
    assert.deepStrictEqual(body, { error: 'Not signed in' });
  } finally {
    if (prevSecret === undefined) delete process.env.SESSION_SECRET;
    else process.env.SESSION_SECRET = prevSecret;
  }
});
