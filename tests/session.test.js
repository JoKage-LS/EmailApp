const test = require('node:test');
const assert = require('node:assert');
const {
  signSession, verifySession, parseCookies, serializeCookie, clearCookie,
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
