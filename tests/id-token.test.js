const test = require('node:test');
const assert = require('node:assert');
const { b64urlEncode } = require('../lib/session');
const { decodeIdToken, assertAllowedDomain } = require('../api/auth/callback');

function fakeIdToken(claims) {
  return `${b64urlEncode('{"alg":"RS256"}')}.${b64urlEncode(JSON.stringify(claims))}.sig`;
}

test('decodeIdToken extracts the claims payload', () => {
  const claims = { email: 'jono@lifeswitch.org.nz', hd: 'lifeswitch.org.nz', email_verified: true };
  assert.deepStrictEqual(decodeIdToken(fakeIdToken(claims)), claims);
});

test('decodeIdToken throws on malformed tokens', () => {
  assert.throws(() => decodeIdToken('not-a-token'));
  assert.throws(() => decodeIdToken(''));
});

test('assertAllowedDomain accepts a verified domain account', () => {
  assert.doesNotThrow(() => assertAllowedDomain(
    { hd: 'lifeswitch.org.nz', email_verified: true, email: 'a@lifeswitch.org.nz' },
    'lifeswitch.org.nz',
  ));
});

test('assertAllowedDomain rejects a personal Gmail account', () => {
  assert.throws(
    () => assertAllowedDomain({ email_verified: true, email: 'someone@gmail.com' }, 'lifeswitch.org.nz'),
    (e) => e.status === 403,
  );
});

test('assertAllowedDomain rejects a different workspace domain', () => {
  assert.throws(
    () => assertAllowedDomain({ hd: 'other.org', email_verified: true, email: 'a@other.org' }, 'lifeswitch.org.nz'),
    (e) => e.status === 403,
  );
});

test('assertAllowedDomain rejects an unverified email', () => {
  assert.throws(
    () => assertAllowedDomain({ hd: 'lifeswitch.org.nz', email_verified: false, email: 'a@lifeswitch.org.nz' }, 'lifeswitch.org.nz'),
    (e) => e.status === 403,
  );
});
