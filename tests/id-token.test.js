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

test('assertAllowedDomain rejects the suffix trick (email domain ends with but is not equal to allowed domain)', () => {
  // Guards against naive suffix matching: 'a@notlifeswitch.org.nz' ends with '@lifeswitch.org.nz' but is a different domain.
  assert.throws(
    () => assertAllowedDomain({ hd: 'lifeswitch.org.nz', email_verified: true, email: 'a@notlifeswitch.org.nz' }, 'lifeswitch.org.nz'),
    (e) => e.status === 403,
  );
});

test('assertAllowedDomain rejects string-valued email_verified (gotcha: loose truthiness)', () => {
  // Guards against the email_verified: 'true' gotcha. String 'true' is truthy but !== true, so must be rejected.
  assert.throws(
    () => assertAllowedDomain({ hd: 'lifeswitch.org.nz', email_verified: 'true', email: 'a@lifeswitch.org.nz' }, 'lifeswitch.org.nz'),
    (e) => e.status === 403,
  );
});

test('assertAllowedDomain rejects correct hd but mismatched email domain', () => {
  assert.throws(
    () => assertAllowedDomain({ hd: 'lifeswitch.org.nz', email_verified: true, email: 'attacker@evil.com' }, 'lifeswitch.org.nz'),
    (e) => e.status === 403,
  );
});

test('assertAllowedDomain rejects null claims', () => {
  assert.throws(
    () => assertAllowedDomain(null, 'lifeswitch.org.nz'),
    (e) => e.status === 403,
  );
});

test('assertAllowedDomain rejects empty claims object', () => {
  assert.throws(
    () => assertAllowedDomain({}, 'lifeswitch.org.nz'),
    (e) => e.status === 403,
  );
});

test('FINDING 6: assertAllowedDomain accepts a mixed-case ALLOWED_HD env value against a lowercase hd claim', () => {
  assert.doesNotThrow(() => assertAllowedDomain(
    { hd: 'lifeswitch.org.nz', email_verified: true, email: 'a@lifeswitch.org.nz' },
    'LifeSwitch.org.nz',
  ));
});
