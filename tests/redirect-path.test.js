const test = require('node:test');
const assert = require('node:assert');
const { sanitizeRedirectPath } = require('../api/auth/login');

test('sanitizeRedirectPath rejects a protocol-relative path (//evil.com)', () => {
  assert.strictEqual(sanitizeRedirectPath('//evil.com'), '/');
});

test('sanitizeRedirectPath rejects an absolute URL (https://evil.com)', () => {
  assert.strictEqual(sanitizeRedirectPath('https://evil.com'), '/');
});

test('sanitizeRedirectPath rejects a backslash-relative path (/\\evil.com)', () => {
  assert.strictEqual(sanitizeRedirectPath('/\\evil.com'), '/');
});

test('sanitizeRedirectPath rejects a path with embedded control characters (header/CRLF injection)', () => {
  assert.strictEqual(sanitizeRedirectPath('/\r\nSet-Cookie:%20evil=1'), '/');
});

test('sanitizeRedirectPath rejects non-string and empty input', () => {
  assert.strictEqual(sanitizeRedirectPath(null), '/');
  assert.strictEqual(sanitizeRedirectPath(undefined), '/');
  assert.strictEqual(sanitizeRedirectPath(''), '/');
  assert.strictEqual(sanitizeRedirectPath(42), '/');
});

test('sanitizeRedirectPath rejects a path not starting with a slash', () => {
  assert.strictEqual(sanitizeRedirectPath('evil.com'), '/');
});

test('sanitizeRedirectPath accepts a genuine same-origin relative path (/phone-lookup)', () => {
  assert.strictEqual(sanitizeRedirectPath('/phone-lookup'), '/phone-lookup');
});

test('sanitizeRedirectPath accepts the root path', () => {
  assert.strictEqual(sanitizeRedirectPath('/'), '/');
});
