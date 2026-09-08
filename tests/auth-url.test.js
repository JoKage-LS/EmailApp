const test = require('node:test');
const assert = require('node:assert');
const { buildAuthUrl, redirectUriFor } = require('../api/auth/login');

test('buildAuthUrl requests only the send scope', () => {
  const url = new URL(buildAuthUrl({
    clientId: 'cid', redirectUri: 'https://x.nz/api/auth/callback',
    state: 'st', hd: 'lifeswitch.org.nz',
  }));
  const scope = url.searchParams.get('scope');
  assert.match(scope, /gmail\.send/);
  assert.doesNotMatch(scope, /mail\.google\.com/);
});

test('buildAuthUrl requests no refresh token', () => {
  const url = new URL(buildAuthUrl({
    clientId: 'cid', redirectUri: 'https://x.nz/api/auth/callback',
    state: 'st', hd: 'lifeswitch.org.nz',
  }));
  assert.strictEqual(url.searchParams.get('access_type'), 'online');
  assert.strictEqual(url.searchParams.get('response_type'), 'code');
});

test('buildAuthUrl passes client, redirect, state and hd', () => {
  const url = new URL(buildAuthUrl({
    clientId: 'cid', redirectUri: 'https://x.nz/api/auth/callback',
    state: 'st', hd: 'lifeswitch.org.nz',
  }));
  assert.strictEqual(url.origin + url.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.strictEqual(url.searchParams.get('client_id'), 'cid');
  assert.strictEqual(url.searchParams.get('redirect_uri'), 'https://x.nz/api/auth/callback');
  assert.strictEqual(url.searchParams.get('state'), 'st');
  assert.strictEqual(url.searchParams.get('hd'), 'lifeswitch.org.nz');
});

test('redirectUriFor prefers forwarded headers', () => {
  assert.strictEqual(
    redirectUriFor({ headers: { 'x-forwarded-proto': 'https', 'x-forwarded-host': 'app.nz' } }),
    'https://app.nz/api/auth/callback',
  );
  assert.strictEqual(
    redirectUriFor({ headers: { host: 'localhost:3000', 'x-forwarded-proto': 'http' } }),
    'http://localhost:3000/api/auth/callback',
  );
});
