# Per-User Google OAuth Sign-In and Sending — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the single hardcoded Gmail sender with per-user Google sign-in restricted to the `lifeswitch.org.nz` Workspace domain, so each staff member sends from their own account, and close the four currently unauthenticated API endpoints.

**Architecture:** OAuth 2.0 Authorization Code flow, entirely server-side. `/api/auth/login` redirects to Google; `/api/auth/callback` exchanges the code, verifies the `hd` domain claim, and sets an HMAC-signed `HttpOnly` cookie holding the access token. Every `api/` handler validates that cookie before doing work. Sending goes through the Gmail API with the send-only scope, reusing nodemailer's `MailComposer` purely to build MIME.

**Tech Stack:** Vercel serverless functions (CommonJS), Node 18+ global `fetch`, Node built-in `crypto`, Node built-in test runner (`node --test`), nodemailer (already present, now only for `MailComposer`).

## Global Constraints

- **No new npm dependencies.** `package.json` dependencies must still list only `nodemailer` when this plan is complete.
- **CommonJS only.** `package.json` sets `"type": "commonjs"`. Use `require`/`module.exports`, never `import`.
- **Scope is exactly `https://www.googleapis.com/auth/gmail.send`.** Never request `https://mail.google.com/`.
- **`access_type=online`.** No refresh token is requested, stored, or persisted anywhere.
- **Domain allowlist is server-side.** The `hd` URL parameter is a hint only; the `hd` claim on the ID token is the control.
- **Remove `Access-Control-Allow-Origin: *`** from every handler in `api/`.
- **Preserve all existing email construction** in `api/send.js`: `formatEmailBody`, `formatInline`, `escHtml`, the `{{first_name}}`/`{{last_name}}`/`{{full_name}}` substitution, the `safeHeaderColor` regex validation, attachment handling, the 150 ms inter-send delay, and the per-recipient `results` array shape.
- **Existing design tokens only** for new UI: `Syne` headings, `DM Sans` body, `#f7f5f0` ground, `.btn-dark`, `var(--radius)`, `var(--border)`.
- **Branch:** `feat/google-oauth-per-user-sending`. Never commit to `main`.

---

### Task 1: Session library and test harness

**Files:**
- Create: `lib/session.js`
- Create: `tests/session.test.js`
- Modify: `package.json` (add `scripts.test`)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `COOKIE_NAME: string` — `'ls_session'`
  - `STATE_COOKIE: string` — `'ls_oauth_state'`
  - `b64urlEncode(input: Buffer|string): string`
  - `b64urlDecode(input: string): Buffer`
  - `signSession(payload: object, secret: string): string`
  - `verifySession(token: string, secret: string, now?: number): object|null`
  - `parseCookies(header: string|undefined): Record<string,string>`
  - `serializeCookie(name: string, value: string, opts?: {maxAge?: number, path?: string, sameSite?: string}): string`
  - `clearCookie(name: string): string`
  - `getSession(req): object|null`
  - `requireSession(req, res): object|null` — sends 401 and returns `null` when absent

- [ ] **Step 1: Add the test script**

In `package.json`, add a `scripts` block between `"type"` and `"dependencies"`:

```json
  "scripts": {
    "test": "node --test tests/"
  },
```

- [ ] **Step 2: Write the failing test**

Create `tests/session.test.js`:

```js
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
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module '../lib/session'`

- [ ] **Step 4: Write the implementation**

Create `lib/session.js`:

```js
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
    out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
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
```

Note on `Secure`: Chrome and Firefox both accept `Secure` cookies over `http://localhost`, so this works under `vercel dev` without a special case.

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm test`
Expected: PASS — 9 tests, 0 failures

- [ ] **Step 6: Commit**

```bash
git add package.json lib/session.js tests/session.test.js
git commit -m "feat: add signed session cookie library"
```

---

### Task 2: OAuth login endpoint

**Files:**
- Create: `api/auth/login.js`
- Create: `tests/auth-url.test.js`

**Interfaces:**
- Consumes: `signSession`, `serializeCookie`, `STATE_COOKIE` from `lib/session`.
- Produces:
  - `buildAuthUrl({ clientId, redirectUri, state, hd }): string` — exported from `api/auth/login.js` for testing
  - `redirectUriFor(req): string` — exported; derives `<proto>://<host>/api/auth/callback`
  - Route `GET /api/auth/login` → 302 to Google

- [ ] **Step 1: Write the failing test**

Create `tests/auth-url.test.js`:

```js
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module '../api/auth/login'`

- [ ] **Step 3: Write the implementation**

Create `api/auth/login.js`:

```js
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
  return `${proto}://${host}/api/auth/callback`;
}

module.exports = async function handler(req, res) {
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const secret   = process.env.SESSION_SECRET;
  const hd       = process.env.ALLOWED_HD;

  if (!clientId) return res.status(500).json({ error: 'GOOGLE_CLIENT_ID not configured in Vercel environment variables.' });
  if (!secret)   return res.status(500).json({ error: 'SESSION_SECRET not configured in Vercel environment variables.' });
  if (!hd)       return res.status(500).json({ error: 'ALLOWED_HD not configured in Vercel environment variables.' });

  const state = crypto.randomBytes(16).toString('hex');
  const stateCookie = signSession({ state, exp: Date.now() + 10 * 60 * 1000 }, secret);

  res.setHeader('Set-Cookie', serializeCookie(STATE_COOKIE, stateCookie, { maxAge: 600 }));
  res.writeHead(302, { Location: buildAuthUrl({ clientId, redirectUri: redirectUriFor(req), state, hd }) });
  return res.end();
};

module.exports.buildAuthUrl   = buildAuthUrl;
module.exports.redirectUriFor = redirectUriFor;
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test`
Expected: PASS — 13 tests total, 0 failures

- [ ] **Step 5: Commit**

```bash
git add api/auth/login.js tests/auth-url.test.js
git commit -m "feat: add Google OAuth login redirect endpoint"
```

---

### Task 3: OAuth callback endpoint

**Files:**
- Create: `api/auth/callback.js`
- Create: `tests/id-token.test.js`

**Interfaces:**
- Consumes: `verifySession`, `signSession`, `parseCookies`, `serializeCookie`, `clearCookie`, `COOKIE_NAME`, `STATE_COOKIE`, `b64urlDecode` from `lib/session`; `redirectUriFor` from `api/auth/login`.
- Produces:
  - `decodeIdToken(idToken: string): object` — exported for testing; throws on malformed input
  - `assertAllowedDomain(claims: object, allowedHd: string): void` — exported; throws `Error` with `.status = 403` when rejected
  - Route `GET /api/auth/callback` → sets session cookie, 302 to `/`

- [ ] **Step 1: Write the failing test**

Create `tests/id-token.test.js`:

```js
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
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `Cannot find module '../api/auth/callback'`

- [ ] **Step 3: Write the implementation**

Create `api/auth/callback.js`:

```js
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

  let tokens;
  try {
    const body = new URLSearchParams({
      code,
      client_id:     clientId,
      client_secret: clientSecret,
      redirect_uri:  redirectUriFor(req),
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm test`
Expected: PASS — 19 tests total, 0 failures

- [ ] **Step 5: Commit**

```bash
git add api/auth/callback.js tests/id-token.test.js
git commit -m "feat: add Google OAuth callback with domain enforcement"
```

---

### Task 4: Session and logout endpoints

**Files:**
- Create: `api/auth/session.js`
- Create: `api/auth/logout.js`

**Interfaces:**
- Consumes: `getSession`, `clearCookie`, `COOKIE_NAME` from `lib/session`.
- Produces:
  - `GET /api/auth/session` → `200 {email, name}` or `401 {error}`
  - `POST /api/auth/logout` → `200 {ok: true}`, clears the cookie

- [ ] **Step 1: Write `api/auth/session.js`**

```js
const { getSession } = require('../../lib/session');

module.exports = async function handler(req, res) {
  const session = getSession(req);
  if (!session) return res.status(401).json({ error: 'Not signed in' });
  return res.status(200).json({ email: session.email, name: session.name });
};
```

The access token is deliberately not returned — the browser never needs it.

- [ ] **Step 2: Write `api/auth/logout.js`**

```js
const { clearCookie, COOKIE_NAME } = require('../../lib/session');

module.exports = async function handler(req, res) {
  res.setHeader('Set-Cookie', clearCookie(COOKIE_NAME));
  return res.status(200).json({ ok: true });
};
```

- [ ] **Step 3: Verify the whole suite still passes**

Run: `npm test`
Expected: PASS — 19 tests, 0 failures

- [ ] **Step 4: Commit**

```bash
git add api/auth/session.js api/auth/logout.js
git commit -m "feat: add session and logout endpoints"
```

---

### Task 5: Protect the Planning Center endpoints

**Files:**
- Modify: `api/lookup.js:1-6`
- Modify: `api/search.js:1-6`
- Modify: `api/lookup-phones.js:1-6`

**Interfaces:**
- Consumes: `requireSession` from `lib/session`.
- Produces: all three routes return 401 without a valid session.

Each of these three files currently opens with an identical block. In **each** file, replace this:

```js
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
```

with this:

```js
const { requireSession } = require('../lib/session');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  if (!requireSession(req, res)) return;
```

The `require` line goes at the very top of the file, above `module.exports`. The CORS headers and the `OPTIONS` branch are removed entirely — the frontend is same-origin, so the preflight they served is no longer needed.

- [ ] **Step 1: Apply the change to `api/lookup.js`**
- [ ] **Step 2: Apply the change to `api/search.js`**
- [ ] **Step 3: Apply the change to `api/lookup-phones.js`**

- [ ] **Step 4: Verify no CORS wildcard or OPTIONS branch remains**

Run: `grep -rn "Access-Control-Allow-Origin\|OPTIONS" api/`
Expected: only `api/send.js` still matches (fixed in Task 6)

- [ ] **Step 5: Commit**

```bash
git add api/lookup.js api/search.js api/lookup-phones.js
git commit -m "feat: require a session on Planning Center endpoints"
```

---

### Task 6: Send as the signed-in user via the Gmail API

**Files:**
- Modify: `api/send.js:1-40` (imports, guards, transporter removal)
- Modify: `api/send.js` send loop (`transporter.sendMail` call site)
- Create: `tests/mime.test.js`

**Interfaces:**
- Consumes: `requireSession`, `b64urlEncode` from `lib/session`.
- Produces:
  - `buildRawMessage(mailOptions: object): Promise<string>` — exported; base64url MIME
  - `sendViaGmail(accessToken: string, raw: string): Promise<object>` — throws `Error` with `.status`

- [ ] **Step 1: Write the failing test**

Create `tests/mime.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { b64urlDecode } = require('../lib/session');
const { buildRawMessage } = require('../api/send');

test('buildRawMessage produces base64url MIME with headers and body', async () => {
  const raw = await buildRawMessage({
    to: 'volunteer@example.com',
    subject: 'Test subject',
    html: '<p>Hello Ana</p>',
  });
  assert.doesNotMatch(raw, /[+/=]/);
  const mime = b64urlDecode(raw).toString('utf8');
  assert.match(mime, /To: volunteer@example\.com/);
  assert.match(mime, /Subject: Test subject/);
  assert.match(mime, /Hello Ana/);
});

test('buildRawMessage includes attachments', async () => {
  const raw = await buildRawMessage({
    to: 'volunteer@example.com',
    subject: 'With file',
    html: '<p>See attached</p>',
    attachments: [{ filename: 'note.txt', content: Buffer.from('hi'), contentType: 'text/plain' }],
  });
  const mime = b64urlDecode(raw).toString('utf8');
  assert.match(mime, /note\.txt/);
});

test('buildRawMessage sets no From header, so Gmail fills it', async () => {
  const raw = await buildRawMessage({ to: 'a@b.nz', subject: 's', html: '<p>x</p>' });
  const mime = b64urlDecode(raw).toString('utf8');
  assert.doesNotMatch(mime, /^From:/m);
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm test`
Expected: FAIL — `buildRawMessage is not a function`

- [ ] **Step 3: Replace the top of `api/send.js`**

Replace lines 1 through 40 — everything from `const nodemailer = require('nodemailer');` down to and including the `const transporter = nodemailer.createTransport({...});` block — with:

```js
const MailComposer = require('nodemailer/lib/mail-composer');
const { requireSession, b64urlEncode } = require('../lib/session');

const GMAIL_SEND_ENDPOINT = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send';

function buildRawMessage(mailOptions) {
  return new Promise((resolve, reject) => {
    new MailComposer(mailOptions).compile().build((err, message) => {
      if (err) return reject(err);
      resolve(b64urlEncode(message));
    });
  });
}

async function sendViaGmail(accessToken, raw) {
  const resp = await fetch(GMAIL_SEND_ENDPOINT, {
    method: 'POST',
    headers: {
      Authorization:  `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ raw }),
  });
  if (!resp.ok) {
    const detail = await resp.text();
    const err = new Error(`Gmail API ${resp.status}: ${detail.slice(0, 200)}`);
    err.status = resp.status;
    throw err;
  }
  return resp.json();
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const session = requireSession(req, res);
  if (!session) return;

  const { recipients, subject, bodyTemplate, senderName, attachments, emailHeader, emailSubHeader, headerColor } = req.body;

  if (!recipients || !Array.isArray(recipients) || recipients.length === 0) {
    return res.status(400).json({ error: 'recipients array required' });
  }
  if (!subject || !bodyTemplate) {
    return res.status(400).json({ error: 'subject and bodyTemplate required' });
  }

  // Validate headerColor is a safe hex value (prevent injection)
  const safeHeaderColor = /^#[0-9a-fA-F]{3,8}$/.test(headerColor || '') ? headerColor : '#1a1a1a';

  const results = [];
```

Everything below — the `for (const recipient of recipients)` loop, the `htmlBody` template, and the `formatEmailBody` / `formatInline` / `escHtml` helpers at the bottom of the file — stays exactly as it is, apart from the two edits in the next two steps.

- [ ] **Step 4: Update the `mailOptions` object inside the loop**

Find the `const mailOptions = {` block. Remove the `from:` line so Gmail supplies the authenticated user's address, and keep the rest:

```js
    const mailOptions = {
      to:   recipient.email,
      subject,
      html: htmlBody,
    };
```

Immediately below the existing `if (attachments && attachments.length > 0) { ... }` block, the footer of `htmlBody` still reads `Sent by ${senderName || 'LifeSwitch'}`, which is unchanged and still uses `senderName` — do not delete that variable.

- [ ] **Step 5: Replace the send call inside the loop**

Replace:

```js
    try {
      await transporter.sendMail(mailOptions);
      results.push({ ...recipient, sendStatus: 'sent', sendMessage: 'Delivered' });
    } catch (err) {
      results.push({ ...recipient, sendStatus: 'failed', sendMessage: err.message });
    }
```

with:

```js
    try {
      const raw = await buildRawMessage(mailOptions);
      await sendViaGmail(session.accessToken, raw);
      results.push({ ...recipient, sendStatus: 'sent', sendMessage: 'Delivered' });
    } catch (err) {
      if (err.status === 401) {
        results.push({ ...recipient, sendStatus: 'failed', sendMessage: 'Session expired' });
        const sent   = results.filter(r => r.sendStatus === 'sent').length;
        const failed = results.filter(r => r.sendStatus === 'failed').length;
        return res.status(401).json({
          error: 'Session expired', sessionExpired: true,
          results, summary: { sent, failed, total: results.length },
        });
      }
      results.push({ ...recipient, sendStatus: 'failed', sendMessage: err.message });
    }
```

A 401 stops the loop so the remaining recipients are not silently marked failed; partial results are still returned so the caller can see who was already sent.

- [ ] **Step 6: Export the helpers for testing**

At the very bottom of `api/send.js`, after the `escHtml` function, add:

```js
module.exports.buildRawMessage = buildRawMessage;
module.exports.sendViaGmail    = sendViaGmail;
```

- [ ] **Step 7: Run the test to verify it passes**

Run: `npm test`
Expected: PASS — 22 tests total, 0 failures

- [ ] **Step 8: Confirm no SMTP or App Password references remain**

Run: `grep -rn "createTransport\|GMAIL_USER\|GMAIL_APP_PASSWORD\|Access-Control-Allow-Origin" api/`
Expected: no output

- [ ] **Step 9: Commit**

```bash
git add api/send.js tests/mime.test.js
git commit -m "feat: send via Gmail API as the signed-in user"
```

---

### Task 7: Sign-in gate on the main page

**Files:**
- Modify: `public/index.html:173` (insert before `</head>`)
- Modify: `public/index.html:181-184` (header nav)
- Modify: `public/index.html:174` (insert overlay after `<body>`)
- Modify: `public/index.html:354` (insert gate script after `<script>`)

**Interfaces:**
- Consumes: `GET /api/auth/session`, `POST /api/auth/logout`, `GET /api/auth/login`.
- Produces: `window.__session` — `{email, name}` once signed in.

- [ ] **Step 1: Add the anti-flash style before `</head>` (line 173)**

Insert immediately before the closing `</head>` tag:

```html
<style>
  html.auth-pending body > *:not(#auth-overlay) { display: none !important; }
  #auth-overlay { position: fixed; inset: 0; z-index: 9999; background: var(--bg); display: flex; align-items: center; justify-content: center; padding: 24px; }
  #auth-overlay.hidden { display: none; }
  .auth-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 36px 32px; max-width: 380px; width: 100%; text-align: center; }
  .auth-card h2 { font-family: 'Syne', sans-serif; font-weight: 800; font-size: 20px; margin-bottom: 8px; }
  .auth-card p { font-size: 14px; color: var(--text-2); line-height: 1.6; margin-bottom: 24px; }
  .auth-card .btn { width: 100%; justify-content: center; text-decoration: none; }
  .auth-error { background: #fdecea; border: 1px solid #f5c6c2; color: #8b1a10; border-radius: var(--radius-sm); padding: 10px 12px; font-size: 13px; margin-bottom: 16px; text-align: left; }
  .user-chip { display: flex; align-items: center; gap: 10px; margin-left: auto; }
  .user-chip span { font-size: 12px; color: rgba(255,255,255,0.6); }
  .user-chip a { cursor: pointer; }
</style>
<script>document.documentElement.className += ' auth-pending';</script>
```

The inline `<script>` runs before `<body>` parses, so the app never flashes on screen before the session check resolves.

- [ ] **Step 2: Add the overlay markup immediately after `<body>` (line 174)**

```html
<div id="auth-overlay">
  <div class="auth-card">
    <h2>Volunteer Emails</h2>
    <p>Sign in with your LifeSwitch Google account to send emails from your own address.</p>
    <div class="auth-error" id="auth-error" style="display:none"></div>
    <a class="btn btn-dark" href="/api/auth/login">Sign in with Google</a>
  </div>
</div>
```

- [ ] **Step 3: Add the user chip to the header nav (lines 181-184)**

Replace the existing `<nav class="header-nav">` block with:

```html
  <nav class="header-nav">
    <a href="/" class="active">Emails</a>
    <a href="/phone-lookup">Phones</a>
  </nav>
  <div class="user-chip" id="user-chip" style="display:none">
    <span id="user-email"></span>
    <a id="sign-out">Sign out</a>
  </div>
```

- [ ] **Step 4: Add the gate script immediately after the opening `<script>` (line 354)**

```js
window.__session = null;

async function initAuth() {
  const overlay = document.getElementById('auth-overlay');
  const params  = new URLSearchParams(location.search);
  if (params.get('expired') === '1') {
    const box = document.getElementById('auth-error');
    box.textContent = 'Your session expired. Please sign in again.';
    box.style.display = 'block';
  }
  try {
    const res = await fetch('/api/auth/session');
    if (!res.ok) throw new Error('not signed in');
    window.__session = await res.json();
  } catch {
    document.documentElement.classList.remove('auth-pending');
    return false;
  }
  overlay.classList.add('hidden');
  document.documentElement.classList.remove('auth-pending');

  const chip = document.getElementById('user-chip');
  document.getElementById('user-email').textContent = window.__session.email;
  chip.style.display = 'flex';
  document.getElementById('sign-out').addEventListener('click', async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    location.reload();
  });

  const senderInput = document.getElementById('sender-name');
  if (senderInput && !senderInput.value.trim()) senderInput.value = window.__session.name;
  return true;
}

function handleAuthFailure() {
  location.href = '/?expired=1';
}

initAuth();
```

`handleAuthFailure` is called by Step 5.

- [ ] **Step 5: Handle mid-session expiry at the three fetch call sites**

At `public/index.html:461`, `:576` and `:649`, each `const res = await fetch(...)` is followed by response handling. Immediately after each of those three `fetch` lines, insert:

```js
    if (res.status === 401) return handleAuthFailure();
```

Match the surrounding indentation at each site.

- [ ] **Step 6: Commit**

```bash
git add public/index.html
git commit -m "feat: add Google sign-in gate to the email page"
```

---

### Task 8: Sign-in gate on the phone lookup page, and cleanup

**Files:**
- Modify: `public/phone-lookup.html:86` (insert before `</head>`)
- Modify: `public/phone-lookup.html:87` (insert overlay after `<body>`)
- Modify: `public/phone-lookup.html:99-102` (header nav)
- Modify: `public/phone-lookup.html:197` (insert gate script)
- Modify: `public/phone-lookup.html:307` (401 handling)
- Delete: `a`
- Create: `README.md`

- [ ] **Step 1: Add the anti-flash style before `</head>` (line 86)**

Insert immediately before the closing `</head>` tag:

```html
<style>
  html.auth-pending body > *:not(#auth-overlay) { display: none !important; }
  #auth-overlay { position: fixed; inset: 0; z-index: 9999; background: var(--bg); display: flex; align-items: center; justify-content: center; padding: 24px; }
  #auth-overlay.hidden { display: none; }
  .auth-card { background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius); padding: 36px 32px; max-width: 380px; width: 100%; text-align: center; }
  .auth-card h2 { font-family: 'Syne', sans-serif; font-weight: 800; font-size: 20px; margin-bottom: 8px; }
  .auth-card p { font-size: 14px; color: var(--text-2); line-height: 1.6; margin-bottom: 24px; }
  .auth-card .btn { width: 100%; justify-content: center; text-decoration: none; }
  .auth-error { background: #fdecea; border: 1px solid #f5c6c2; color: #8b1a10; border-radius: var(--radius-sm); padding: 10px 12px; font-size: 13px; margin-bottom: 16px; text-align: left; }
  .user-chip { display: flex; align-items: center; gap: 10px; margin-left: auto; }
  .user-chip span { font-size: 12px; color: rgba(255,255,255,0.6); }
  .user-chip a { cursor: pointer; }
</style>
<script>document.documentElement.className += ' auth-pending';</script>
```

This is byte-identical to the block added to `index.html`. Both pages already
define the same `--bg`, `--surface`, `--border`, `--radius`, `--radius-sm` and
`--text-2` tokens, so it needs no per-page adjustment.

- [ ] **Step 2: Add the overlay after `<body>` (line 87)**

Same markup as Task 7 Step 2, with the heading changed:

```html
<div id="auth-overlay">
  <div class="auth-card">
    <h2>Phone Lookup</h2>
    <p>Sign in with your LifeSwitch Google account to look up contact details.</p>
    <div class="auth-error" id="auth-error" style="display:none"></div>
    <a class="btn btn-dark" href="/api/auth/login">Sign in with Google</a>
  </div>
</div>
```

- [ ] **Step 3: Add the user chip to the header nav (lines 99-102)**

```html
  <nav class="header-nav">
    <a href="/">Emails</a>
    <a href="/phone-lookup" class="active">Phones</a>
  </nav>
  <div class="user-chip" id="user-chip" style="display:none">
    <span id="user-email"></span>
    <a id="sign-out">Sign out</a>
  </div>
```

- [ ] **Step 4: Add the gate script immediately after the opening `<script>` (line 197)**

Identical to Task 7 Step 4, except the `senderInput` lines are omitted (this page has no sender field) and `handleAuthFailure` redirects to this page:

```js
window.__session = null;

async function initAuth() {
  const overlay = document.getElementById('auth-overlay');
  const params  = new URLSearchParams(location.search);
  if (params.get('expired') === '1') {
    const box = document.getElementById('auth-error');
    box.textContent = 'Your session expired. Please sign in again.';
    box.style.display = 'block';
  }
  try {
    const res = await fetch('/api/auth/session');
    if (!res.ok) throw new Error('not signed in');
    window.__session = await res.json();
  } catch {
    document.documentElement.classList.remove('auth-pending');
    return false;
  }
  overlay.classList.add('hidden');
  document.documentElement.classList.remove('auth-pending');

  const chip = document.getElementById('user-chip');
  document.getElementById('user-email').textContent = window.__session.email;
  chip.style.display = 'flex';
  document.getElementById('sign-out').addEventListener('click', async () => {
    await fetch('/api/auth/logout', { method: 'POST' });
    location.reload();
  });
  return true;
}

function handleAuthFailure() {
  location.href = '/phone-lookup?expired=1';
}

initAuth();
```

- [ ] **Step 5: Handle 401 at the lookup call site (line 307)**

After the `const res = await fetch('/api/lookup-phones', {` call completes, insert:

```js
      if (res.status === 401) return handleAuthFailure();
```

- [ ] **Step 6: Delete the stray file**

`a` is a 2-byte file containing only `\r\n`, committed by accident.

```bash
git rm a
```

- [ ] **Step 7: Write `README.md`**

```markdown
# LifeSwitch Volunteer Emails

Sends templated emails to Planning Center contacts. Staff sign in with their
LifeSwitch Google account, and each email sends from that person's own Gmail
account and appears in their own Sent folder.

## Access

Restricted to verified `@lifeswitch.org.nz` Google Workspace accounts. There is
no shared password. Enforcement is server-side, on the `hd` claim of the Google
ID token.

## Environment Variables (Vercel)

| Name | Purpose |
|---|---|
| `GOOGLE_CLIENT_ID` | OAuth client ID from Google Cloud |
| `GOOGLE_CLIENT_SECRET` | OAuth client secret from Google Cloud |
| `SESSION_SECRET` | 32+ random bytes, hex. Generate with `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
| `ALLOWED_HD` | `lifeswitch.org.nz` |
| `PCO_APP_ID` | Planning Center application ID |
| `PCO_SECRET` | Planning Center secret |

`GMAIL_USER` and `GMAIL_APP_PASSWORD` are no longer used. Delete them from
Vercel and revoke the App Password in the Google account that owned it.

## Google Cloud Setup

1. Create a project, e.g. `lifeswitch-email`, and select it in the console's top bar.
2. **APIs & Services → Library → enable Gmail API.** Do this before step 4 — until
   the API is enabled, its scopes do not appear in the scope picker at all.
3. **Google Auth Platform → Audience** → User Type **Internal**. Fill in app name,
   user support email, and developer contact email under **Branding**.
4. **Google Auth Platform → Data Access → Add or remove scopes.** Filter for
   `gmail.send`, or paste it into **Manually add scopes** at the bottom of the panel:
   ```
   https://www.googleapis.com/auth/gmail.send
   ```
   Tick it → **Update** → **Save**.
5. **Credentials → Create credentials → OAuth client ID → Web application.**
6. Authorized redirect URIs — paste these exactly. Google accepts only complete,
   literal URIs: no wildcards, no placeholders, and `http://` only for localhost.

   ```
   http://localhost:3000/api/auth/callback
   https://emailapp-roan.vercel.app/api/auth/callback
   https://emailapp-git-main-jono-chaplows-projects.vercel.app/api/auth/callback
   https://emailapp-jono-chaplows-projects.vercel.app/api/auth/callback
   https://emailapp-git-feat-oauth-jono-chaplows-projects.vercel.app/api/auth/callback
   ```

   `emailapp-roan.vercel.app` is the production domain. The last entry is the
   preview alias for the `feat/oauth` branch.
7. Copy the client ID and secret into Vercel.

### A note on preview URLs

Vercel names branch previews `emailapp-git-<branch>-jono-chaplows-projects.vercel.app`.
That hostname label cannot exceed 63 characters, and Vercel truncates longer ones
and appends an unpredictable hash. Since Google requires each redirect URI to be
registered in advance, an unpredictable preview host cannot be pre-registered.

Keep branch names short. `feat/oauth` yields a 46-character host and works; the
original `feat/google-oauth-per-user-sending` yielded 69 and would not have.
If you do deploy a long-named branch, read its real URL from the Vercel dashboard
and add that exact URI to the Google client before testing sign-in.

### Notes on scopes and verification

The console will show verification warnings for `gmail.send`, because Google
classifies it as a **sensitive** scope. Those warnings apply to **External** apps.
This app is **Internal** — every user is on the Workspace domain — so no
verification, review, or security assessment applies.

`gmail.send` is deliberately chosen over `https://mail.google.com/`. The latter is
a **restricted** scope granting full mailbox access, and it triggers a third-party
security assessment if the app is ever made External. Never widen the scope.

What actually grants permission at runtime is the `scope` parameter in the auth
URL, built in `api/auth/login.js`. The Data Access page governs what the consent
screen displays and what verification checks. Keep the two in agreement.

## Sessions

Sessions last one Google access-token lifetime (about an hour) and are held in
an `HttpOnly`, `Secure`, `SameSite=Lax`, HMAC-signed cookie. No refresh token is
requested and no tokens are stored server-side, so there is no database and no
long-lived access to anyone's mailbox. Staff re-click sign-in about hourly.

## Development

```bash
npm install
npm test        # node --test, no external test framework
vercel dev      # http://localhost:3000
```

`vercel dev` needs a `.env.local` with the variables above.

## Sending Limits

Google Workspace caps around 2,000 recipients per day per account. Because each
staff member now sends from their own account, that ceiling applies per person
rather than to one shared mailbox.
```

- [ ] **Step 8: Run the full suite**

Run: `npm test`
Expected: PASS — 22 tests, 0 failures

- [ ] **Step 9: Commit**

```bash
git add public/phone-lookup.html README.md
git commit -m "feat: gate phone lookup page and document setup"
```

---

## Manual Verification

Automated tests cover the pure logic — signing, domain rules, MIME. The OAuth
round trip and real sending need a browser and a live Google client, so run this
matrix against the Vercel preview deployment before merging.

| # | Test | Expected |
|---|---|---|
| 1 | Open the app signed out | App hidden, sign-in card shown, no flash of app content |
| 2 | Sign in with a `@lifeswitch.org.nz` account | App reveals, email in header |
| 3 | Sign in with a personal Gmail | 403, "limited to LifeSwitch staff accounts", no session |
| 4 | Send a test email to yourself | **Arrives from the signed-in user**, appears in **their** Sent folder |
| 5 | `curl -X POST <preview>/api/send` with no cookie | 401 |
| 6 | `curl -X POST <preview>/api/lookup` with no cookie | 401 |
| 7 | Click Sign out | App hides, endpoints 401 again |
| 8 | Phone lookup page | Same gate; PCO lookup works once signed in |
| 9 | Send with an attachment | Attachment arrives intact |

Test 4 proves the core requirement. Tests 5 and 6 prove the open relay and the
Planning Center data exposure are closed.

## Rollout

1. Push `feat/google-oauth-per-user-sending`, open a PR against `main`.
2. Add the Vercel preview URL to the Google client's authorized redirect URIs.
3. Set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `SESSION_SECRET`, `ALLOWED_HD` in Vercel for Preview and Production.
4. Run the matrix on the preview. `main` is untouched, so the live app keeps working throughout.
5. Merge only after test 4 passes.
6. Re-run tests 2, 4 and 5 against production.
7. Delete `GMAIL_USER` and `GMAIL_APP_PASSWORD` from Vercel, and revoke the App Password in Google.
