const test = require('node:test');
const assert = require('node:assert');
const { b64urlDecode, signSession } = require('../lib/session');
const { buildRawMessage } = require('../api/send');
const sendHandler = require('../api/send');
const { sendViaGmail } = sendHandler;

const GMAIL_SEND_ENDPOINT = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send';
const TEST_SECRET = 'test-secret-value-do-not-use-in-production';

function makeRes() {
  const res = {
    statusCode: undefined,
    body: undefined,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; },
    end() { return this; },
    setHeader() { return this; },
  };
  return res;
}

function sessionCookie() {
  const token = signSession(
    { typ: 'session', email: 't@lifeswitch.org.nz', name: 'T', accessToken: 'ya29.TEST', exp: Date.now() + 600000 },
    process.env.SESSION_SECRET,
  );
  return `ls_session=${encodeURIComponent(token)}`;
}

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

test('sendViaGmail POSTs the raw message to the Gmail send endpoint with a bearer token', async () => {
  const originalFetch = global.fetch;
  let capturedUrl, capturedOptions;
  global.fetch = async (url, options) => {
    capturedUrl = url;
    capturedOptions = options;
    return { ok: true, json: async () => ({ id: 'msg-1' }) };
  };

  try {
    await sendViaGmail('ya29.ABC123', 'RAW_BASE64URL_PAYLOAD');
  } finally {
    global.fetch = originalFetch;
  }

  assert.strictEqual(capturedUrl, GMAIL_SEND_ENDPOINT);
  assert.strictEqual(capturedOptions.method, 'POST');
  assert.strictEqual(capturedOptions.headers.Authorization, 'Bearer ya29.ABC123');
  const parsedBody = JSON.parse(capturedOptions.body);
  assert.ok(Object.prototype.hasOwnProperty.call(parsedBody, 'raw'));
  assert.strictEqual(parsedBody.raw, 'RAW_BASE64URL_PAYLOAD');
});

test('sendViaGmail attaches the HTTP status code to the thrown error on failure', async () => {
  const originalFetch = global.fetch;
  global.fetch = async () => ({ ok: false, status: 403, text: async () => 'quota' });

  try {
    await assert.rejects(
      () => sendViaGmail('ya29.ABC123', 'raw'),
      (err) => {
        assert.strictEqual(err.status, 403);
        return true;
      },
    );
  } finally {
    global.fetch = originalFetch;
  }
});

test('handler rejects an anonymous request with 401 and never calls fetch', async () => {
  const originalFetch = global.fetch;
  let fetchCalled = false;
  global.fetch = async () => {
    fetchCalled = true;
    throw new Error('fetch should not have been called for an anonymous request');
  };

  const res = makeRes();
  const req = {
    method: 'POST',
    headers: {},
    body: {
      recipients: [{ email: 'a@x.nz', firstName: 'Ana' }],
      subject: 'S',
      bodyTemplate: 'Hello {{first_name}}',
    },
  };

  try {
    await sendHandler(req, res);
  } finally {
    global.fetch = originalFetch;
  }

  assert.strictEqual(res.statusCode, 401);
  assert.deepStrictEqual(res.body, { error: 'Not signed in' });
  assert.strictEqual(fetchCalled, false);
});

test('handler records a per-recipient failure and continues to the next recipient', async () => {
  const prevSecret = process.env.SESSION_SECRET;
  process.env.SESSION_SECRET = TEST_SECRET;

  const originalFetch = global.fetch;
  let callCount = 0;
  global.fetch = async () => {
    callCount += 1;
    if (callCount === 1) {
      return { ok: false, status: 500, text: async () => 'boom' };
    }
    return { ok: true, json: async () => ({ id: 'msg-2' }) };
  };

  const res = makeRes();
  const req = {
    method: 'POST',
    headers: { cookie: sessionCookie() },
    body: {
      recipients: [
        { email: 'a@x.nz', firstName: 'Ana' },
        { email: 'b@x.nz', firstName: 'Bo' },
      ],
      subject: 'S',
      bodyTemplate: 'Hello {{first_name}}',
    },
  };

  try {
    await sendHandler(req, res);
  } finally {
    global.fetch = originalFetch;
    if (prevSecret === undefined) delete process.env.SESSION_SECRET;
    else process.env.SESSION_SECRET = prevSecret;
  }

  assert.strictEqual(callCount, 2);
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(res.body.results.length, 2);
  assert.strictEqual(res.body.results[0].sendStatus, 'failed');
  assert.strictEqual(res.body.results[1].sendStatus, 'sent');
  assert.deepStrictEqual(res.body.summary, { sent: 1, failed: 1, total: 2 });
});

test('handler stops the send loop on a 401 from Gmail and reports session expiry', async () => {
  const prevSecret = process.env.SESSION_SECRET;
  process.env.SESSION_SECRET = TEST_SECRET;

  const originalFetch = global.fetch;
  let callCount = 0;
  global.fetch = async () => {
    callCount += 1;
    return { ok: false, status: 401, text: async () => 'expired' };
  };

  const res = makeRes();
  const req = {
    method: 'POST',
    headers: { cookie: sessionCookie() },
    body: {
      recipients: [
        { email: 'a@x.nz', firstName: 'Ana' },
        { email: 'b@x.nz', firstName: 'Bo' },
      ],
      subject: 'S',
      bodyTemplate: 'Hello {{first_name}}',
    },
  };

  try {
    await sendHandler(req, res);
  } finally {
    global.fetch = originalFetch;
    if (prevSecret === undefined) delete process.env.SESSION_SECRET;
    else process.env.SESSION_SECRET = prevSecret;
  }

  assert.strictEqual(callCount, 1);
  assert.strictEqual(res.statusCode, 401);
  assert.strictEqual(res.body.sessionExpired, true);
  assert.strictEqual(res.body.error, 'Session expired');
});
