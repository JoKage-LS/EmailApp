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
