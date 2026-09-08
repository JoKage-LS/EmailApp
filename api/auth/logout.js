const { clearCookie, COOKIE_NAME } = require('../../lib/session');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });
  res.setHeader('Set-Cookie', clearCookie(COOKIE_NAME));
  return res.status(200).json({ ok: true });
};
