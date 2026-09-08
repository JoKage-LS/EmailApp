const { clearCookie, COOKIE_NAME } = require('../../lib/session');

module.exports = async function handler(req, res) {
  res.setHeader('Set-Cookie', clearCookie(COOKIE_NAME));
  return res.status(200).json({ ok: true });
};
