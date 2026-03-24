import nodemailer from 'nodemailer';

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const GMAIL_USER = process.env.GMAIL_USER;
  const GMAIL_APP_PASSWORD = process.env.GMAIL_APP_PASSWORD;

  if (!GMAIL_USER || !GMAIL_APP_PASSWORD) {
    return res.status(500).json({ error: 'GMAIL_USER or GMAIL_APP_PASSWORD not configured in Vercel environment variables.' });
  }

  const { recipients, subject, bodyTemplate, senderName, attachments } = req.body;

  if (!recipients || !Array.isArray(recipients) || recipients.length === 0) {
    return res.status(400).json({ error: 'recipients array required' });
  }
  if (!subject || !bodyTemplate) {
    return res.status(400).json({ error: 'subject and bodyTemplate required' });
  }

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: GMAIL_USER,
      pass: GMAIL_APP_PASSWORD,
    },
  });

  const results = [];

  for (const recipient of recipients) {
    if (!recipient.email || !recipient.firstName) {
      results.push({ ...recipient, sendStatus: 'skipped', sendMessage: 'Missing email or name' });
      continue;
    }

    const personalBody = bodyTemplate
      .replace(/\{\{first_name\}\}/g, recipient.firstName)
      .replace(/\{\{last_name\}\}/g, recipient.lastName || '')
      .replace(/\{\{full_name\}\}/g, `${recipient.firstName} ${recipient.lastName || ''}`.trim());

    const htmlBody = `
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; color: #1a1a1a; margin: 0; padding: 0; background: #f5f5f5; }
  .wrapper { max-width: 600px; margin: 0 auto; background: #ffffff; }
  .header { background: #1a1a1a; padding: 24px 32px; }
  .header-title { color: #ffffff; font-size: 18px; font-weight: 700; margin: 0; }
  .header-sub { color: rgba(255,255,255,0.5); font-size: 12px; margin: 4px 0 0; }
  .body { padding: 32px; }
  .body p { line-height: 1.7; margin: 0 0 16px; font-size: 15px; color: #1a1a1a; }
  .body ul { margin: 0 0 16px; padding-left: 20px; }
  .body ul li { line-height: 1.7; font-size: 15px; color: #1a1a1a; margin-bottom: 6px; }
  .body strong { font-weight: 600; }
  .section-heading { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #888; margin: 24px 0 8px; border-top: 1px solid #f0f0f0; padding-top: 20px; }
  .footer { background: #f9f9f9; border-top: 1px solid #eee; padding: 20px 32px; font-size: 12px; color: #999; }
</style>
</head>
<body>
<div class="wrapper">
  <div class="header">
    <p class="header-title">LifeSwitch Church</p>
    <p class="header-sub">Volunteer Communication</p>
  </div>
  <div class="body">
    ${formatEmailBody(personalBody)}
  </div>
  <div class="footer">
    This email was sent to ${recipient.email}. Sent by ${senderName || 'LifeSwitch'}.
  </div>
</div>
</body>
</html>`;

    const mailOptions = {
      from: `${senderName || 'LifeSwitch'} <${GMAIL_USER}>`,
      to: recipient.email,
      subject: subject,
      html: htmlBody,
    };

    if (attachments && attachments.length > 0) {
      mailOptions.attachments = attachments.map(a => ({
        filename: a.name,
        content: Buffer.from(a.data, 'base64'),
        contentType: a.type,
      }));
    }

    try {
      await transporter.sendMail(mailOptions);
      results.push({ ...recipient, sendStatus: 'sent', sendMessage: 'Delivered' });
    } catch (err) {
      results.push({ ...recipient, sendStatus: 'failed', sendMessage: err.message });
    }

    await new Promise(r => setTimeout(r, 150));
  }

  const sent = results.filter(r => r.sendStatus === 'sent').length;
  const failed = results.filter(r => r.sendStatus === 'failed').length;

  return res.status(200).json({ results, summary: { sent, failed, total: results.length } });
}

function formatEmailBody(text) {
  const lines = text.split('\n');
  let html = '';
  let inList = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) {
      if (inList) { html += '</ul>'; inList = false; }
      continue;
    }
    if (line === line.toUpperCase() && line.length > 3 && /[A-Z]/.test(line) && !line.startsWith('-') && !line.startsWith('•')) {
      if (inList) { html += '</ul>'; inList = false; }
      html += `<p class="section-heading">${escHtml(line)}</p>`;
      continue;
    }
    if (line.startsWith('- ') || line.startsWith('• ')) {
      if (!inList) { html += '<ul>'; inList = true; }
      html += `<li>${formatInline(line.replace(/^[-•]\s+/, ''))}</li>`;
      continue;
    }
    if (inList) { html += '</ul>'; inList = false; }
    html += `<p>${formatInline(line)}</p>`;
  }

  if (inList) html += '</ul>';
  return html;
}

function formatInline(text) {
  return escHtml(text)
    .replace(/\*\*\*(.*?)\*\*\*/g, '<strong><em>$1</em></strong>')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>');
}

function escHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
