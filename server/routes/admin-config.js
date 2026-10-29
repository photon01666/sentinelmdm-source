// routes/admin-config.js — admin-only config: notification prefs, SMTP, email templates.
// Extracted from server.js. All routes are requireAdmin; deps are injected. express + nodemailer
// are required directly here (they're stateless libs).

const express = require('express');
const nodemailer = require('nodemailer');

module.exports = function registerAdminConfigRoutes({
  app, db, log, requireAdmin, decryptText,
  getNotifyPrefs, saveNotifyPrefs, getSmtpConfig, saveSmtpConfig, getEmailTemplate, saveEmailTemplate,
  NOTIFY_EVENT_TYPES,
}) {
  // GET returns the current toggles plus which keys are locked-on (login). POST
  // saves the toggleable ones; login can never be turned off.
  app.get('/api/admin/notify-prefs', requireAdmin, async (req, res) => {
    res.json({ prefs: (await getNotifyPrefs()), locked: ['login'], types: ['login', ...NOTIFY_EVENT_TYPES] });
  });
  app.post('/api/admin/notify-prefs', requireAdmin, express.json(), async (req, res) => {
    try {
      (await saveNotifyPrefs(req.body?.prefs || req.body || {}));
      res.json({ ok: true, prefs: (await getNotifyPrefs()) });
    } catch (e) { res.status(500).json({ error: 'Failed to save preferences' }); }
  });

  // ── SMTP config + Email template routes (admin only, after requireAuth) ───────
  app.get('/api/admin/smtp', requireAdmin, async (req, res) => {
    const cfg = (await getSmtpConfig());
    // Never expose the raw password in the response
    res.json({ ...cfg, pass: cfg.pass ? '••••••••' : '' });
  });

  app.post('/api/admin/smtp', requireAdmin, async (req, res) => {
    const { host, port, secure, user, pass, from_name, from_email } = req.body || {};
    const existing = (await getSmtpConfig());
    // If admin didn't change the placeholder password, keep the existing one
    const finalPass = (pass && pass !== '••••••••') ? pass : (existing.pass || '');
    (await saveSmtpConfig({ host, port, secure, user, pass: finalPass, from_name, from_email }));
    res.json({ ok: true });
  });

  app.post('/api/admin/smtp/test', requireAdmin, async (req, res) => {
    const cfg = (await getSmtpConfig());
    if (!cfg.host) return res.status(400).json({ error: 'SMTP is not configured — set the host and save first.' });
    // Recipient: explicit body.to → the admin's own account email (if any) → from_email → smtp user.
    // (The built-in admin session has userId=null, so the account-email lookup is best-effort only.)
    let to = String(req.body?.to || '').trim();
    if (!to && req.session.userId) {
      try { to = decryptText((await db.prepare('SELECT email FROM users WHERE id=?').get(req.session.userId))?.email || '') || ''; } catch {}
    }
    if (!to) to = cfg.from_email || cfg.user || '';
    if (!to) return res.status(400).json({ error: 'No recipient — enter a test email address.' });
    try {
      const transport = nodemailer.createTransport({
        host: cfg.host, port: Number(cfg.port) || 587,
        secure: cfg.secure === true || cfg.port == 465,
        auth: cfg.user ? { user: cfg.user, pass: cfg.pass } : undefined,
      });
      await transport.sendMail({
        from: `"${cfg.from_name || 'SentinelMDM'}" <${cfg.from_email || cfg.user}>`,
        to, subject: 'SentinelMDM — SMTP test',
        html: `<p style="font-family:sans-serif">SMTP configuration is working. Test sent at ${new Date().toUTCString()}.</p>`,
      });
      log('info', 'SMTP test email sent', { to });
      res.json({ ok: true, to });
    } catch (e) {
      log('error', 'SMTP test failed', { to, err: e.message });
      res.status(502).json({ error: `Send failed: ${e.message}`, to });
    }
  });

  app.get('/api/admin/email-template/:key', requireAdmin, async (req, res) => {
    res.json((await getEmailTemplate(req.params.key)));
  });

  app.post('/api/admin/email-template/:key', requireAdmin, async (req, res) => {
    const { subject, body } = req.body || {};
    if (!subject || !body) return res.status(400).json({ error: 'subject and body required' });
    (await saveEmailTemplate(req.params.key, subject, body));
    res.json({ ok: true });
  });

  app.post('/api/admin/email-template/:key/reset', requireAdmin, async (req, res) => {
    (await db.prepare('DELETE FROM settings WHERE key = ?').run('email_tpl_' + req.params.key));
    res.json((await getEmailTemplate(req.params.key)));
  });
};
