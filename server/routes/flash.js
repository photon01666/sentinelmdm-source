// routes/flash.js — OS-flash trial bind, status, admin-assist.
// Extracted from server.js L3742-3818. 3 routes.
module.exports = ({ app, DAY_MS, TRIAL_DAYS, daysRemaining, db, encryptText, genLicenseKey, hwidHmac, log, notifyAdminForUser, recordTosAcceptance }) => {

app.post('/api/flash/bind', async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'public account required' });
  const serial = (req.body && req.body.hardware_id || '').toString().trim();
  if (!serial || serial.length < 3 || serial.length > 128)
    return res.status(400).json({ error: 'valid hardware_id required' });

  const userId  = req.session.userId;
  const hmac    = hwidHmac(serial);
  const now     = Date.now();

  let ent = (await db.prepare("SELECT * FROM entitlements WHERE user_id=? AND hardware_id_hmac=? AND trial_type='os_flash_7'")
              .get(userId, hmac));

  const otherOwner = (await db.prepare("SELECT user_id FROM entitlements WHERE hardware_id_hmac=? AND trial_type='os_flash_7' AND user_id<>?")
                       .get(hmac, userId));
  if (otherOwner)
    return res.status(409).json({ error: 'This device is already registered to another account.' });

  if (!ent) {
    const key      = (await genLicenseKey());
    const deadline = now + (TRIAL_DAYS.os_flash_7 * DAY_MS);
    (await db.prepare(`INSERT INTO entitlements
      (license_key,user_id,order_id,device_id,trial_type,hardware_id,hardware_id_hmac,
       trial_start_date,software_trial_deadline,status,created_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?)`).run(
      key, userId, null, null, 'os_flash_7',
      encryptText(serial), hmac, now, deadline, 'Active', now));
    ent = (await db.prepare('SELECT * FROM entitlements WHERE license_key=?').get(key));
    log('info', 'OS flash trial bound', { userId, hwid_hmac: hmac.slice(0, 12), licenseKey: key });
  }

  if (req.body && req.body.tos && req.body.tos.accepted) {
    (await recordTosAcceptance(req, { userId, email: req.session.username || null,
      policyKey: req.body.tos.policy_key || 'os_flash_trial',
      policyVersion: req.body.tos.policy_version || '1',
      policyText: req.body.tos.policy_text || null }));
  }

  res.json({
    ok: true, license_key: ent.license_key, trial_type: ent.trial_type,
    status: ent.status, trial_days: TRIAL_DAYS.os_flash_7,
    software_trial_deadline: ent.software_trial_deadline,
    days_remaining: daysRemaining(ent.software_trial_deadline),
  });
});

app.get('/api/flash/status', async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'public account required' });
  const rows = (await db.prepare("SELECT * FROM entitlements WHERE user_id=? AND trial_type='os_flash_7' ORDER BY created_at DESC")
                 .all(req.session.userId)).map(e => ({
    license_key: e.license_key, status: e.status,
    software_trial_deadline: e.software_trial_deadline || null,
    days_remaining: daysRemaining(e.software_trial_deadline),
  }));
  res.json({ entitlements: rows });
});

app.post('/api/flash/admin-assist', async (req, res) => {
  if (!req.session.authenticated)
    return res.status(401).json({ error: 'Unauthorized' });
  const stage  = String(req.body?.stage  || 'unknown').slice(0, 80);
  const detail = String(req.body?.detail || '').slice(0, 500);
  const who    = req.session.username || `user#${req.session.userId || '?'}`;
  notifyAdminForUser(
    `🛠️ Flasher Admin Assist requested\n**User:** ${who}\n**Stage:** \`${stage}\`\n**Detail:** ${detail || '_none_'}`,
    req.session.userId
  ).catch(() => {});
  log('warn', 'Flasher admin-assist', { who, stage, detail });
  res.json({ ok: true });
});

};
