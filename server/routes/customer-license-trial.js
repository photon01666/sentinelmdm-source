module.exports = ({ app, daysRemaining, genLicenseKey, log, TRIAL_DAYS, trialStmts }) => {
// ── Phase 1: customer license / trial management (session-authenticated) ─────
// A logged-in public user mints (idempotently) their 30-day digital agent trial,
// then downloads the agent and provisions it as Device Owner (see /docs).
app.post('/api/license/register', async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'public account required' });
  const userId = req.session.userId;
  let ent = trialStmts.entDigitalForUser.get(userId);   // one digital trial per account
  if (!ent) {
    const key = (await genLicenseKey());
    trialStmts.insertEnt.run(key, userId, null, 'digital_mdm_7', 'Active', Date.now());
    ent = trialStmts.entByLicense.get(key);
    log('info', 'Digital trial license issued', { userId, licenseKey: key });
  }
  res.json({
    license_key: ent.license_key, trial_type: ent.trial_type, status: ent.status,
    trial_days: TRIAL_DAYS[ent.trial_type] || 30,
    activated: !!ent.trial_start_date,
    software_trial_deadline: ent.software_trial_deadline || null,
    days_remaining: daysRemaining(ent.software_trial_deadline),
    download_url: '/api/update/apk',
  });
});

app.get('/api/license/status', (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'public account required' });
  const rows = trialStmts.entByUser.all(req.session.userId).map(e => ({
    license_key: e.license_key, trial_type: e.trial_type, status: e.status,
    activated: !!e.trial_start_date,
    trial_start_date: e.trial_start_date || null,
    software_trial_deadline: e.software_trial_deadline || null,
    hardware_return_deadline: e.hardware_return_deadline || null,
    days_remaining: daysRemaining(e.software_trial_deadline),
    device_id: e.device_id || null,
  }));
  res.json({ entitlements: rows });
});
};
