module.exports = ({ app, authenticateDeviceRequest, daysRemaining, DAY_MS, log,
  maybeAlertTrialLapse, requireUnlocked, trialStmts, TRIAL_DAYS }) => {
// ── Phase 1: SentinelOS agent software trial (30-day) ─────────────────────────
// Agent calls this on boot + periodically to ACTIVATE and CHECK its trial.
// Device-signature auth (x-device-* headers) — MUST stay above app.use(requireAuth);
// the agent has no session cookie. Body: { license_key } (or x-license-key header).
// First valid ping starts the 30-day countdown and binds the license to the device.
app.post('/api/license/ping', requireUnlocked, async (req, res) => {
  if (!(await authenticateDeviceRequest(req)))
    return res.status(401).json({ valid: false, error: 'unauthorized' });
  const deviceId   = req.headers['x-device-id'];
  const licenseKey = (req.body && req.body.license_key) || req.headers['x-license-key'];
  if (!licenseKey)
    return res.status(400).json({ valid: false, error: 'license_key required' });

  const ent = trialStmts.entByLicense.get(licenseKey);
  if (!ent) return res.status(404).json({ valid: false, status: 'invalid' });

  const now = Date.now();

  // First ping → bind device + start the countdown.
  if (!ent.trial_start_date) {
    const days     = TRIAL_DAYS[ent.trial_type] || 30;
    const deadline = now + days * DAY_MS;
    trialStmts.activateEnt.run(deviceId, now, deadline, now, now, ent.id);
    log('info', 'Trial activated', { licenseKey, deviceId, trial_type: ent.trial_type });
    return res.json({ valid: true, status: 'Active', software_trial_deadline: deadline,
                      days_remaining: daysRemaining(deadline), server_time: now });
  }

  // License already bound to a different device → refuse (no key sharing).
  if (ent.device_id && ent.device_id !== deviceId)
    return res.status(409).json({ valid: false, status: 'bound_other_device' });

  // Subsequent pings → refresh last_ping. Trial expiry NEVER auto-disables the
  // account (user policy 2026-05-30). When the deadline passes we alert the admin
  // ONCE and keep serving as valid until the admin extends or expires it. Only an
  // admin-set 'Expired' status invalidates the license.
  trialStmts.touchEnt.run(now, ent.id);
  const pastDeadline = ent.software_trial_deadline ? now > ent.software_trial_deadline : false;
  if (ent.status === 'Active' && pastDeadline) (await maybeAlertTrialLapse(ent));
  const valid = ent.status !== 'Expired';   // grace continues past deadline until admin acts
  res.json({ valid, status: ent.status, in_grace: valid && pastDeadline,
             software_trial_deadline: ent.software_trial_deadline,
             days_remaining: daysRemaining(ent.software_trial_deadline), server_time: now });
});
};
