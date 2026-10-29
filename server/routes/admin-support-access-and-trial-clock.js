// routes/admin-support-access-and-trial-clock.js — Admin "Support Access" dashboard (list/
// reveal-code/impersonate/exit-impersonation) + manual trial-countdown set/reset for public
// users. Extracted from server.js L6354-6489. 6 routes.
module.exports = ({ app, TRIAL_LEN_MS, db, decryptText, log, requireAdmin, requireAuth, signalAlert, trialInfo }) => {
// ── Admin: "Support Access" dashboard menu ────────────────────────────────────────────────
// Lists every Hybrid Managed account that has granted support access (safe metadata only — owner,
// granted date, device count) and lets a staff member fetch the E2E-encrypted code envelope for a
// specific delegate to decrypt CLIENT-SIDE with their unwrapped Support private key (same mechanism
// as decrypting a Conversations message). The server never sees the plaintext code at any point.
app.get('/api/admin/support-access', requireAdmin, async (req, res) => {
  // `devices` is a LIVE count off the owner's current fleet, not the delegate's grant-time
  // permissions snapshot — the delegate always has access to all of them (see
  // applySupportDelegatePerms), so counting the stale blob would under-report here too.
  const rows = (await db.prepare(
    `SELECT u.id AS delegate_id, u.username AS delegate_login, u.created_at,
            o.id AS owner_id, o.username AS owner_username, o.email AS owner_email_enc,
            (SELECT COUNT(*) FROM devices d WHERE d.owner_user_id = o.id) AS device_count
     FROM users u JOIN users o ON u.parent_owner_id = o.id
     WHERE u.is_support_delegate = 1
     ORDER BY u.created_at DESC`
  ).all());
  res.json(rows.map(r => ({
    delegate_id: r.delegate_id,
    owner_id: r.owner_id,
    owner_username: r.owner_username,
    owner_email: decryptText(r.owner_email_enc) || null,
    delegate_login: r.delegate_login,
    granted_at: r.created_at,
    devices: Number(r.device_count) || 0,
  })));
});

// Returns the E2E ciphertext envelope only — decryption happens in the admin's browser. Every
// fetch is audit-logged (who, when) since this is the access point to a credential that unlocks
// a customer's private data.
app.get('/api/admin/support-access/:delegateId/code', requireAdmin, async (req, res) => {
  const row = (await db.prepare('SELECT id, support_code_payload, support_code_dek_support FROM users WHERE id=? AND is_support_delegate=1').get(req.params.delegateId));
  if (!row) return res.status(404).json({ error: 'Support delegate not found' });
  if (!row.support_code_payload || !row.support_code_dek_support)
    return res.status(404).json({ error: 'No code on file for this delegate.' });
  (await db.prepare('INSERT INTO support_code_reveals (delegate_user_id, revealed_by, revealed_at) VALUES (?,?,?)')
    .run(row.id, req.session.username, Date.now()));
  log('info', 'Support access code fetched by admin', { delegateUserId: row.id, by: req.session.username });
  res.json({ payload: row.support_code_payload, dek_support: JSON.parse(row.support_code_dek_support) });
});

// Nextcloud-style "log in as" for a support delegate — swaps the ADMIN's own session to the
// delegate identity (same session fields /login sets for a business_sub account) so every
// permission/ownership check in the app just works as if the admin had actually signed in with
// the login+code. The admin's own session is snapshotted into req.session._preImpersonation so
// POST .../exit-impersonation can restore it exactly; nesting is refused rather than silently
// overwriting the snapshot (would strand the admin's real identity). This only swaps the SERVER
// session — the browser must separately unwrap the ZK private key using the (already E2E-revealed)
// plaintext code and zk_salt/zk_encrypted_priv_key returned here, same as a normal login does.
app.post('/api/admin/support-access/:delegateId/impersonate', requireAdmin, async (req, res) => {
  if (req.session.impersonating) return res.status(409).json({ error: 'Already impersonating a support delegate — exit that session first.' });
  const delegate = (await db.prepare('SELECT * FROM users WHERE id=? AND is_support_delegate=1').get(req.params.delegateId));
  if (!delegate) return res.status(404).json({ error: 'Support delegate not found' });
  const owner = (await db.prepare('SELECT id, username, email FROM users WHERE id=?').get(delegate.parent_owner_id));

  req.session._preImpersonation = {
    username: req.session.username, role: req.session.role, userId: req.session.userId,
    account_type: req.session.account_type, parent_owner_id: req.session.parent_owner_id || null,
    permissions: req.session.permissions || {}, enabled_features: req.session.enabled_features || {},
  };
  req.session.impersonating   = true;
  req.session.username        = delegate.username;
  req.session.role            = delegate.role;
  req.session.userId          = delegate.id;
  req.session.account_type    = delegate.account_type || 'business_sub';
  req.session.parent_owner_id = delegate.parent_owner_id || null;
  req.session.permissions     = JSON.parse(decryptText(delegate.permissions) || '{}');
  req.session.enabled_features = JSON.parse(decryptText(delegate.enabled_features || '{}') || '{}');
  req.session.is_support_delegate = true;   // the row above was verified is_support_delegate=1

  const adminUsername = req.session._preImpersonation.username;
  log('info', 'Admin impersonated support delegate', {
    adminId: req.session._preImpersonation.userId, adminUsername, delegateId: delegate.id, ownerId: owner?.id,
  });
  (await signalAlert('🛟 Admin Impersonating Support Delegate',
    `Admin \`${adminUsername}\` is now signed in as the support-delegate identity for \`${owner?.username || 'unknown'}\`.`, req));
  res.json({
    ok: true, zk_salt: delegate.zk_salt, zk_encrypted_priv_key: delegate.zk_encrypted_priv_key,
    owner_username: owner?.username || null, owner_email: decryptText(owner?.email) || null,
  });
});

app.post('/api/admin/support-access/exit-impersonation', requireAuth, async (req, res) => {
  if (!req.session.impersonating || !req.session._preImpersonation)
    return res.status(400).json({ error: 'Not currently impersonating a support delegate.' });
  const pre = req.session._preImpersonation;
  log('info', 'Admin exited support-delegate impersonation', { adminId: pre.userId, delegateId: req.session.userId });
  req.session.username        = pre.username;
  req.session.role            = pre.role;
  req.session.userId          = pre.userId;
  req.session.account_type    = pre.account_type;
  req.session.parent_owner_id = pre.parent_owner_id;
  req.session.permissions     = pre.permissions;
  req.session.enabled_features = pre.enabled_features;
  req.session.impersonating   = false;
  req.session._preImpersonation = null;
  delete req.session.is_support_delegate;   // back to a clean admin session
  res.json({ ok: true });
});

// ── Admin: manually edit the exact 30-day trial countdown for a public user ──────────────
// Unlike the comp-sub override (which EXEMPTS the account from the trial entirely), this edits the
// trial CLOCK itself — e.g. to test the near-expiry/expired UI, backdate a re-homed test device's
// inherited start, or give a support case a specific number of days without granting a full comp
// plan. Body: { daysRemaining: number } — 0..3650. Computes trial_started_at so that, AS OF RIGHT
// NOW, exactly `daysRemaining` days are left (same days_remaining math as trialInfo()), so this can
// both shorten AND lengthen the trial — not just add to it.
app.post('/api/users/:id/trial', requireAdmin, async (req, res) => {
  const target = (await db.prepare('SELECT id, username, account_type FROM users WHERE id=?').get(req.params.id));
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.account_type !== 'public')
    return res.status(400).json({ error: 'The trial clock only applies to public (FamilySafe) accounts.' });
  const daysRemaining = Number(req.body?.daysRemaining);
  if (!Number.isFinite(daysRemaining) || daysRemaining < 0 || daysRemaining > 3650)
    return res.status(400).json({ error: 'daysRemaining must be between 0 and 3650' });
  const startedAt = Date.now() + Math.round(daysRemaining * 86400000) - TRIAL_LEN_MS;
  // trial_enabled=1: setting an exact countdown implies the trial mechanism should be active for
  // this account even if it somehow wasn't (e.g. a comp-only account being switched back to trial).
  // Clear trial_1d_alerted_at so a freshly-lengthened trial isn't left wipe-eligible from a stale warning.
  (await db.prepare('UPDATE users SET trial_enabled=1, trial_started_at=?, trial_1d_alerted_at=NULL WHERE id=?')
    .run(startedAt, target.id));
  log('info', 'Trial countdown manually set by admin', { userId: target.id, username: target.username, daysRemaining, by: req.session.username });
  res.json({ ok: true, trial: trialInfo({ trial_enabled: 1, trial_started_at: startedAt }) });
});
// Reset a trial back to "awaiting first device" (un-starts the countdown) — e.g. to re-test the
// enrollment/first-connect flow from a clean slate without deleting the account.
app.delete('/api/users/:id/trial', requireAdmin, async (req, res) => {
  const target = (await db.prepare('SELECT id, username, account_type FROM users WHERE id=?').get(req.params.id));
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.account_type !== 'public')
    return res.status(400).json({ error: 'The trial clock only applies to public (FamilySafe) accounts.' });
  (await db.prepare('UPDATE users SET trial_started_at=NULL, trial_1d_alerted_at=NULL WHERE id=?').run(target.id));
  log('info', 'Trial countdown reset by admin', { userId: target.id, username: target.username, by: req.session.username });
  res.json({ ok: true });
});
};
