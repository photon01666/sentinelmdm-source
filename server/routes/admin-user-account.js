// routes/admin-user-account.js — Admin per-user account management: wipe, per-device permissions, feature toggles.
// Extracted from server.js L7928-7988. 5 routes.
// Shared helper wipeUserAccount() stays in server.js (also used by routes/account-security.js and the trial
// auto-wipe sweep) and is passed in via ctx — do NOT move it here.
module.exports = ({ app, db, decryptText, encryptText, isDeviceLocked, log, requireAdmin, signalAlert,
  stmts, wipeUserAccount }) => {

app.delete('/api/users/:id/wipe', requireAdmin, async (req, res) => {
  const userId = parseInt(req.params.id, 10);
  // Wrapped for the same reason as POST /api/account/secure — an uncaught exception here must
  // return a real error instead of leaving the admin's request hanging forever.
  let r;
  try {
    r = (await wipeUserAccount(userId));
  } catch (e) {
    log('error', 'Admin wipe threw', { userId, err: e.message });
    return res.status(500).json({ error: 'Wipe failed — please try again or check server logs.' });
  }
  if (!r.ok) return res.status(r.code || 500).json({ error: r.error });
  log('warn', 'Public user account wiped by admin', { userId, username: r.username, devicesReleased: r.devicesReleased });
  // Loud Signal alert — a wipe is the only thing that can detach a locked device, so a stolen
  // admin session abusing it (DoS) must be impossible to do quietly.
  (await signalAlert('🔑 Public Account Wiped',
    `Account "${r.username}" (#${userId}) wiped. ${r.devicesReleased} device(s) released to email lineage "${r.lineageEmail || 'n/a'}" — only a NEW same-email account can re-bind them, and only from the device.`,
    req));
  res.json({ ok: true, devicesReleased: r.devicesReleased, username: r.username });
});

// Grant or update a user's permissions for a specific device
app.put('/api/users/:id/devices/:deviceId', requireAdmin, async (req, res) => {
  const user = (await stmts.getUserById.get(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });
  const perms = JSON.parse(decryptText(user.permissions) || '{}');
  perms[req.params.deviceId] = req.body.permissions || {};
  (await stmts.updateUserPerms.run(encryptText(JSON.stringify(perms)), req.params.id));
  res.json({ ok: true });
});

// Revoke a user's access to a specific device
app.delete('/api/users/:id/devices/:deviceId', requireAdmin, async (req, res) => {
  const user = (await stmts.getUserById.get(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });
  // Permanent lock: admin cannot strip a public owner's access to their own locked device.
  if ((await isDeviceLocked(req.params.deviceId))) {
    (await signalAlert('⚠️ Blocked Device Access Revocation',
      `Admin attempted to revoke access to permanently-locked device ${req.params.deviceId}.`, req, req.params.deviceId));
    return res.status(409).json({ error: 'Device is permanently locked to its owner and cannot be revoked.', locked: true });
  }
  const perms = JSON.parse(decryptText(user.permissions) || '{}');
  delete perms[req.params.deviceId];
  (await stmts.updateUserPerms.run(encryptText(JSON.stringify(perms)), req.params.id));
  res.json({ ok: true });
});

// ── Per-user feature toggles ───────────────────────────────────────────────
app.get('/api/users/:id/features', requireAdmin, async (req, res) => {
  const user = (await db.prepare('SELECT enabled_features FROM users WHERE id=?').get(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json(JSON.parse(decryptText(user.enabled_features || '{}') || '{}'));
});

app.put('/api/users/:id/features', requireAdmin, async (req, res) => {
  const user = (await db.prepare('SELECT id FROM users WHERE id=?').get(req.params.id));
  if (!user) return res.status(404).json({ error: 'User not found' });
  (await db.prepare('UPDATE users SET enabled_features=? WHERE id=?')
    .run(encryptText(JSON.stringify(req.body || {})), req.params.id));
  res.json({ ok: true });
});

};
