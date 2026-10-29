module.exports = ({ app, AUTH_SCHEME_PREHASH, COMP_PLANS, COMP_PLAN_LABEL, bcrypt, businessModeQualifies, computeAuthPrehash, db, decryptText, encryptText, hwidHmac, log, looksLikeAuthHash, looksLikeAuthSalt, newAuthSalt, normIdent, notifyAdminForUser, notifyAdminLogin, requireAdmin, requireAuth, revokeUserSessions, signalAlert, speakeasy, stmts, trialInfo, verifyUserPassword }) => {
app.get('/api/users', requireAdmin, async (_req, res) => {
  const users = (await stmts.allUsers.all()).map(u => ({
    ...u,
    permissions:      JSON.parse(decryptText(u.permissions)        || '{}'),
    enabled_features: JSON.parse(decryptText(u.enabled_features || '{}') || '{}'),
    trial:            trialInfo(u),
    comp:             (u.comp_plan && !(u.comp_expires_at != null && Number(u.comp_expires_at) <= Date.now()))
                        ? { plan: u.comp_plan, label: COMP_PLAN_LABEL[u.comp_plan] || u.comp_plan,
                            expires_at: u.comp_expires_at || null, granted_by: u.comp_granted_by || null }
                        : null,
  }));
  res.json(users);
});

app.post('/api/users', requireAdmin, async (req, res) => {
  const { username, password, auth_hash, auth_salt, role = 'user', permissions = {} } = req.body;
  // The dashboard sends the new user's credential pre-hashed (auth_hash + auth_salt); a plaintext
  // submission (older cached dashboard) is converted here so every new row is scheme-uniform.
  const usingPrehash = looksLikeAuthHash(auth_hash) && looksLikeAuthSalt(auth_salt);
  if (!username || (!password && !usingPrehash))
    return res.status(400).json({ error: 'Username and password required' });
  if ((await stmts.userByName.get(username)))
    return res.status(409).json({ error: 'Username already exists' });
  const salt = usingPrehash ? auth_salt : newAuthSalt();
  const hash = bcrypt.hashSync(usingPrehash ? auth_hash : (await computeAuthPrehash(password, salt)), 10);
  const { id: id } = (await stmts.insertUser.get(
    username, hash, role, encryptText(JSON.stringify(permissions)), Date.now(), AUTH_SCHEME_PREHASH, salt
  ));
  log('info', 'User created via API', { username, role });
  res.json({ ok: true, id });
});

app.put('/api/users/:id/permissions', requireAdmin, async (req, res) => {
  const { permissions } = req.body;
  (await stmts.updateUserPerms.run(encryptText(JSON.stringify(permissions || {})), req.params.id));
  res.json({ ok: true });
});

app.delete('/api/users/:id', requireAdmin, async (req, res) => {
  (await stmts.deleteUser.run(req.params.id));
  res.json({ ok: true });
});

// ── Admin: grant / revoke a complimentary ("comp") subscription for a public user ──────────
// A comp sub is a FREE admin override: the public account is treated as if it holds a live paid
// plan — no trial lock, no 48h auto-wipe (userHasActiveSubscription/trialLockState/runTrialSweep
// all honor it), and its device cap follows the plan (deviceLimitForUser). It lives on the users
// row (not `subscriptions`) so a Stripe webhook can't clobber it, and takes priority over real
// billing. Grant body: { plan: 'unlimited'|'1device', days?: number } — omit days (or days<=0)
// for a perpetual comp. Admin-only; target must be a public account.
app.post('/api/users/:id/comp-sub', requireAdmin, async (req, res) => {
  const target = (await db.prepare('SELECT id, username, account_type FROM users WHERE id=?').get(req.params.id));
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.account_type !== 'public')
    return res.status(400).json({ error: 'Complimentary subscriptions apply to public (FamilySafe) accounts only.' });
  const plan = String(req.body?.plan || 'unlimited');
  if (!COMP_PLANS.has(plan)) return res.status(400).json({ error: 'Invalid plan — use "unlimited", "1device", or "hybrid".' });
  const days = Number(req.body?.days);
  const expiresAt = (Number.isFinite(days) && days > 0) ? Date.now() + Math.round(days * 86400000) : null;
  (await db.prepare('UPDATE users SET comp_plan=?, comp_expires_at=?, comp_granted_by=?, comp_granted_at=? WHERE id=?')
    .run(plan, expiresAt, req.session.username || 'admin', Date.now(), target.id));
  // Clear any "1 day left" trial-warning flag so a previously-warned account can't be silently
  // wipe-eligible the instant a (later) comp lapses — it would have to be re-warned first.
  try { (await db.prepare('UPDATE users SET trial_1d_alerted_at=NULL WHERE id=?').run(target.id)); } catch {}
  log('info', 'Complimentary subscription granted', { userId: target.id, username: target.username, plan, expiresAt, by: req.session.username });
  res.json({ ok: true, comp: { plan, label: COMP_PLAN_LABEL[plan] || plan, expires_at: expiresAt } });
});
app.delete('/api/users/:id/comp-sub', requireAdmin, async (req, res) => {
  const target = (await db.prepare('SELECT id, username, email FROM users WHERE id=?').get(req.params.id));
  if (!target) return res.status(404).json({ error: 'User not found' });
  (await db.prepare('UPDATE users SET comp_plan=NULL, comp_expires_at=NULL, comp_granted_by=NULL, comp_granted_at=NULL WHERE id=?').run(target.id));
  // Also wipe any comp stashed for this email lineage (account_continuity), so a revoked comp can NOT
  // be resurrected by wiping + re-registering the same email — the registration restore trusts the
  // stash, and an open-ended (NULL-expiry) comp would otherwise re-apply forever. Best-effort.
  try {
    const eh = (() => { const em = normIdent(decryptText(target.email)); return em ? hwidHmac(em) : null; })();
    if (eh) (await db.prepare('UPDATE account_continuity SET comp_plan=NULL, comp_expires_at=NULL WHERE email_hmac=?').run(eh));
  } catch (e) { log('warn', 'account_continuity comp clear failed', { userId: target.id, error: e.message }); }
  log('info', 'Complimentary subscription revoked', { userId: target.id, username: target.username, by: req.session.username });
  res.json({ ok: true });
});

// ── Business Account compliance mode ──────────────────────────────────────────────────────
// One-way toggle: a public user may turn this ON (permanently blocks audio/video/screen-recording/
// keylog/manual-photo commands on every device they own — see BUSINESS_MODE_BLOCKED_COMMANDS),
// but this endpoint can NEVER turn it back off. Only an admin can revert it (below), in case of
// accidental activation. Re-auth (password + 2FA code if enabled) mirrors totp/disable's shape.
app.post('/api/account/business-mode', requireAuth, async (req, res) => {
  if (req.session?.account_type !== 'public' || !req.session.userId)
    return res.status(403).json({ error: 'Public account required' });
  const userId = req.session.userId;
  const user = (await db.prepare(`SELECT id, username, email, password_hash, pw_scheme, auth_salt,
    totp_secret, totp_verified, business_mode, comp_plan, comp_expires_at, trial_enabled, trial_started_at
    FROM users WHERE id=?`).get(userId));
  if (!user) return res.status(404).json({ error: 'Account not found' });
  if (user.business_mode) return res.status(409).json({ error: 'Business Account mode is already on.' });
  if (!(await businessModeQualifies(user)))
    return res.status(403).json({ error: 'Business Account mode requires an active free trial, an annual plan, or the Unlimited plan — upgrade to unlock it.', business_mode_upgrade_required: true });

  const { password, authHash, code } = req.body || {};
  if (!(await verifyUserPassword(user, { password, authHash }))) {
    (await notifyAdminLogin('🔴 Business Account Toggle — Wrong Password\n' +
      `Failed re-auth on Business Account activation for user #${userId}.`, userId));
    return res.status(401).json({ error: 'Incorrect password' });
  }
  if (user.totp_verified) {
    const totpSecret = decryptText(user.totp_secret);
    const valid = !!totpSecret && speakeasy.totp.verify({
      secret: totpSecret, encoding: 'base32', token: String(code || '').replace(/\s/g, ''), window: 1,
    });
    if (!valid) return res.status(401).json({ error: 'Invalid 2FA code' });
  }

  (await db.prepare('UPDATE users SET business_mode=1, business_mode_set_at=? WHERE id=?').run(Date.now(), userId));
  log('warn', 'Account converted to Business Account (compliance mode)', { userId, username: user.username });
  notifyAdminForUser(`🏢 Business Account Activated\nUser \`${user.username}\` (#${userId}) enabled Business Account mode — permanent, only an admin can revert it.`, userId);
  res.json({ ok: true, business_mode: true });
});

// Admin-only revert (in case of accidental activation) — mirrors the comp-sub grant/revoke style.
app.delete('/api/users/:id/business-mode', requireAdmin, async (req, res) => {
  const target = (await db.prepare('SELECT id, username, account_type, business_mode FROM users WHERE id=?').get(req.params.id));
  if (!target) return res.status(404).json({ error: 'User not found' });
  if (target.account_type !== 'public')
    return res.status(400).json({ error: 'Business Account mode applies to public (FamilySafe) accounts only.' });
  if (!target.business_mode) return res.json({ ok: true, already: true });
  (await db.prepare('UPDATE users SET business_mode=0, business_mode_reverted_at=?, business_mode_reverted_by=? WHERE id=?')
    .run(Date.now(), req.session.username || 'admin', target.id));
  log('warn', 'Business Account mode reverted by admin', { userId: target.id, username: target.username, by: req.session.username });
  (await signalAlert('🏢 Business Account Reverted', `Admin reverted Business Account mode for "${target.username}" (#${target.id}).`, req));
  res.json({ ok: true });
});

// ── Business sub-users (account_type='business_sub') ──────────────────────────────────────
// ONLY a business_mode=1 owner may create these. Full ZK parity: the sub-user holds a re-wrapped
// COPY of the owner's own EC private key (produced client-side in the owner's browser via
// _zkRewrapPrivKey(), never the raw key) — so their login can decrypt exactly the devices the
// owner grants them, via the same permissions-map mechanism admin_created sub-users use, scoped
// to the owner's own fleet by parent_owner_id. Max 10 team members per owner.
const MAX_BUSINESS_SUBUSERS = 10;

app.post('/api/account/subusers', requireAuth, async (req, res) => {
  if (req.session?.account_type !== 'public' || !req.session.userId)
    return res.status(403).json({ error: 'Public account required' });
  const owner = (await db.prepare('SELECT id, business_mode, zk_public_key FROM users WHERE id=?').get(req.session.userId));
  if (!owner?.business_mode) return res.status(403).json({ error: 'Business Account mode required to add team members.' });
  if (!owner.zk_public_key) return res.status(400).json({ error: 'Your account has no encryption key yet — sign in again first.' });

  let { username, auth_hash, auth_salt, zk_encrypted_priv_key, zk_salt } = req.body || {};
  // Team member logins are their email address — used as both `username` (the literal login
  // identifier) and `email` (so /login's isEmail branch, which looks up ONLY by the email column
  // for an '@'-containing identifier, actually finds the row).
  const email = String(username || '').trim().toLowerCase();
  if (!email || email.length > 200 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return res.status(400).json({ error: 'Enter a valid email address for the team member.' });
  if (!looksLikeAuthHash(auth_hash) || !looksLikeAuthSalt(auth_salt))
    return res.status(400).json({ error: 'Invalid credential data — please reload and try again.' });
  if (typeof zk_encrypted_priv_key !== 'string' || !zk_encrypted_priv_key || typeof zk_salt !== 'string' || !zk_salt)
    return res.status(400).json({ error: 'Invalid encryption data — please reload and try again.' });
  if ((await stmts.userByName.get(email))) return res.status(409).json({ error: 'An account with this email already exists.' });

  // The Hybrid support delegate is a business_sub too, but not a "team member" — exclude it from the cap.
  const { n } = (await db.prepare('SELECT COUNT(*) AS n FROM users WHERE parent_owner_id=? AND COALESCE(is_support_delegate,0)=0').get(owner.id));
  if (n >= MAX_BUSINESS_SUBUSERS) return res.status(400).json({ error: `Team member limit reached (${MAX_BUSINESS_SUBUSERS}).` });

  const hash = bcrypt.hashSync(auth_hash, 10);
  const { id } = (await db.prepare(
    `INSERT INTO users (username,email,password_hash,role,permissions,created_at,pw_scheme,auth_salt,
                         account_type,parent_owner_id,status,zk_public_key,zk_encrypted_priv_key,zk_salt)
     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?) RETURNING id`
  ).get(email, email, hash, 'user', encryptText('{}'), Date.now(), AUTH_SCHEME_PREHASH, auth_salt,
        'business_sub', owner.id, 'active', owner.zk_public_key, zk_encrypted_priv_key, zk_salt));
  log('info', 'Business sub-user created', { userId: id, email, parentOwnerId: owner.id });
  (await signalAlert('👥 Business Team Member Added', `"${req.session.username}" added team member "${email}".`, req));
  res.json({ ok: true, id, username: email });
});

app.get('/api/account/subusers', requireAuth, async (req, res) => {
  if (req.session?.account_type !== 'public') return res.status(403).json({ error: 'Public account required' });
  const rows = (await db.prepare('SELECT id, username, permissions, created_at FROM users WHERE parent_owner_id=? AND COALESCE(is_support_delegate,0)=0 ORDER BY created_at').all(req.session.userId));
  res.json(rows.map(r => ({
    id: r.id, username: r.username, created_at: r.created_at,
    permissions: JSON.parse(decryptText(r.permissions) || '{}'),
  })));
});

app.delete('/api/account/subusers/:subUserId', requireAuth, async (req, res) => {
  if (req.session?.account_type !== 'public') return res.status(403).json({ error: 'Public account required' });
  const target = (await db.prepare('SELECT id, parent_owner_id, username FROM users WHERE id=?').get(req.params.subUserId));
  if (!target || target.parent_owner_id !== req.session.userId) return res.status(404).json({ error: 'Team member not found' });
  (await db.prepare('DELETE FROM users WHERE id=?').run(target.id));
  (await revokeUserSessions(target.id));
  log('info', 'Business sub-user removed', { userId: target.id, username: target.username, by: req.session.userId });
  res.json({ ok: true });
});

// Grant/revoke ONE device's permission-map entry for ONE of the caller's own sub-users. Scoped
// BOTH ways: the target sub-user must belong to this caller, AND the device must be owned by this
// caller — an owner can only ever grant devices they actually own.
app.put('/api/account/subusers/:subUserId/devices/:deviceId', requireAuth, async (req, res) => {
  if (req.session?.account_type !== 'public') return res.status(403).json({ error: 'Public account required' });
  const owner = (await db.prepare('SELECT id, business_mode FROM users WHERE id=?').get(req.session.userId));
  if (!owner?.business_mode) return res.status(403).json({ error: 'Business Account mode required.' });
  const sub = (await stmts.getUserById.get(req.params.subUserId));
  if (!sub || sub.parent_owner_id !== owner.id) return res.status(404).json({ error: 'Team member not found' });
  const device = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(req.params.deviceId));
  if (!device || device.owner_user_id !== owner.id) return res.status(403).json({ error: 'You do not own this device' });
  const perms = JSON.parse(decryptText(sub.permissions) || '{}');
  perms[req.params.deviceId] = req.body?.permissions || {};
  (await stmts.updateUserPerms.run(encryptText(JSON.stringify(perms)), sub.id));
  res.json({ ok: true });
});

app.delete('/api/account/subusers/:subUserId/devices/:deviceId', requireAuth, async (req, res) => {
  if (req.session?.account_type !== 'public') return res.status(403).json({ error: 'Public account required' });
  const owner = (await db.prepare('SELECT id FROM users WHERE id=?').get(req.session.userId));
  const sub = (await stmts.getUserById.get(req.params.subUserId));
  if (!sub || sub.parent_owner_id !== owner.id) return res.status(404).json({ error: 'Team member not found' });
  const perms = JSON.parse(decryptText(sub.permissions) || '{}');
  delete perms[req.params.deviceId];
  (await stmts.updateUserPerms.run(encryptText(JSON.stringify(perms)), sub.id));
  res.json({ ok: true });
});
};
