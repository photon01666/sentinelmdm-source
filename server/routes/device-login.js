// routes/device-login.js — Device-side ADMIN/SUB login (admin agent variant).
// Authenticates an admin OR sub-user ON the device for enrollment ticket requests.
const speakeasy = require('speakeasy');
module.exports = ({ app, ADMIN_USER, TOTP_SECRET, db, decryptText, loginRateLimit, log,
                    notifyAdminLogin, notifyAdminLoginNodeRed, notifyUser,
                    sendLoginNotificationEmail, signalAlert, stmts, totpRateLimit,
                    verifyUserPassword, session, crypto, getServerGeneration,
                    regenSession }) => {
// ── Device-side ADMIN/SUB login (the ADMIN agent variant) ─────────────────────────────────────────
// Authenticates an admin OR sub-user ON the device so it can request an enrollment ticket and claim
// the device into the admin fleet (lineage_kind='admin'). Mirrors the public /login TOTP flow. Public
// accounts are rejected here (they use the standard agent + /login). Pre-auth; sets the session.
// Session-fixation defense: every auth→session boundary rotates the session ID (regenSession).
function _setAdminAgentSession(req, user, done) {
  regenSession(req, {
    authenticated:    true,
    serverGeneration: getServerGeneration(),
    username:         user.username,
    role:             user.role,
    userId:           user.id,
    account_type:     user.account_type || 'admin_created',
    permissions:      JSON.parse(decryptText(user.permissions) || '{}'),
    enabled_features: JSON.parse(decryptText(user.enabled_features || '{}') || '{}'),
  }, done);
}
app.post('/api/device-admin/login', loginRateLimit, async (req, res) => {
  const { username, password, authHash } = req.body || {};
  const isEmail = username && username.includes('@');
  const user = isEmail ? (await stmts.userByEmail.get(username))
    : ((await stmts.userByName.get(username)) || (await stmts.userByEmail.get(username)));
  if (!user || !(await verifyUserPassword(user, { password, authHash }))) {
    (await signalAlert('🔴 Failed Admin-Agent Login', `Identifier: \`${username || '(blank)'}\``, req));
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.account_type === 'public')
    return res.status(403).json({ error: 'Public accounts use the standard agent.' });
  if (user.role !== 'admin' && user.account_type !== 'admin_created')
    return res.status(403).json({ error: 'This account cannot sign in on a device.' });
  if (user.totp_verified) {                                  // per-account 2FA → defer until verified
    regenSession(req, {
      pendingTotp:    true,
      pendingUserId:  user.id,
      pendingAuthAt:  Date.now(),
    }, () => res.json({ totp_required: true }));
    return;
  }
  _setAdminAgentSession(req, user, () => res.json({ ok: true }));
});
app.post('/api/device-admin/login/totp', totpRateLimit, async (req, res) => {
  if (!req.session?.pendingTotp || !req.session.pendingUserId)
    return res.status(400).json({ error: 'No pending login — start over' });
  const user = (await db.prepare('SELECT * FROM users WHERE id=?').get(req.session.pendingUserId));
  if (!user || (user.role !== 'admin' && user.account_type !== 'admin_created'))
    return res.status(400).json({ error: 'Invalid login state' });
  const valid = speakeasy.totp.verify({ secret: decryptText(user.totp_secret), encoding: 'base32',
    token: (req.body?.code || '').replace(/\s/g, ''), window: 1 });
  if (!valid) return res.status(401).json({ error: 'Invalid code — try again' });
  _setAdminAgentSession(req, user, () => res.json({ ok: true }));
});

app.post('/login', loginRateLimit, async (req, res) => {
  const { username, password, authHash } = req.body;
  const isEmail = username && username.includes('@');
  const user = isEmail
    ? (await stmts.userByEmail.get(username))
    : ((await stmts.userByName.get(username)) || (await stmts.userByEmail.get(username)));
  if (!user || !(await verifyUserPassword(user, { password, authHash }))) {
    (await notifyAdminLogin('🔴 Failed Login — Wrong Password\n' +
      `Identifier attempted: \`${username || '(blank)'}\``, user?.id));
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  // Block public users based on registration status
  if (user.account_type === 'public') {
    if (user.status === 'pending_email') {
      return res.status(403).json({ error: 'Please verify your email from the registration page first.' });
    }
    if (user.status === 'pending_totp') {
      return res.status(403).json({ error: 'Please complete 2FA setup from the registration page first.' });
    }
    if (user.status === 'rejected') {
      return res.status(403).json({ error: 'Your account registration was not approved. Contact the administrator.' });
    }
  }
  if (user.role === 'admin') {
    return res.status(403).json({ error: 'Admin accounts must sign in at /admin/login' });
  }
  // Business sub-users are cryptographically an extension of their business-owner account (they
  // hold a re-wrapped copy of the SAME ZK private key) and go through the exact same ZK
  // salt/derive dance a public owner does — so they share this login route, not
  // /admin/subusers/login (that's for the unrelated global admin-fleet sub-user model).
  if (!['public', 'business_sub'].includes(user.account_type)) {
    return res.status(403).json({ error: 'Sub-user accounts must sign in at /admin/subusers/login' });
  }
  // Public users + business sub-users require per-user 2FA
  if (['public', 'business_sub'].includes(user.account_type) && user.totp_verified) {
    regenSession(req, {
      pendingTotp:     true,
      pendingUsername:  user.username,
      pendingUserRole:  'user',
      pendingUserId:    user.id,
      pendingAuthAt:   Date.now(),
    }, () => {
      res.json({
        totp_required: true,
        // Send ZK fields so browser can derive KEK while user enters TOTP code
        zk_salt:               user.zk_salt || null,
        zk_encrypted_priv_key: user.zk_encrypted_priv_key || null,
      });
    });
    return;
  }
  // Admin-created sub-users — no 2FA required (existing behaviour)
  const buildSession = () => ({
    authenticated:    true,
    serverGeneration: getServerGeneration(),
    username:         user.username,
    role:             user.role,
    userId:           user.id,
    account_type:     user.account_type || 'admin_created',
    parent_owner_id:  user.parent_owner_id || null,
    permissions:      JSON.parse(decryptText(user.permissions) || '{}'),
    enabled_features: JSON.parse(decryptText(user.enabled_features || '{}') || '{}'),
    is_support_delegate: !!user.is_support_delegate,
  });
  let sessionFields;
  try {
    sessionFields = buildSession();
  } catch (e) {
    // A malformed permissions/enabled_features blob must never leave the request hanging (the
    // regenSession callback's own catch would swallow a throw here and res.json() would never
    // fire). Fail closed with a 500 instead.
    log('error', 'login: failed to build session fields', { userId: user.id, err: e.message });
    return res.status(500).json({ error: 'Login failed — could not read account permissions' });
  }
  regenSession(req, sessionFields, () => {
    notifyAdminLogin('✅ Successful Login\n' +
      `User \`${user.username}\` logged in (role: ${user.role}).`, user.id).catch(() => {});
    // Notify public user of their own login
    if (['public', 'business_sub'].includes(user.account_type)) {
      const xff = /** @type {string|undefined} */ (req.headers['x-forwarded-for']);
      const ip  = (xff ? xff.split(',')[0].trim() : null) || req.ip || req.socket?.remoteAddress || 'unknown';
      notifyUser(user.id,
        `🔐 Account Login\nUser: ${user.username}\nTime: ${new Date().toLocaleString()}\nIP: ${ip}\n\nIf this wasn't you, contact your administrator immediately.`,
        { skipEmail: true }
      ).catch(() => {});
      if (user.account_type === 'public') {
        // Always email the owner about the sign-in (not gated by the email_alerts pref).
        sendLoginNotificationEmail(user.id, user.username, ip).catch(() => {});
      } else if (user.parent_owner_id) {
        // A business sub-user holds a live-decryptable copy of the owner's ZK key — the owner
        // should know when a team member signs in.
        notifyUser(user.parent_owner_id,
          `🔐 Team Member Login\nUser: ${user.username}\nTime: ${new Date().toLocaleString()}\nIP: ${ip}\n\nIf you don't recognize this, remove the team member from Account & Security.`,
          { skipEmail: true }
        ).catch(() => {});
      }
    }
    // For public users / business sub-users without TOTP: return ZK fields so the browser can
    // derive and store the private key in sessionStorage (same as the TOTP path does).
    res.json({
      ok: true,
      ...(['public', 'business_sub'].includes(user.account_type) ? {
        zk_salt:               user.zk_salt               || null,
        zk_encrypted_priv_key: user.zk_encrypted_priv_key || null,
      } : {}),
    });
  });
});

// Login step 2 — TOTP (admin + public users)
async function handleTotpVerify(req, res) {
  if (!req.session?.pendingTotp)
    return res.status(401).json({ error: 'No pending login' });

  // Resolve which TOTP secret to verify against
  let totpSecretToUse;
  if (req.session.pendingUserRole === 'admin') {
    const adminUser = req.session.pendingUserId ? (await db.prepare('SELECT totp_secret, totp_verified FROM users WHERE id=?').get(req.session.pendingUserId)) : null;
    let dbSecretDecrypted = adminUser && adminUser.totp_secret ? decryptText(adminUser.totp_secret) : null;
    if (dbSecretDecrypted === 'DISABLED' && (!adminUser || !adminUser.totp_verified)) {
      totpSecretToUse = null;
    } else {
      totpSecretToUse = (adminUser && adminUser.totp_verified && adminUser.totp_secret) ? dbSecretDecrypted : TOTP_SECRET;
    }
  } else {
    const pendingUser = req.session.pendingUserId
      ? (await db.prepare('SELECT totp_secret FROM users WHERE id=?').get(req.session.pendingUserId))
      : null;
    totpSecretToUse = pendingUser ? decryptText(pendingUser.totp_secret) : null;
    if (!totpSecretToUse) return res.status(401).json({ error: '2FA not configured for this account' });
  }

  const valid = speakeasy.totp.verify({
    secret: totpSecretToUse,
    encoding: 'base32',
    token: (req.body.code || '').replace(/\s/g, ''),
    window: 1,
  });
  if (!valid) {
    // Per-session brute-force guard (HIGH-3): the 6-digit code is a 10^6 space and the only limit
    // is per-IP (5/15min) — a distributed guess slips past it. Bound the guesses against THIS
    // pending login: 5 wrong codes burns the pending state and forces a fresh password step (the
    // pendingTotp session was regenerated at the password step, so the counter is per-login-attempt).
    const pendingUid = req.session.pendingUserId;
    const fails = (req.session.pendingTotpFails || 0) + 1;
    req.session.pendingTotpFails = fails;
    if (fails >= 5) {
      req.session.pendingTotp = null;
      req.session.pendingUsername = null;
      req.session.pendingUserRole = null;
      req.session.pendingUserId = null;
      req.session.pendingTotpFails = null;
      (await notifyAdminLogin('🔴 Login — 2FA brute-force guard tripped\nToo many wrong 2FA codes; pending login discarded.', pendingUid));
      return res.status(429).json({ error: 'Too many incorrect codes — please sign in again.' });
    }
    (await notifyAdminLogin('🔴 Failed Login — Wrong 2FA Code\n' +
      'Password was correct but 2FA code was invalid.', pendingUid));
    if (req.session.pendingUserRole === 'admin') {
      notifyAdminLoginNodeRed('failed', req.session.pendingUsername, req);
    }
    return res.status(401).json({ error: 'Invalid code — try again' });
  }
  const username = req.session.pendingUsername || ADMIN_USER;

  if (req.session.pendingUserRole === 'admin') {
    const userId = req.session.pendingUserId;
    // Session-fixation defense: rotate the ID at this final auth→session boundary. The pending*
    // fields are cleared implicitly (regenerate wipes the session); carry only the post-login
    // identity onto the fresh session.
    regenSession(req, {
      authenticated:    true,
      serverGeneration: getServerGeneration(),
      username:         username,
      role:             'admin',
      userId:           userId,
      account_type:     'admin_created',
      permissions:      {},
      enabled_features: {},
    }, () => {
      signalAlert('✅ Successful Login',
        `Admin \`${username}\` dashboard access granted.`, req).catch(() => {});
      notifyAdminLoginNodeRed('success', username, req);
      res.json({ ok: true, redirect: '/admin' });
    });
  } else {
    const userId = req.session.pendingUserId;
    const user   = (await db.prepare('SELECT * FROM users WHERE id=?').get(userId));
    let sessionFields;
    try {
      sessionFields = {
        authenticated:    true,
        serverGeneration: getServerGeneration(),
        username:         username,
        role:             user.role,
        userId:           userId,
        // Business sub-users share this pending-TOTP path too (see /login) — read the real
        // account_type from the row rather than assuming 'public'.
        account_type:     user.account_type || 'public',
        parent_owner_id:  user.parent_owner_id || null,
        permissions:      JSON.parse(decryptText(user.permissions) || '{}'),
        enabled_features: JSON.parse(decryptText(user.enabled_features || '{}') || '{}'),
      };
    } catch (e) {
      // Fail closed — never leave the TOTP-verified request hanging (see the /login guard).
      log('error', 'login/totp: failed to build session fields', { userId, err: e.message });
      return res.status(500).json({ error: 'Login failed — could not read account permissions' });
    }
    regenSession(req, sessionFields, () => {
      notifyAdminLogin('✅ Successful Login\n' +
        `Public user \`${username}\` logged in.`, userId).catch(() => {});
      // Notify public user of their own login
      const xff2 = req.headers['x-forwarded-for'];
      const ip2  = (xff2 ? xff2.split(',')[0].trim() : null) || req.ip || req.socket?.remoteAddress || 'unknown';
      notifyUser(userId,
        `🔐 Account Login\nUser: ${username}\nTime: ${new Date().toLocaleString()}\nIP: ${ip2}\n\nIf this wasn't you, contact your administrator immediately.`,
        { skipEmail: true }
      ).catch(() => {});
      if (user.account_type === 'business_sub' && user.parent_owner_id) {
        notifyUser(user.parent_owner_id,
          `🔐 Team Member Login\nUser: ${username}\nTime: ${new Date().toLocaleString()}\nIP: ${ip2}\n\nIf you don't recognize this, remove the team member from Account & Security.`,
          { skipEmail: true }
        ).catch(() => {});
      } else {
        // Always email the owner about the sign-in (not gated by the email_alerts pref).
        sendLoginNotificationEmail(userId, username, ip2).catch(() => {});
      }
      res.json({ ok: true });
    });
  }
}
app.post('/login/totp',       totpRateLimit, handleTotpVerify);
app.post('/admin/login/totp', totpRateLimit, handleTotpVerify);

};
