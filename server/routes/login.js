// routes/login.js — Prelogin KDF, admin login, TOTP verification, session management.
// All dependencies injected — no imports from server.js scope.
const speakeasy = require('speakeasy');
module.exports = ({ app, db, decryptText, log, makeRateLimit, notifyAdmin,
                    notifyAdminLogin, notifyAdminLoginNodeRed, notifyUser,
                    sendLoginNotificationEmail, signalAlert, stmts,
                    totpRateLimit, verifyUserPassword, ADMIN_USER, TOTP_SECRET,
                    loginRateLimit, session, ensureAuthSalt, AUTH_SCHEME_PREHASH,
                    AUTH_PREHASH_ITER, preloginFakeSeed, sendAuthPage,
                    staffZkLoginFields, crypto, bcrypt, getServerGeneration,
                    regenSession }) => {
// ── Login routes ───────────────────────────────────────────────────────────
// Validate a post-login `next` redirect target: same-origin relative paths ONLY (blocks open
// redirects — no `//host`, `/\host`, or absolute/scheme URLs). Used for the email deep link.
function safeNextPath(next) {
  const s = (next || '').toString();
  if (!s.startsWith('/') || s.startsWith('//') || s.startsWith('/\\')) return null;
  return s.slice(0, 512);
}

// Pre-login KDF parameters: tells the client which scheme + per-user auth_salt to hash with
// BEFORE it submits credentials. Unknown identifiers get a stable decoy salt (HMAC of the
// identifier, seeded from settings so all replicas agree) — the response shape never reveals
// whether an account exists. `migrate:true` (row still bcrypt(plaintext)) tells the client to
// send the plaintext one final time; that successful login upgrades the row in place.
const preloginRateLimit = makeRateLimit(30, 15 * 60 * 1000, 'prelogin');
// Password-check endpoint (re-auth for the Remote Assist key reveal): throttle like a login so a
// hijacked-but-unlocked session can't be used as a fast password-guessing oracle (MEDIUM-3).
const verifySessionPasswordRateLimit = makeRateLimit(10, 15 * 60 * 1000, 'verify-session-pw');
app.post('/api/auth/prelogin', preloginRateLimit, async (req, res) => {
  const identifier = String(req.body?.identifier || req.body?.username || '').trim().slice(0, 200);
  if (!identifier) return res.status(400).json({ error: 'identifier required' });
  const isEmail = identifier.includes('@');
  const user = isEmail
    ? (await stmts.userByEmail.get(identifier))
    : ((await stmts.userByName.get(identifier)) || (await stmts.userByEmail.get(identifier)));
  if (user) {
    const auth_salt = (await ensureAuthSalt(user));
    return res.json({
      scheme: AUTH_SCHEME_PREHASH, auth_salt, iterations: AUTH_PREHASH_ITER,
      ...(user.pw_scheme === AUTH_SCHEME_PREHASH ? {} : { migrate: true }),
    });
  }
  const seed = (await preloginFakeSeed());
  const fake = crypto.createHmac('sha256', seed).update(identifier.toLowerCase()).digest().subarray(0, 16).toString('base64');
  res.json({ scheme: AUTH_SCHEME_PREHASH, auth_salt: fake, iterations: AUTH_PREHASH_ITER });
});

// Re-verify the current session's password — used by the WebUI Remote Assist tab to require
// password confirmation before exposing the SSH private key/command to a public user. Accepts a
// pre-hashed authHash (same PBKDF2 scheme as /login) and checks against the session user's stored
// hash. Returns ok:true for 5 min; client caches and only re-prompts after expiry.
app.post('/api/auth/verify-session-password', verifySessionPasswordRateLimit, async (req, res) => {
  if (!req.session?.authenticated || !req.session.userId)
    return res.status(401).json({ error: 'Not authenticated' });
  const { authHash } = req.body || {};
  if (!authHash || typeof authHash !== 'string')
    return res.status(400).json({ error: 'authHash required' });
  const user = (await db.prepare("SELECT * FROM users WHERE id=?").get(req.session.userId));
  if (!user || !(await verifyUserPassword(user, { authHash })))
    return res.status(403).json({ error: 'Password incorrect' });
  res.json({ ok: true, verifiedAt: Date.now(), expiresIn: 300 });
});

app.get('/login', (req, res) => {
  if (req.session?.authenticated) {
    if (req.session.role === 'admin') return res.redirect('/admin');
    if (req.session.account_type === 'admin_created') return res.redirect('/admin/subusers');
    return res.redirect(safeNextPath(req.query.next) || '/');
  }
  sendAuthPage(res, 'login.html');
});

app.get('/admin/login', (req, res) => {
  if (req.session?.authenticated) {
    if (req.session.role === 'admin') return res.redirect('/admin');
    if (req.session.account_type === 'admin_created') return res.redirect('/admin/subusers');
    return res.redirect('/');
  }
  sendAuthPage(res, 'login.html');
});

app.post('/admin/login', loginRateLimit, async (req, res) => {
  const { username, password, authHash } = req.body;
  const isEmail = username && username.includes('@');
  const user = isEmail
    ? (await stmts.userByEmail.get(username))
    : ((await stmts.userByName.get(username)) || (await stmts.userByEmail.get(username)));
  if (!user || !(await verifyUserPassword(user, { password, authHash }))) {
    (await signalAlert('🔴 Failed Login — Wrong Password',
      `Identifier attempted: \`${username || '(blank)'}\``, req));
    notifyAdminLoginNodeRed('failed', username, req);
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.role !== 'admin') {
    return res.status(403).json({ error: 'This login is for administrator accounts only.' });
  }
  let requiresTotp = true;
  let dbSecretDecrypted = user.totp_secret ? decryptText(user.totp_secret) : null;
  if (dbSecretDecrypted === 'DISABLED' && !user.totp_verified) {
      requiresTotp = false;
  }

  if (requiresTotp) {
    (await signalAlert('🟡 Login — Password Accepted',
      `Admin \`${user.username}\` verified. Waiting for 2FA.`, req));
    // Rotate the session ID at this privilege boundary (session-fixation defense): carry only the
    // pending state onto the fresh session so a pre-planted session ID can't be reused after login.
    return regenSession(req, {
      pendingTotp:     true,
      pendingUsername:  user.username,
      pendingUserRole:  'admin',
      pendingUserId:    user.id,
      pendingAuthAt:   Date.now(),
    }, () => {
      // Hand back the admin's personal ZK key (for E2E "Conversations") so the browser can derive it
      // during 2FA entry, or signal it must generate one. Password is available client-side at this step.
      res.json({ totp_required: true, ...staffZkLoginFields(user) });
    });
  } else {
    (await signalAlert('✅ Successful Login',
      `Admin \`${user.username}\` dashboard access granted.`, req));
    notifyAdminLoginNodeRed('success', user.username, req);
    return regenSession(req, {
      authenticated:    true,
      serverGeneration: getServerGeneration(),
      username:         user.username,
      role:             'admin',
      userId:           user.id,
      account_type:     'admin_created',
      permissions:      {},
      enabled_features: {},
    }, () => {
      res.json({ ok: true, totp_required: false, ...staffZkLoginFields(user) });
    });
  }
});

app.get('/admin/subusers/login', (req, res) => {
  if (req.session?.authenticated) {
    if (req.session.role === 'admin') return res.redirect('/admin');
    if (req.session.account_type === 'admin_created') return res.redirect('/admin/subusers');
    return res.redirect('/');
  }
  sendAuthPage(res, 'login.html');
});

app.post('/admin/subusers/login', loginRateLimit, async (req, res) => {
  const { username, password, authHash } = req.body;
  const isEmail = username && username.includes('@');
  const user = isEmail
    ? (await stmts.userByEmail.get(username))
    : ((await stmts.userByName.get(username)) || (await stmts.userByEmail.get(username)));
  if (!user || !(await verifyUserPassword(user, { password, authHash }))) {
    (await signalAlert('🔴 Failed Login — Wrong Password',
      `Identifier attempted: \`${username || '(blank)'}\``, req));
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  if (user.role === 'admin') {
    return res.status(403).json({ error: 'Admin accounts must sign in at /admin/login' });
  }
  if (user.account_type === 'public') {
    return res.status(403).json({ error: 'Parent accounts must sign in at the parent portal.' });
  }
  // Rotate the session ID at the auth→session privilege boundary (session-fixation defense).
  let sessionFields;
  try {
    sessionFields = {
      authenticated:    true,
      serverGeneration: getServerGeneration(),
      username:         user.username,
      role:             user.role,
      userId:           user.id,
      account_type:     user.account_type || 'admin_created',
      permissions:      JSON.parse(decryptText(user.permissions) || '{}'),
      enabled_features: JSON.parse(decryptText(user.enabled_features || '{}') || '{}'),
      is_support_delegate: !!user.is_support_delegate,
    };
  } catch (e) {
    // Fail closed — a malformed permissions blob must never leave the request hanging.
    log('error', 'admin/subusers/login: failed to build session fields', { userId: user.id, err: e.message });
    return res.status(500).json({ error: 'Login failed — could not read account permissions' });
  }
  regenSession(req, sessionFields, () => {
    signalAlert('✅ Successful Login',
      `Sub-user \`${user.username}\` logged in (role: ${user.role}).`, req).catch(() => {});
    // ZK key for E2E "Conversations" — browser unwraps it now (password in hand) or provisions one.
    res.json({ ok: true, redirect: '/admin/subusers', ...staffZkLoginFields(user) });
  });
});

};
