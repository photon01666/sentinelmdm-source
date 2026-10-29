// routes/passkeys.js — Passkeys / WebAuthn registration and authentication.
const speakeasy = require('speakeasy');
const webauthn  = require('../webauthn');
module.exports = ({ app, ADMIN_USER, QRCode, TOTP_SECRET, actingUserRow, db, decryptText,
                    log, loginRateLimit, makeRateLimit, notifyAdminLogin, path, requireAuth,
                    signalAlert, session, getServerGeneration, regenSession }) => {
// ── Passkeys / WebAuthn ──────────────────────────────────────────────────────
// Usernameless passkey login that REPLACES username+password+OTP (the passkey's user
// verification IS the second factor). For PUBLIC users — whose password is also their ZK
// data-encryption key — the browser derives a stable KEK from the passkey's PRF output and
// stores the re-wrapped ZK private key per credential (`zk_wrapped_priv`); the server only
// ever holds that ciphertext, so the zero-knowledge guarantee is preserved. See webauthn.js.
const webauthn = require('../webauthn');
const waGetCredsForUser = async (uid) => (await db.prepare('SELECT * FROM webauthn_credentials WHERE user_id=? ORDER BY created_at').all(uid));
const waGetCredById     = async (id)  => (await db.prepare('SELECT * FROM webauthn_credentials WHERE id=?').get(id));
// users.email is encrypted at rest — decrypt it for the WebAuthn user.name/displayName
// (else the platform passkey UI would show the ENC:… ciphertext as the account label).
const waRegOptionsFor = async (user) => {
  const existing = (await waGetCredsForUser(user.id)).map(c => c.id);
  return webauthn.regOptions({ ...user, email: decryptText(user.email) }, existing);
};
// Shared credential store for the two enrollment paths (signed-in dashboard + end of
// public registration). zkWrapped is REQUIRED for public accounts by both callers.
async function waInsertCredential(userId, v, response, name, zkWrapped) {
  const cred = v.registrationInfo.credential;     // { id, publicKey, counter, transports }
  (await db.prepare(`INSERT INTO webauthn_credentials
      (id,user_id,public_key,counter,transports,device_type,backed_up,aaguid,name,zk_wrapped_priv,created_at,last_used_at)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
      ON CONFLICT(id) DO UPDATE SET public_key=excluded.public_key, counter=excluded.counter, name=excluded.name`).run(
    cred.id, userId, webauthn.b64u.enc(cred.publicKey), Number(cred.counter) || 0,
    JSON.stringify(cred.transports || response?.response?.transports || []),
    v.registrationInfo.credentialDeviceType || null, v.registrationInfo.credentialBackedUp ? 1 : 0,
    v.registrationInfo.aaguid || null, (name || '').toString().slice(0, 40) || null,
    zkWrapped || null, Date.now(), Date.now()));
}

// 1) Registration options — enroll a passkey (must already be signed in).
app.post('/api/webauthn/register/options', requireAuth, async (req, res) => {
  try {
    const user = (await actingUserRow(req));
    if (!user) return res.status(401).json({ error: 'Not signed in' });
    const opts = (await waRegOptionsFor(user));
    req.session.waRegChallenge = opts.challenge;
    res.json(opts);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 2) Registration verify — store the credential. Public users MUST also send the
//    PRF-wrapped ZK key (else they'd lock themselves out of their own encrypted data).
app.post('/api/webauthn/register/verify', requireAuth, async (req, res) => {
  try {
    const user = (await actingUserRow(req));
    if (!user) return res.status(401).json({ error: 'Not signed in' });
    const expectedChallenge = req.session.waRegChallenge;
    if (!expectedChallenge) return res.status(400).json({ error: 'No registration in progress' });
    const { response, name, zk_wrapped_priv } = req.body || {};
    const v = (await webauthn.verifyReg(response, expectedChallenge));
    req.session.waRegChallenge = null;
    if (!v.verified || !v.registrationInfo) {
      log('warn', 'Passkey registration failed verification', { userId: user.id });
      return res.status(400).json({ error: 'Passkey registration failed verification' });
    }
    if (user.account_type === 'public' && !zk_wrapped_priv) {
      log('warn', 'Passkey registration rejected — public user without PRF-wrapped ZK key', { userId: user.id });
      return res.status(400).json({ error: 'Missing PRF-wrapped ZK key for a private-user passkey' });
    }
    (await waInsertCredential(user.id, v, response, name, zk_wrapped_priv));
    log('info', 'Passkey registered', { userId: user.id, account_type: user.account_type, name: name || null });
    res.json({ ok: true });
  } catch (e) { log('warn', 'Passkey registration error', { error: e.message }); res.status(500).json({ error: e.message }); }
});

// 3) Authentication options — usernameless (discoverable credential); no session required.
// Throttled like a login: an unauthenticated caller could otherwise mint unlimited challenges
// (session-store bloat + cheap prelude to verify brute-force). Shares the login budget.
app.post('/api/webauthn/auth/options', loginRateLimit, async (req, res) => {
  try {
    const opts = (await webauthn.authOptions());
    req.session.waAuthChallenge = opts.challenge;     // saveUninitialized:false → writing this persists the session
    res.json(opts);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 4) Authentication verify — establish the session (passkey UV = 2FA, so no TOTP step) and,
//    for public users, hand back the PRF-wrapped ZK key for the matched credential.
app.post('/api/webauthn/auth/verify', loginRateLimit, async (req, res) => {
  try {
    const expectedChallenge = req.session.waAuthChallenge;
    if (!expectedChallenge) return res.status(400).json({ error: 'No login in progress' });
    const { response } = req.body || {};
    const credRow = response?.id ? (await waGetCredById(response.id)) : null;
    // Generic failure for every pre-verification outcome (unknown credential, bad assertion,
    // missing account) — a distinct message here lets an unauthenticated caller probe which
    // credential IDs exist (MEDIUM-1).
    if (!credRow) { (await signalAlert('🔴 Failed Login — Passkey', 'Unknown credential presented.', req)); return res.status(401).json({ error: 'Passkey verification failed' }); }
    const v = (await webauthn.verifyAuth(response, expectedChallenge, credRow));
    req.session.waAuthChallenge = null;
    if (!v.verified) { (await signalAlert('🔴 Failed Login — Passkey', 'Assertion failed verification.', req)); return res.status(401).json({ error: 'Passkey verification failed' }); }
    (await db.prepare('UPDATE webauthn_credentials SET counter=?, last_used_at=? WHERE id=?').run(v.authenticationInfo.newCounter, Date.now(), credRow.id));
    const user = (await db.prepare('SELECT * FROM users WHERE id=?').get(credRow.user_id));
    if (!user) return res.status(401).json({ error: 'Passkey verification failed' });
    // Mirror the password login's registration-status gate. A passkey can be enrolled at
    // sign-up before the flow finishes, and a later-rejected account must not keep a working passkey.
    // (Account-state detail is only revealed AFTER a valid assertion — the credential holder has
    // already proven possession, so this is not an enumeration oracle.)
    const statusErr = {
      pending_email:    'Please verify your email from the registration page first.',
      pending_totp:     'Please complete 2FA setup from the registration page first.',
      rejected:         'Your account registration was not approved. Contact the administrator.',
    }[user.status];
    if (statusErr) {
      (await notifyAdminLogin('🔴 Failed Login — Passkey\n' +
        `\`${user.username}\` blocked (status: ${user.status}).`, user.id));
      return res.status(403).json({ error: statusErr });
    }
    // Finalize session — mirror handleTotpVerify (admin keeps userId=null).
    // Session-fixation defense: rotate the session ID at this auth→session boundary, carrying
    // only the post-login identity onto the fresh session.
    const isStaff = user.role === 'admin';
    let sessionFields;
    try {
      sessionFields = {
        authenticated: true,
        serverGeneration: getServerGeneration(),
        username: user.username,
        role:     user.role,
        ...(isStaff
          ? { userId: null, account_type: 'admin_created', permissions: {}, enabled_features: {} }
          : {
              userId:        user.id,
              account_type:  user.account_type,
              parent_owner_id: user.parent_owner_id || null,
              permissions:      JSON.parse(decryptText(user.permissions) || '{}'),
              enabled_features: JSON.parse(decryptText(user.enabled_features || '{}') || '{}'),
              is_support_delegate: !!user.is_support_delegate,
            }),
      };
    } catch (e) {
      // Fail closed — a malformed permissions blob must never leave the request hanging.
      log('error', 'webauthn auth/verify: failed to build session fields', { userId: user.id, err: e.message });
      return res.status(500).json({ error: 'Login failed — could not read account permissions' });
    }
    regenSession(req, sessionFields, () => {
      (notifyAdminLogin('✅ Successful Login (passkey)\n' +
        `\`${user.username}\` (${user.role}) signed in with a passkey.`, user.id)).catch(() => {});
      const redirect = isStaff ? '/admin' : (user.account_type === 'admin_created' ? '/admin/subusers' : '/');
      res.json({ ok: true, redirect, account_type: user.account_type,
                 // Hand back the matched credential's PRF-wrapped ZK key for ANYONE who has one — public
                 // users (data key) AND staff who've linked this passkey for E2E Conversations. The client
                 // unwraps it via PRF into sessionStorage; staff without a wrap just fall back to password.
                 zk_wrapped_priv: credRow.zk_wrapped_priv || null });
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// 5) List / 6) delete the signed-in user's passkeys.
app.get('/api/webauthn/credentials', requireAuth, async (req, res) => {
  try {
    const user = (await actingUserRow(req));
    if (!user) return res.status(401).json({ error: 'Not signed in' });
    const creds = (await waGetCredsForUser(user.id));
    res.json({ credentials: creds.map(c => ({ id: c.id, name: c.name, device_type: c.device_type, backed_up: !!c.backed_up, zk_linked: !!c.zk_wrapped_priv, created_at: c.created_at, last_used_at: c.last_used_at })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/webauthn/credentials/:id', requireAuth, async (req, res) => {
  try {
    const user = (await actingUserRow(req));
    if (!user) return res.status(401).json({ error: 'Not signed in' });
    (await db.prepare('DELETE FROM webauthn_credentials WHERE id=? AND user_id=?').run(req.params.id, user.id));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
// 7) Bind (or re-bind) the caller's personal ZK key to an EXISTING passkey — stores the PRF-wrapped
//    key on that credential so future passkey logins unlock it (staff E2E Conversations, or recovery).
//    The wrap is opaque ciphertext the server can't read; ownership-scoped so a session can only set
//    it on its OWN credential (a bogus wrap would only break that user's own future passkey unlock).
app.post('/api/webauthn/credentials/:id/zk-bind', requireAuth, async (req, res) => {
  try {
    const user = (await actingUserRow(req));
    if (!user) return res.status(401).json({ error: 'Not signed in' });
    const wrap = req.body?.zk_wrapped_priv;
    if (typeof wrap !== 'string' || !wrap) return res.status(400).json({ error: 'zk_wrapped_priv required' });
    const r = (await db.prepare('UPDATE webauthn_credentials SET zk_wrapped_priv=? WHERE id=? AND user_id=?').run(wrap, req.params.id, user.id));
    if (!r.changes) return res.status(404).json({ error: 'Passkey not found' });
    log('info', 'Passkey bound to ZK key for E2E', { userId: user.id, credId: req.params.id });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Setup page — admin only; exposes the TOTP secret
app.get('/setup-2fa', async (req, res) => {
  if (!req.session?.authenticated) return res.redirect('/admin/login');
  if (req.session.role !== 'admin') return res.status(403).send('Admin access required');
  const otpauthUrl = speakeasy.otpauthURL({
    secret: TOTP_SECRET,
    label: encodeURIComponent('FamilyMon:' + (req.session.username || ADMIN_USER)),
    issuer: 'FamilyMon',
    encoding: 'base32',
  });
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl);
  res.send(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FamilyMon — Setup 2FA</title>
<link rel="stylesheet" href="/vendor/bootstrap/5.3.2/css/bootstrap.min.css">
</head><body class="bg-light">
<div class="container" style="max-width:420px;padding-top:60px">
  <div class="card shadow p-4 text-center">
    <h5 class="fw-bold mb-1">Two-Factor Authentication Setup</h5>
    <p class="text-muted small mb-3">Scan this QR code in <strong>Google Authenticator</strong>, <strong>Authy</strong>, or any TOTP app.</p>
    <img src="${qrDataUrl}" class="img-fluid mx-auto d-block mb-3" style="max-width:220px">
    <p class="text-muted small mb-1">Or enter the key manually:</p>
    <code class="d-block bg-light border rounded p-2 mb-3 user-select-all" style="word-break:break-all;font-size:.8rem">${TOTP_SECRET}</code>
    <p class="text-warning small"><strong>⚠ Set <code>TOTP_SECRET=${TOTP_SECRET}</code> in your Portainer stack</strong> so this secret persists across container restarts.</p>
    <a href="/login" class="btn btn-primary mt-2">Back to Login</a>
  </div>
</div></body></html>`);
});

app.post('/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// Login page assets — must be public, served before the auth wall.
// __dirname here is server/routes/, so the public dir is one level up — NOT
// path.join(__dirname, 'public', ...), which resolved to the nonexistent
// server/routes/public/ and silently 404'd (found live 2026-08-06: top-left
// logo missing from every dashboard/login page).
app.get('/logo.png', (_req, res) => res.sendFile(path.join(__dirname, '..', 'public', 'logo.png')));


// The trust anchor is the same browser session that just proved email ownership + TOTP
// (`pendingRegistration.passkeyEligible`, set only by /api/register/complete). The account
// is already active at this point (registration activates immediately, no admin approval
// step) — this just adds a passkey as an additional sign-in method before the user leaves
// the registration flow.
// Own rate-limit bucket: the ceremony is challenge+session-bound (nothing brute-forceable
// like a 6-digit code), and sharing the tight 5/15min 'totp' bucket would let one cancelled
// passkey dialog or a mistyped code earlier in the flow 429-brick the whole registration.
const regPasskeyRateLimit = makeRateLimit(10, 15 * 60 * 1000, 'regpasskey');
app.post('/api/register/passkey/options', regPasskeyRateLimit, async (req, res) => {
  try {
    const pr = req.session?.pendingRegistration;
    if (!pr?.passkeyEligible) return res.status(400).json({ error: 'No completed registration in this session' });
    const user = (await db.prepare('SELECT * FROM users WHERE id=?').get(pr.userId));
    if (!user || user.status !== 'active') return res.status(400).json({ error: 'Invalid registration state' });
    const opts = (await waRegOptionsFor(user));
    req.session.waRegChallenge = opts.challenge;
    res.json(opts);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/register/passkey/verify', regPasskeyRateLimit, async (req, res) => {
  try {
    const pr = req.session?.pendingRegistration;
    if (!pr?.passkeyEligible) return res.status(400).json({ error: 'No completed registration in this session' });
    const user = (await db.prepare('SELECT * FROM users WHERE id=?').get(pr.userId));
    if (!user || user.status !== 'active') return res.status(400).json({ error: 'Invalid registration state' });
    const expectedChallenge = req.session.waRegChallenge;
    if (!expectedChallenge) return res.status(400).json({ error: 'No registration in progress' });
    const { response, name, zk_wrapped_priv } = req.body || {};
    const v = (await webauthn.verifyReg(response, expectedChallenge));
    req.session.waRegChallenge = null;
    if (!v.verified || !v.registrationInfo) {
      log('warn', 'Sign-up passkey failed verification', { userId: user.id });
      return res.status(400).json({ error: 'Passkey registration failed verification' });
    }
    // Registration accounts are always public → the PRF-wrapped ZK key is mandatory
    // (without it the passkey couldn't unlock their end-to-end-encrypted data).
    if (!zk_wrapped_priv) {
      log('warn', 'Sign-up passkey rejected — missing PRF-wrapped ZK key', { userId: user.id });
      return res.status(400).json({ error: 'Missing PRF-wrapped ZK key for a private-user passkey' });
    }
    (await waInsertCredential(user.id, v, response, name, zk_wrapped_priv));
    req.session.pendingRegistration = null;   // one sign-up passkey; more can be added in the dashboard
    log('info', 'Passkey registered at sign-up', { userId: user.id, name: name || null });
    res.json({ ok: true });
  } catch (e) { log('warn', 'Sign-up passkey error', { error: e.message }); res.status(500).json({ error: e.message }); }
});

};
