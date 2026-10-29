// routes/account-security.js — Auth params, secure-account, change-email, change-password, 2FA setup/enable/disable.
// Extracted from server.js L9807-10151. 8 routes + rate limiters + ZK helper fns.
module.exports = ({ app, ADMIN_USER, AUTH_PREHASH_ITER, AUTH_SCHEME_PREHASH, EMAIL_CODE_TTL_MS, QRCode,
  TOTP_SECRET, actingUserRow, bcrypt, db, decryptText, encryptText, ensureAuthSalt, esc, genEmailCode,
  log, looksLikeAuthHash, looksLikeAuthSalt, makeRateLimit, normIdent, notifyAdminForUser, notifyAdminLogin,
  requireAuth, revokeUserSessions, sendEmail, sendEmailVerifyCode, sha256hex, speakeasy, totpRateLimit,
  verifyUserPassword, wipeUserAccount }) => {

const changeEmailRateLimit  = makeRateLimit(5, 15 * 60 * 1000, 'changeemail');
const changePasswordRateLimit = makeRateLimit(5, 15 * 60 * 1000, 'changepw');

function looksLikeZkWrapped(s) {
  if (typeof s !== 'string' || s.length < 40 || s.length > 8192 || !/^[A-Za-z0-9+/]+=*$/.test(s)) return false;
  try { const n = Buffer.from(s, 'base64').length; return n >= 28 && n <= 4096; } catch { return false; }
}
function looksLikeZkSalt(s) {
  if (typeof s !== 'string' || s.length > 128 || !/^[A-Za-z0-9+/]+=*$/.test(s)) return false;
  try { const n = Buffer.from(s, 'base64').length; return n >= 8 && n <= 64; } catch { return false; }
}

// KDF parameters for the SIGNED-IN account — lets app.js compute the auth prehash for its
// re-auth prompts (secure account / change email / 2FA on-off / user create) instead of
// re-sending the plaintext. A pre-migration row answers scheme:'plain' and the client falls
// back to the plaintext form, which the server-side legacy path still verifies.
app.get('/api/account/auth-params', requireAuth, async (req, res) => {
  const user = (await actingUserRow(req));
  if (!user) return res.status(404).json({ error: 'Account not found' });
  if (user.pw_scheme !== AUTH_SCHEME_PREHASH) return res.json({ scheme: 'plain' });
  res.json({ scheme: AUTH_SCHEME_PREHASH, auth_salt: (await ensureAuthSalt(user)), iterations: AUTH_PREHASH_ITER });
});

app.post('/api/account/secure', requireAuth, async (req, res) => {
  if (req.session?.account_type !== 'public' || !req.session.userId)
    return res.status(403).json({ error: 'Public account required' });
  const userId = req.session.userId;
  const user = (await db.prepare('SELECT id, username, email, password_hash, pw_scheme, auth_salt, totp_secret, totp_verified FROM users WHERE id=?').get(userId));
  if (!user) return res.status(404).json({ error: 'Account not found' });

  const { password, authHash, code } = req.body || {};
  if (!(await verifyUserPassword(user, { password, authHash }))) {
    (await notifyAdminLogin('🔴 Secure-Account — Wrong Password\n' +
      `Failed re-auth on "Secure my account" for user #${userId}.`, userId));
    return res.status(401).json({ error: 'Incorrect password' });
  }
  if (user.totp_verified) {
    const totpSecret = decryptText(user.totp_secret);
    const totpOk = !!totpSecret && speakeasy.totp.verify({
      secret: totpSecret, encoding: 'base32',
      token: String(code || '').replace(/\s/g, ''), window: 1,
    });
    if (!totpOk) return res.status(401).json({ error: 'Invalid 2FA code' });
  }

  const email = decryptText(user.email) || '';

  let r;
  try {
    r = (await wipeUserAccount(userId));
  } catch (e) {
    log('error', 'Secure-account wipe threw', { userId, err: e.message });
    return res.status(500).json({ error: 'Could not secure your account — please try again or contact support.' });
  }
  if (!r.ok) return res.status(r.code || 500).json({ error: r.error });
  const sessionsRevoked = (await revokeUserSessions(userId));

  log('warn', 'Account self-secured (ZK re-key)', { userId, devicesReleased: r.devicesReleased, sessionsRevoked });
  notifyAdminForUser(`🛡️ Account Self-Secured (ZK Re-Key)\nUser "${r.username}" (#${userId}) ran "Secure my account". ${r.devicesReleased} device(s) released to email lineage "${r.lineageEmail || 'n/a'}"; ${sessionsRevoked} session(s) revoked. Recovery = re-register the SAME email + re-enroll from the physical device.`, userId);

  req.session.destroy(() => {
    res.json({ ok: true, reRegisterEmail: email, devicesReleased: r.devicesReleased });
  });
});

// ── Self-service email change (public accounts) ──────────────────────────────
app.post('/api/account/change-email/start', changeEmailRateLimit, requireAuth, async (req, res) => {
  if (req.session?.account_type !== 'public' || !req.session.userId)
    return res.status(403).json({ error: 'Public account required' });
  const userId = req.session.userId;
  const user = (await db.prepare('SELECT id, password_hash, pw_scheme, auth_salt, totp_secret, totp_verified FROM users WHERE id=?').get(userId));
  if (!user) return res.status(404).json({ error: 'Account not found' });

  const { password, authHash, code: totpCode, newEmail } = req.body || {};
  if (!(await verifyUserPassword(user, { password, authHash }))) {
    (await notifyAdminLogin('🔴 Change-Email — Wrong Password\n' +
      `Failed re-auth on email change for user #${userId}.`, userId));
    return res.status(401).json({ error: 'Incorrect password' });
  }
  if (user.totp_verified) {
    const totpSecret = decryptText(user.totp_secret);
    const totpOk = !!totpSecret && speakeasy.totp.verify({
      secret: totpSecret, encoding: 'base32',
      token: String(totpCode || '').replace(/\s/g, ''), window: 1,
    });
    if (!totpOk) return res.status(401).json({ error: 'Invalid 2FA code' });
  }

  const email = String(newEmail || '').trim().toLowerCase();
  if (!email || !email.includes('@') || email.length > 200)
    return res.status(400).json({ error: 'A valid new email is required' });

  const otpCode = genEmailCode();
  req.session.pendingEmailChange = { userId, newEmail: email, hash: sha256hex(otpCode), expires: Date.now() + EMAIL_CODE_TTL_MS };
  sendEmailVerifyCode(email, otpCode).catch(() => {});
  log('info', 'Email change requested — code sent to new address', { userId });
  res.json({ ok: true });
});

app.post('/api/account/change-email/verify', changeEmailRateLimit, requireAuth, async (req, res) => {
  if (req.session?.account_type !== 'public' || !req.session.userId)
    return res.status(403).json({ error: 'Public account required' });
  const userId = req.session.userId;
  const pending = req.session.pendingEmailChange;
  if (!pending || pending.userId !== userId)
    return res.status(400).json({ error: 'No email change in progress — start again.' });
  if (Date.now() > pending.expires) {
    req.session.pendingEmailChange = null;
    return res.status(400).json({ error: 'Code expired — start again.' });
  }
  const code = String(req.body?.code || '').replace(/\D/g, '');
  if (sha256hex(code) !== pending.hash)
    return res.status(401).json({ error: 'Incorrect code — check the new inbox.' });

  const user = (await db.prepare('SELECT id, username, email FROM users WHERE id=?').get(userId));
  if (!user) return res.status(404).json({ error: 'Account not found' });
  const oldEmail = decryptText(user.email) || '';
  const newEmail = pending.newEmail;

  (await db.transaction(async () => {
    (await db.prepare('UPDATE users SET email=? WHERE id=?').run(newEmail, userId));
    (await db.prepare('UPDATE devices SET locked_identity_email=? WHERE owner_user_id=?')
      .run(encryptText(normIdent(newEmail)), userId));
  })());

  req.session.pendingEmailChange = null;
  log('warn', 'Account email changed', { userId, oldEmail, newEmail });
  notifyAdminForUser(`📧 Account Email Changed\nUser "${user.username}" (#${userId}) changed their account email from ${oldEmail || '(none)'} to ${newEmail}.`, userId);
  if (oldEmail) {
    sendEmail(oldEmail, 'Your SentinelMDM account email was changed',
      `<p>Your SentinelMDM account email was changed to <strong>${esc(newEmail)}</strong>. If this wasn't you, contact support immediately.</p>`
    ).catch(() => {});
  }
  res.json({ ok: true, email: newEmail });
});

// ── Self-service password change (all account types) ─────────────────────────
app.post('/api/account/change-password', changePasswordRateLimit, requireAuth, async (req, res) => {
  const user = (await actingUserRow(req));
  if (!user) return res.status(404).json({ error: 'Account not found' });

  const { password, authHash, code, new_auth_hash, new_auth_salt,
          zk_encrypted_priv_key, zk_salt } = req.body || {};

  if (!(await verifyUserPassword(user, { password, authHash }))) {
    (await notifyAdminLogin('🔴 Change-Password — Wrong Password\n' +
      `Failed re-auth on password change for user #${user.id}.`, user.id));
    return res.status(401).json({ error: 'Current password is incorrect' });
  }
  if (user.totp_verified) {
    const totpSecret = decryptText(user.totp_secret);
    const totpOk = !!totpSecret && speakeasy.totp.verify({
      secret: totpSecret, encoding: 'base32',
      token: String(code || '').replace(/\s/g, ''), window: 1,
    });
    if (!totpOk) return res.status(401).json({ error: 'Invalid 2FA code' });
  }

  if (!looksLikeAuthHash(new_auth_hash) || !looksLikeAuthSalt(new_auth_salt))
    return res.status(400).json({ error: 'Invalid new password data — please reload and try again.' });

  const hasZk = !!(user.zk_encrypted_priv_key && user.zk_salt);
  let newZk = null;
  if (hasZk) {
    if (!looksLikeZkWrapped(zk_encrypted_priv_key) || !looksLikeZkSalt(zk_salt))
      return res.status(400).json({ error: 'Please sign out and back in, then change your password again.' });
    newZk = { zk_encrypted_priv_key, zk_salt };
  }

  const newHash = bcrypt.hashSync(new_auth_hash, 10);
  (await db.transaction(async () => {
    if (newZk) {
      (await db.prepare('UPDATE users SET password_hash=?, pw_scheme=?, auth_salt=?, zk_encrypted_priv_key=?, zk_salt=? WHERE id=?')
        .run(newHash, AUTH_SCHEME_PREHASH, new_auth_salt, newZk.zk_encrypted_priv_key, newZk.zk_salt, user.id));
    } else {
      (await db.prepare('UPDATE users SET password_hash=?, pw_scheme=?, auth_salt=? WHERE id=?')
        .run(newHash, AUTH_SCHEME_PREHASH, new_auth_salt, user.id));
    }
  })());

  const sessionsRevoked = (await revokeUserSessions(user.id, req.sessionID));

  log('warn', 'Account password changed', { userId: user.id, rewrappedZk: !!newZk, sessionsRevoked });
  notifyAdminForUser(`🔑 Account Password Changed\nUser "${user.username}" (#${user.id}) changed their password.${newZk ? ' ZK key re-wrapped.' : ''} ${sessionsRevoked} other session(s) revoked.`, user.id);
  try {
    const email = decryptText(user.email) || '';
    if (email && email.includes('@')) {
      sendEmail(email, 'Your SentinelMDM password was changed',
        `<p>Your SentinelMDM account password was just changed. If this wasn't you, contact support immediately and secure your account.</p>`
      ).catch(() => {});
    }
  } catch (_) {}

  res.json({ ok: true, sessionsRevoked });
});

// ── Self-service 2FA enable/disable (public accounts) ────────────────────────
app.post('/api/account/totp/setup', totpRateLimit, requireAuth, async (req, res) => {
  if (!['public', 'admin', 'admin_created', 'business_sub'].includes(req.session?.account_type) || !req.session.userId)
    return res.status(403).json({ error: 'Public or admin account required' });
  const userId = req.session.userId;
  const user = (await db.prepare('SELECT id, username, password_hash, pw_scheme, auth_salt, totp_verified FROM users WHERE id=?').get(userId));
  if (!user) return res.status(404).json({ error: 'Account not found' });
  if (user.totp_verified) return res.status(400).json({ error: '2FA is already enabled on this account' });

  const { password, authHash } = req.body || {};
  if (!(await verifyUserPassword(user, { password, authHash }))) {
    (await notifyAdminLogin('🔴 2FA Setup — Wrong Password\n' +
      `Failed re-auth on 2FA setup for user #${userId}.`, userId));
    return res.status(401).json({ error: 'Incorrect password' });
  }

  const totpSecret = speakeasy.generateSecret({ length: 20 }).base32;
  (await db.prepare('UPDATE users SET totp_secret=? WHERE id=?').run(encryptText(totpSecret), userId));

  const otpauthUrl = speakeasy.otpauthURL({
    secret: totpSecret, label: encodeURIComponent(`SentinelMDM:${user.username}`), issuer: 'SentinelMDM', encoding: 'base32',
  });
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl, { width: 200, margin: 1 });
  log('info', '2FA setup started', { userId });
  res.json({ ok: true, otpauth: otpauthUrl, qr_data_url: qrDataUrl });
});

app.post('/api/account/totp/enable', totpRateLimit, requireAuth, async (req, res) => {
  if (!['public', 'admin', 'admin_created', 'business_sub'].includes(req.session?.account_type) || !req.session.userId)
    return res.status(403).json({ error: 'Public or admin account required' });
  const userId = req.session.userId;
  const user = (await db.prepare('SELECT id, email, totp_secret, totp_verified FROM users WHERE id=?').get(userId));
  if (!user) return res.status(404).json({ error: 'Account not found' });
  if (user.totp_verified) return res.status(400).json({ error: '2FA is already enabled on this account' });
  if (!user.totp_secret) return res.status(400).json({ error: 'Start 2FA setup first' });

  const totpSecret = decryptText(user.totp_secret);
  const valid = !!totpSecret && speakeasy.totp.verify({
    secret: totpSecret, encoding: 'base32',
    token: String(req.body?.code || '').replace(/\s/g, ''), window: 1,
  });
  if (!valid) return res.status(401).json({ error: 'Invalid code — try again' });

  (await db.prepare('UPDATE users SET totp_verified=1 WHERE id=?').run(userId));
  log('info', 'Public user enabled 2FA', { userId });
  notifyAdminForUser(`🔐 2FA Enabled\nUser #${userId} enabled two-factor authentication on their account.`, userId);
  const email = decryptText(user.email) || '';
  if (email) {
    sendEmail(email, 'Two-factor authentication enabled',
      `<p>Two-factor authentication was just turned <strong>on</strong> for your SentinelMDM account. If this wasn't you, contact support immediately.</p>`
    ).catch(() => {});
  }
  res.json({ ok: true });
});

app.post('/api/account/totp/disable', totpRateLimit, requireAuth, async (req, res) => {
  if (!['public', 'admin', 'admin_created', 'business_sub'].includes(req.session?.account_type) || !req.session.userId)
    return res.status(403).json({ error: 'Public or admin account required' });
  const userId = req.session.userId;
  const user = (await db.prepare('SELECT id, email, password_hash, pw_scheme, auth_salt, totp_secret, totp_verified FROM users WHERE id=?').get(userId));
  if (!user) return res.status(404).json({ error: 'Account not found' });
  const isRootAdmin = req.session.username === ADMIN_USER;
  if (!user.totp_verified && !isRootAdmin) return res.status(400).json({ error: '2FA is not enabled on this account' });

  const { password, authHash, code } = req.body || {};
  if (!(await verifyUserPassword(user, { password, authHash }))) {
    (await notifyAdminLogin('🔴 2FA Disable — Wrong Password\n' +
      `Failed re-auth on 2FA disable for user #${userId}.`, userId));
    return res.status(401).json({ error: 'Incorrect password' });
  }
  let totpSecret = decryptText(user.totp_secret);
  if (!user.totp_verified && isRootAdmin && !totpSecret) {
    totpSecret = TOTP_SECRET;
  }
  const valid = !!totpSecret && speakeasy.totp.verify({
    secret: totpSecret, encoding: 'base32',
    token: String(code || '').replace(/\s/g, ''), window: 1,
  });
  if (!valid) return res.status(401).json({ error: 'Invalid 2FA code' });

  if (isRootAdmin && !user.totp_verified) {
    (await db.prepare("UPDATE users SET totp_secret=?, totp_verified=0 WHERE id=?").run(encryptText('DISABLED'), userId));
  } else {
    (await db.prepare('UPDATE users SET totp_verified=0 WHERE id=?').run(userId));
  }
  log('warn', 'Public user disabled 2FA', { userId });
  notifyAdminForUser(`🔓 2FA Disabled\nUser #${userId} disabled two-factor authentication on their account.`, userId);
  const email = decryptText(user.email) || '';
  if (email) {
    sendEmail(email, 'Two-factor authentication disabled',
      `<p>Two-factor authentication was just turned <strong>off</strong> for your SentinelMDM account. If this wasn't you, contact support immediately.</p>`
    ).catch(() => {});
  }
  res.json({ ok: true });
});

};
