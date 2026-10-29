// routes/register.js — Public registration (no auth required).
// Creates new user accounts, handles email verification, TOTP setup, demo device seeding.
const speakeasy = require('speakeasy');
module.exports = ({ app, AUTH_SCHEME_PREHASH, EMAIL_CODE_TTL_MS, PUBLIC_USER_DEFAULT_FEATURES,
                    QRCode, bcrypt, computeAuthPrehash, createDemoDeviceForUser, crypto,
                    db, decryptText, encryptText, genEmailCode, genRef, hwidHmac, log,
                    looksLikeAuthHash, looksLikeAuthSalt, makeChatRateLimit, makeRateLimit,
                    newAuthSalt, notifyAdminForUser, notifyPush, recordPolicyAcceptances,
                    recordTosAcceptance, sendApprovalEmail, sendAuthPage, sendEmailVerifyCode,
                    sha256hex, shopStmts, stmts, totpRateLimit,
                    contactRateLimit, guestChatRateLimit, analyticsRateLimit,
                    guestReadRateLimit, botLogRateLimit }) => {
// ── Public registration routes (no auth required) ──────────────────────────
const registrationRateLimit = makeRateLimit(5,  60 * 60 * 1000, 'register');

app.get('/register', (req, res) => {
  if (req.session?.authenticated) {
    if (req.session.role === 'admin') return res.redirect('/admin');
    if (req.session.account_type === 'admin_created') return res.redirect('/admin/subusers');
    return res.redirect('/');
  }
  sendAuthPage(res, 'register.html');
});

// Step 1 — submit registration form (creates account in pending_totp state)
app.post('/api/register', registrationRateLimit, async (req, res) => {
  // Read LAZILY: a by-value ctx capture freezes this at the require() site,
  // before tryAutoUnlock() runs, so this used to 503 forever while /health said
  // 200 (known-behavior-losses #5). state.js exposes a live accessor.
  if (!require('../state').serverUnlocked) return res.status(503).json({ error: 'Server is starting up — please try again in a moment' });
  let { username } = req.body;
  const { email, password, auth_hash, auth_salt, zk_public_key, zk_encrypted_priv_key, zk_salt, tos } = req.body;

  // Preferred path: the browser sends a PBKDF2 prehash (auth_hash + its auth_salt) instead of the
  // plaintext password — the register page enforces the length/strength policy client-side, since
  // the server never sees the plaintext. The plaintext branch remains for older cached pages.
  const usingPrehash = looksLikeAuthHash(auth_hash) && looksLikeAuthSalt(auth_salt);
  if (!email || (!password && !usingPrehash))
    return res.status(400).json({ error: 'Email and password are required' });
  if (!email.includes('@') || email.length > 200)
    return res.status(400).json({ error: 'Invalid email address' });
  if (!usingPrehash && password.length < 10)
    return res.status(400).json({ error: 'Password must be at least 10 characters' });

  if (username) {
    // Explicit/legacy username path — keep the original validation.
    if (username.length < 3 || username.length > 32)
      return res.status(400).json({ error: 'Username must be 3–32 characters' });
    if (!/^[a-z0-9_.\-]+$/i.test(username))
      return res.status(400).json({ error: 'Username may only contain letters, digits, underscore, dot, or hyphen' });
    if ((await stmts.userByName.get(username)))
      return res.status(409).json({ error: 'Username already taken — choose a different one' });
  } else {
    // Email-only registration: derive a unique internal username from the email.
    // The email is the user-facing identity (devices are locked to it, and it is
    // intentionally reusable for re-link-after-wipe); username is now just an
    // internal handle for the session/admin display. Emails are NOT unique, so a
    // random suffix guarantees the derived username is.
    let base = (email.split('@')[0] || 'user').toLowerCase().replace(/[^a-z0-9_.\-]/g, '');
    if (base.length < 3) base = `${base}user`;
    base = base.slice(0, 28);                       // leave room for a uniqueness suffix
    username = base;
    while ((await stmts.userByName.get(username)))
      username = `${base}${crypto.randomBytes(2).toString('hex')}`.slice(0, 32);
  }

  // Store bcrypt over the client prehash; a plaintext submission (older cached page) is converted
  // to the same at-rest form here so every new row is scheme-uniform.
  const authSalt    = usingPrehash ? auth_salt : newAuthSalt();
  const hash        = bcrypt.hashSync(usingPrehash ? auth_hash : (await computeAuthPrehash(password, authSalt)), 10);
  const totpSecret  = speakeasy.generateSecret({ length: 20 }).base32;

  // Generate unique enrollment token (admin uses this in ADB setup to auto-link the device)
  // SECURITY (2026-10-13): 128-bit (was 32-bit `randomBytes(4)` = 8 hex chars). This token is
  // matched in the device handshake to pre-associate an enrollment with the account, and it is
  // exposed pre-auth via /api/enrollment/get-token — 2^32 is brute-forceable from a small botnet,
  // so it must be unguessable. 16 bytes = 32 hex chars.
  const genTok = () => crypto.randomBytes(16).toString('hex').toUpperCase();
  let enrollToken;
  do { enrollToken = genTok(); } while ((await db.prepare("SELECT id FROM users WHERE enrollment_token=?").get(enrollToken)));

  const { id } = (await db.prepare(`
    INSERT INTO users
      (username,password_hash,role,permissions,created_at,status,account_type,email,
       totp_secret,totp_verified,enabled_features,zk_public_key,zk_encrypted_priv_key,zk_salt,enrollment_token,
       trial_enabled,pw_scheme,auth_salt)
    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?) RETURNING id
  `).get(
    username, hash, 'user', encryptText('{}'), Date.now(),
    'pending_email', 'public', email,
    encryptText(totpSecret), 0,
    encryptText('{}'),
    zk_public_key        || null,
    zk_encrypted_priv_key || null,
    zk_salt              || null,
    enrollToken,
    AUTH_SCHEME_PREHASH, authSalt
  ));

  // Clean up ABANDONED incomplete registration stubs for this same email (prior attempts that never
  // finished email/2FA verification). Emails are non-unique, so without this, restarting registration
  // (common in the "Secure my account" → re-register flow) leaves stale pending_email/pending_totp
  // siblings that make email login ambiguous. NEVER touches active/pending_approval/admin rows, and
  // excludes the row just created. Best-effort.
  try { (await db.prepare("DELETE FROM users WHERE email=? AND account_type='public' AND status IN ('pending_email','pending_totp') AND id<>?").run(email, id)); } catch {}

  // Link any Stripe subscription started with this email to the new account — both never-linked
  // (checkout-before-account) AND orphaned by a prior account wipe (its user_id points at a
  // now-deleted account). The `NOT IN (live users)` clause reclaims a post-wipe orphan WITHOUT ever
  // stealing a subscription bound to a different LIVE account. So "Secure my account" → re-register
  // with the same email picks the subscription back up where it left off.
  try { (await db.prepare('UPDATE subscriptions SET user_id=? WHERE LOWER(email)=? AND (user_id IS NULL OR user_id NOT IN (SELECT id FROM users))').run(id, email.toLowerCase())); } catch {}

  // Re-registration continuity: if this email previously had an account that was wiped (via "Secure
  // my account" or the trial auto-wipe), resume its trial countdown + admin comp plan from the
  // account_continuity stash so the new same-email account picks up where it left off — the trial
  // does NOT reset to a fresh 30 days (also closes the trial-reset abuse hole), and any comp grant
  // carries over. Best-effort; never fails registration. (Stripe sub is handled by the re-link above.)
  try {
    const cont = (await db.prepare('SELECT trial_started_at, comp_plan, comp_expires_at FROM account_continuity WHERE email_hmac=?').get(hwidHmac(email)));
    if (cont) {
      const sets = [], vals = [];
      if (cont.trial_started_at) { sets.push('trial_started_at=?'); vals.push(cont.trial_started_at); }
      // Restore comp only if it hasn't lapsed (open-ended comp_expires_at=NULL is still active).
      if (cont.comp_plan && (cont.comp_expires_at == null || Number(cont.comp_expires_at) > Date.now())) {
        sets.push('comp_plan=?', 'comp_expires_at=?', 'comp_granted_by=?', 'comp_granted_at=?');
        vals.push(cont.comp_plan, cont.comp_expires_at ?? null, 'continuity:re-register', Date.now());
      }
      if (sets.length) { vals.push(id); (await db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id=?`).run(...vals)); }
    }
  } catch (e) { log('warn', 'account continuity restore failed', { err: e.message }); }

  // Clickwrap + chargeback-defense evidence: one append-only row per policy the register page
  // displayed, tied to the real account (same-origin). Append-only; survives the 30-day purge.
  // Text/version/hash come from POLICY_TEXTS server-side — the client only names the keys.
  if (Array.isArray(req.body.acceptances) && req.body.acceptances.length) {
    (await recordPolicyAcceptances(req, req.body.acceptances, { userId: id, email }));
  } else if (tos && tos.accepted) {
    // Legacy single-object shape. Retained so a browser still running a CACHED copy of the old
    // register.html (which posts `tos`, not `acceptances`) keeps producing a valid record during
    // rollout instead of silently registering with no acceptance on file at all.
    (await recordTosAcceptance(req, {
      userId: id, email,
      policyKey:     tos.policy_key     || 'physical_damage_voids_return',
      policyVersion: tos.policy_version || '1',
      policyText:    tos.policy_text    || null,
    }));
  }

  // Link the storefront-funnel order intent to the freshly-created account so the
  // admin sees exactly which order ↔ which account (orders.user_id FK). The static
  // checkout funnel can't write this itself (cross-origin), so it forwards the
  // intent via /register query params. Best-effort: never fail registration on a
  // bad/missing order — the account is what matters; the order is a linked record.
  const po = req.body.pending_order;
  if (po && typeof po === 'object') {
    try {
      const orderType = po.order_type === 'hardware' ? 'hardware' : 'digital';
      const sku   = po.sku ? String(po.sku).slice(0, 64) : null;
      const amount = Number.isFinite(+po.amount_cents) && +po.amount_cents >= 0
        ? Math.round(+po.amount_cents) : null;
      const orderRef = genRef('ORD');
      const now = Date.now();
      (await shopStmts.insertOrder.run({
        order_ref: orderRef, user_id: id, email,
        order_type: orderType, product_sku: sku, amount_cents: amount, currency: 'usd',
        status: 'pending', carrier: null, tracking_number: null,
        shipped_at: null, delivered_at: null, created_at: now, updated_at: now,
      }));
      log('info', 'Funnel order linked to new account', { orderRef, userId: id, orderType, sku });
    } catch (e) {
      log('warn', 'Failed to link funnel order at registration', { error: e.message });
    }
  }

  // Store registration context in session so the email-verify + TOTP steps can verify
  req.session.pendingRegistration = { userId: id, username };

  // Email-ownership verification (EVERY public signup): send a 6-digit code. The account stays
  // 'pending_email' until the code is entered at /api/register/verify-email, which then issues the
  // TOTP QR. This proves the registrant controls the email — the anchor of the device-lineage lock.
  try {
    const code = genEmailCode();
    (await db.prepare('UPDATE users SET email_verify_hash=?, email_verify_expires=? WHERE id=?')
      .run(sha256hex(code), Date.now() + EMAIL_CODE_TTL_MS, id));
    sendEmailVerifyCode(email, code).catch(() => {});
  } catch (e) { log('warn', 'email verify code send failed', { err: e.message }); }

  log('info', 'New public user registration started — email verification pending', { username, email });
  res.json({ ok: true, userId: id, email_verification: true, email });
});

// Step 1.5 — verify the emailed code (proves email ownership), then issue the TOTP QR.
app.post('/api/register/verify-email', totpRateLimit, async (req, res) => {
  if (!req.session?.pendingRegistration)
    return res.status(400).json({ error: 'No pending registration session — please start from the beginning' });
  const { userId } = req.session.pendingRegistration;
  const user = (await db.prepare('SELECT * FROM users WHERE id=?').get(userId));
  if (!user || user.status !== 'pending_email')
    return res.status(400).json({ error: 'Invalid registration state' });
  const code = String(req.body?.code || '').replace(/\D/g, '');
  if (!user.email_verify_hash || !user.email_verify_expires || Date.now() > Number(user.email_verify_expires))
    return res.status(400).json({ error: 'Your code expired — request a new one.' });
  if (sha256hex(code) !== user.email_verify_hash) {
    // Per-session brute-force guard (HIGH-3, mirrors the TOTP guard): a 6-digit code is 10^6 and
    // only IP-rate-limited — bound the guesses against THIS pending registration (5 wrong codes
    // burns it and forces a restart).
    const fails = (req.session.pendingRegFails || 0) + 1;
    req.session.pendingRegFails = fails;
    if (fails >= 5) {
      req.session.pendingRegistration = null;
      req.session.pendingRegFails = null;
      return res.status(429).json({ error: 'Too many incorrect codes — please start registration again.' });
    }
    return res.status(401).json({ error: 'Incorrect code — check your email and try again.' });
  }
  // Verified → advance to TOTP setup, clear the code, and issue the authenticator QR now.
  (await db.prepare("UPDATE users SET status='pending_totp', email_verify_hash=NULL, email_verify_expires=NULL WHERE id=?").run(userId));
  const totpSecret = decryptText(user.totp_secret);
  const otpauthUrl = speakeasy.otpauthURL({
    secret: totpSecret, label: encodeURIComponent(`SentinelMDM:${user.username}`), issuer: 'SentinelMDM', encoding: 'base32',
  });
  const qrDataUrl = await QRCode.toDataURL(otpauthUrl, { width: 200, margin: 1 });
  log('info', 'Registration email verified — proceeding to TOTP', { username: user.username });
  res.json({ ok: true, otpauth: otpauthUrl, qr_data_url: qrDataUrl });
});

// Resend the email verification code (rate-limited).
app.post('/api/register/resend-email-code', totpRateLimit, async (req, res) => {
  if (!req.session?.pendingRegistration) return res.status(400).json({ error: 'No pending registration session' });
  const { userId } = req.session.pendingRegistration;
  const user = (await db.prepare('SELECT id, email, status FROM users WHERE id=?').get(userId));
  if (!user || user.status !== 'pending_email') return res.status(400).json({ error: 'Invalid registration state' });
  const code = genEmailCode();
  (await db.prepare('UPDATE users SET email_verify_hash=?, email_verify_expires=? WHERE id=?')
    .run(sha256hex(code), Date.now() + EMAIL_CODE_TTL_MS, userId));
  const email = decryptText(user.email) || '';
  if (email) sendEmailVerifyCode(email, code).catch(() => {});
  res.json({ ok: true });
});

// Shared by /api/register/complete (2FA verified) and /api/register/skip-totp (2FA skipped) —
// 2FA is optional at signup (mirrors admin-created sub-users, who never had it mandatory either);
// only the totp_verified flag differs, which the login gate already keys off to decide whether
// to challenge for a code (see handleTotpVerify / POST /login).
async function finishPublicRegistration(req, user, totpVerified) {
  // Activate immediately — no manual admin approval step. Full feature access by default,
  // same grant the old "Approve" button used to apply.
  (await db.prepare("UPDATE users SET status='active', totp_verified=?, enabled_features=? WHERE id=?")
    .run(totpVerified ? 1 : 0, encryptText(JSON.stringify(PUBLIC_USER_DEFAULT_FEATURES)), user.id));
  // Keep the registration session alive (flagged) so the final OPTIONAL passkey step can
  // enroll against /api/register/passkey/* — the earlier steps stay locked out because the
  // user's status has moved past pending_email/pending_totp. Cleared after one enrollment.
  req.session.pendingRegistration = { userId: user.id, username: user.username, passkeyEligible: true };

  // Notify admin via Signal and any open admin dashboards (informational — no action needed).
  // Routed through the account alert policy — a fresh account is never hybrid, so this mirror
  // is suppressed for public accounts (the in-dashboard push below still fires).
  notifyAdminForUser(`🆕 New User Registered\nUsername: ${user.username}\nEmail: ${user.email || 'N/A'}\n2FA: ${totpVerified ? 'enabled' : 'skipped at signup'}\n\nAccount is active — full features enabled by default.`, user.id);
  (await notifyPush('enrollment', '🆕 New Registration', `${user.username} created an account.`, '/'));

  // Send the "you're all set — sign in" email right away (was previously sent at admin-approval time).
  sendApprovalEmail(user).catch(e => log('warn', 'Welcome email failed', { username: user.username, err: e.message }));

  // Seed a sample device so the dashboard isn't empty before the user enrolls a real one
  // (removed automatically the moment their first real device is bound — see bindDeviceToOwner()).
  try { (await createDemoDeviceForUser(user.id)); }
  catch (e) { log('warn', 'Demo device seed failed', { userId: user.id, err: e.message }); }

  log('info', 'Public user registration complete — account active', { username: user.username, totpVerified });
}

// Step 2 — verify TOTP setup code and complete registration
app.post('/api/register/complete', totpRateLimit, async (req, res) => {
  if (!req.session?.pendingRegistration)
    return res.status(400).json({ error: 'No pending registration session — please start from the beginning' });

  const { userId } = req.session.pendingRegistration;
  const user = (await db.prepare('SELECT * FROM users WHERE id=?').get(userId));
  if (!user || user.status !== 'pending_totp')
    return res.status(400).json({ error: 'Invalid registration state' });

  const totpSecret = decryptText(user.totp_secret);
  const valid = speakeasy.totp.verify({
    secret:   totpSecret,
    encoding: 'base32',
    token:    (req.body.code || '').replace(/\s/g, ''),
    window:   1,
  });
  if (!valid) return res.status(401).json({ error: 'Invalid TOTP code — try again' });

  await finishPublicRegistration(req, user, true);
  res.json({ ok: true, message: 'Registration complete! Your account is active — you can sign in now.' });
});

// Step 2 (alternate) — skip 2FA setup and activate without it. 2FA is optional here, not
// mandatory (mirrors admin-created sub-users, who never had it mandatory either).
app.post('/api/register/skip-totp', totpRateLimit, async (req, res) => {
  if (!req.session?.pendingRegistration)
    return res.status(400).json({ error: 'No pending registration session — please start from the beginning' });

  const { userId } = req.session.pendingRegistration;
  const user = (await db.prepare('SELECT * FROM users WHERE id=?').get(userId));
  if (!user || user.status !== 'pending_totp')
    return res.status(400).json({ error: 'Invalid registration state' });

  await finishPublicRegistration(req, user, false);
  res.json({ ok: true, message: 'Registration complete! Your account is active — you can sign in now.' });
});

};
