const speakeasy = require('speakeasy');
module.exports = ({ app, db, decryptText, express, loginRateLimit, stmts, vapidPublicKey, verifyUserPassword }) => {
// ── Web Push public key (no auth — needed before login to subscribe) ─────────
app.get('/api/push/vapid-public-key', (req, res) => {
  res.json({ publicKey: vapidPublicKey });
});

// ── Self-install APK: get enrollment token by credentials (no session) ────────
// Used by the self-install APK login popup so the device can link itself to a
// user account without admin ADB intervention.
// SECURITY (2026-10-13): this is a credential-equivalent endpoint — it hands back the
// enrollment token that pre-associates a device with the account. It MUST honor 2FA exactly
// like /login does: a password alone must never mint the token for a totp_verified account.
// It is unauthenticated-by-session (the APK has no session yet), so 2FA is verified inline
// from a `code` in the same request. An older client that sends no code gets a `totp_required`
// challenge rather than silently bypassing 2FA — a hard failure is always safer than a silent
// second-factor skip.
app.post('/api/enrollment/get-token', loginRateLimit, express.json(), async (req, res) => {
  const { username, password, authHash, code } = req.body || {};
  if (!username || (!password && !authHash)) return res.status(400).json({ error: 'Username and password required' });
  try {
    const user = (await stmts.userByName.get(username));
    // Generic failure for EVERYTHING that is not a valid, active, ready account — identical
    // response whether the identifier is unknown, the password is wrong, the account is
    // inactive, or it has no token. A distinct per-state message here would let an unauthenticated
    // caller enumerate which identifiers have accounts / are active (MEDIUM-1).
    const generic = () => res.status(401).json({ error: 'Invalid credentials' });
    if (!user || !(await verifyUserPassword(user, { password, authHash }))) return generic();
    if (user.status !== 'active') return generic();
    // 2FA gate (mirror /login's rule): a totp_verified account needs its per-user code.
    if (user.totp_verified) {
      const secret = user.totp_secret ? decryptText(user.totp_secret) : null;
      const ok = !!secret && speakeasy.totp.verify({
        secret, encoding: 'base32',
        token: String(code || '').replace(/\s/g, ''), window: 1,
      });
      if (!ok) return res.status(401).json({ totp_required: true, error: 'Two-factor code required — include `code`.' });
    }
    if (!user.enrollment_token) return generic();
    res.json({ enrollment_token: user.enrollment_token });
  } catch (e) { res.status(500).json({ error: 'Server error' }); }
});
};
