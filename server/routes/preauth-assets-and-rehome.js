module.exports = ({ app, authenticateDeviceRequest, db, decryptText, EMAIL_CODE_TTL_MS, genEmailCode, log, normIdent, path, requireUnlocked, sendEmailVerifyCode, sha256hex, signalAlert }) => {
for (const _img of ['favicon.png', 'favicon.ico', 'icon-192.png', 'logo.png']) {
  app.get(`/${_img}`, (_req, res) => {
    res.set('Cache-Control', 'public, max-age=86400');
    res.sendFile(path.join(__dirname, '..', 'public', _img));
  });
}

// ── Digital Asset Links — MUST be served BEFORE requireAuth ──────────────────
// Lets the SentinelClient companion apps use passkeys inside their WebView:
// WebSettingsCompat.setWebAuthenticationSupport(FOR_APP) only works when the OS can
// validate the app↔origin association by fetching this file from the RP origin
// (handle_all_urls = passkey sharing, get_login_creds = password sharing). The fetch
// comes from the device/Google with no session cookie, so it must be pre-auth — same
// class as /sw.js. Public by spec, nothing sensitive (package names + signing certs).
// SHA-256 of the client app signing cert, colon-separated as Android prints it.
// Supply ASSETLINKS_CLIENT_CERT in production; empty omits the fingerprint entry.
const ASSETLINKS_CLIENT_CERT = (process.env.ASSETLINKS_CLIENT_CERT || '').trim();
const ASSETLINKS = ['com.sentinelmdm.monitor', 'com.sentinelmdm.adminmonitor', 'com.sentinelmdm.subusersmonitor']
  .map(pkg => ({
    relation: ['delegate_permission/common.handle_all_urls', 'delegate_permission/common.get_login_creds'],
    target: {
      namespace: 'android_app',
      package_name: pkg,
      ...(ASSETLINKS_CLIENT_CERT ? { sha256_cert_fingerprints: [ASSETLINKS_CLIENT_CERT] } : {}),
    },
  }));
app.get('/.well-known/assetlinks.json', (_req, res) => {
  res.set('Cache-Control', 'public, max-age=3600');
  res.json(ASSETLINKS);
});

// ── Device re-home to a DIFFERENT email (device-signed; BEFORE requireAuth) ──────────────────────
// A device is permanently welded to its first email's lineage and survives factory reset. The ONLY
// way to move it to a different email is to prove control of the ORIGINAL email: the agent (orphan
// reclaim screen, "use a different email") requests a code sent to the lineage email; entering it
// clears the lineage so the device can enroll to a new account. A thief / compromised admin can't
// receive that code, so anti-theft is preserved. Both steps require the device's signed handshake.
app.post('/api/device/rehome/start', requireUnlocked, async (req, res) => {
  if (!(await authenticateDeviceRequest(req))) return res.status(401).json({ error: 'Device authentication failed' });
  const deviceId = req.headers['x-device-id'];
  const dev = (await db.prepare('SELECT locked_identity_email FROM devices WHERE id=?').get(deviceId));
  if (!dev || !dev.locked_identity_email) return res.status(400).json({ error: 'This device is not locked to an email.' });
  const oldEmail = normIdent(decryptText(dev.locked_identity_email));
  if (!oldEmail) return res.status(400).json({ error: 'No lineage email on file.' });
  const code = genEmailCode();
  (await db.prepare('UPDATE devices SET rehome_code_hash=?, rehome_code_expires=? WHERE id=?')
    .run(sha256hex(code), Date.now() + EMAIL_CODE_TTL_MS, deviceId));
  sendEmailVerifyCode(oldEmail, code).catch(() => {});
  log('warn', 'Device re-home code requested (sent to original email)', { deviceId });
  signalAlert('🔁 Device Re-home Requested', `Device ${deviceId} requested a re-home to a new email. A verification code was sent to its ORIGINAL email lineage.`, null, deviceId).catch(() => {});
  // Masked hint so the user knows which inbox to check, without leaking the full address.
  const hint = oldEmail.replace(/^(.).*?(.?@.*)$/, (_, a, b) => a + '•••' + b);
  res.json({ ok: true, email_hint: hint });
});
app.post('/api/device/rehome/verify', requireUnlocked, async (req, res) => {
  if (!(await authenticateDeviceRequest(req))) return res.status(401).json({ error: 'Device authentication failed' });
  const deviceId = req.headers['x-device-id'];
  const dev = (await db.prepare('SELECT rehome_code_hash, rehome_code_expires FROM devices WHERE id=?').get(deviceId));
  const code = String(req.body?.code || '').replace(/\D/g, '');
  if (!dev || !dev.rehome_code_hash || !dev.rehome_code_expires || Date.now() > Number(dev.rehome_code_expires))
    return res.status(400).json({ error: 'No active re-home request, or it expired — start again.' });
  if (sha256hex(code) !== dev.rehome_code_hash)
    return res.status(401).json({ error: 'Incorrect code — check the original email.' });
  // Verified → clear the lineage lock entirely; the device is now free to enroll to ANY email.
  (await db.prepare('UPDATE devices SET locked_identity_email=NULL, locked_pubkey_sha=NULL, rehome_code_hash=NULL, rehome_code_expires=NULL WHERE id=?').run(deviceId));
  log('warn', 'Device re-homed — lineage cleared, free to enroll to a new email', { deviceId });
  signalAlert('✅ Device Re-homed', `Device ${deviceId} re-home verified via the original email. Lineage cleared; it can now enroll to a new email.`, null, deviceId).catch(() => {});
  res.json({ ok: true });
});
};
