// routes/s3-drive.js — S3 Bucket Network Drive: per-device enable/force-resync/status, the
// account-wide S3 config + Public share password, the per-device Private share password, and the
// crash/reinstall recovery pair (recoverable / recover-private). 11 routes, moved verbatim from
// server.js L7805-L7920 and registered in place via require('./routes/s3-drive')({ ...deps }) at the
// exact line the block previously occupied — registration order relative to every other route is
// therefore unchanged. No middleware, worker or bootstrap code in this range.
//
// The feature's helper cluster (getS3DriveConfig/setS3DriveConfig, the Public/Private password
// getters+setters, getS3DrivePrivatePrefixOverride/setS3DrivePrivatePrefixOverride,
// resolveS3DriveSettingsForOwner, resolveS3DriveOwnerUserId, getS3DriveEnabled/setS3DriveEnabled
// and buildS3DriveCommand) deliberately STAYS in server.js rather than moving with these routes:
// it sits above this block, and resolveS3DriveOwnerUserId/getS3DriveEnabled/buildS3DriveCommand are
// also called from the Socket.IO device-handshake re-push in server.js (~L10676) which has no HTTP
// req/res. They are injected as ctx deps below, so there is exactly one implementation of each.
// The secrets discipline is unchanged: no route ever returns a password, only an isSet boolean; the
// values themselves leave the server only via the set_s3_drive agent command (buildS3DriveCommand).

module.exports = ({ app, buildS3DriveCommand, db, decryptText, emitToDevice, getS3DriveConfig, getS3DriveEnabled, getS3DrivePrivatePassword, getS3DrivePublicPassword, log, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked, resolveS3DriveOwnerUserId, setS3DriveConfig, setS3DriveEnabled, setS3DrivePrivatePassword, setS3DrivePrivatePrefixOverride, setS3DrivePublicPassword }) => {
app.get('/api/devices/:id/s3-drive/enabled', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  res.json({ enabled: (await getS3DriveEnabled(req.params.id)) });
});
app.post('/api/devices/:id/s3-drive/enabled', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const enabled = !!(req.body || {}).enabled;
  (await setS3DriveEnabled(req.params.id, enabled));
  const ownerUserId = (await resolveS3DriveOwnerUserId(req.params.id, req));
  emitToDevice(req.params.id, 'command', (await buildS3DriveCommand(req.params.id, ownerUserId, enabled, false)));
  log('info', `S3 Drive ${enabled ? 'enabled' : 'disabled'}`, { deviceId: req.params.id });
  res.json({ ok: true, enabled });
});

app.post('/api/devices/:id/s3-drive/force-resync', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const enabled = (await getS3DriveEnabled(req.params.id));
  const ownerUserId = (await resolveS3DriveOwnerUserId(req.params.id, req));
  emitToDevice(req.params.id, 'command', (await buildS3DriveCommand(req.params.id, ownerUserId, enabled, true)));
  log('info', 'S3 Drive force-resync requested', { deviceId: req.params.id });
  res.json({ ok: true });
});

app.get('/api/devices/:id/s3-drive/status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('s3_drive_status:' + req.params.id));
  let status = {};
  if (row) { try { status = JSON.parse(row.value); } catch {} }
  res.json({ enabled: (await getS3DriveEnabled(req.params.id)), ...status });
});

app.get('/api/account/s3-drive-s3-config', requireUnlocked, requireAuth, async (req, res) => {
  const cfg = (await getS3DriveConfig(req.session.userId));
  res.json({
    endpoint: cfg.endpoint, bucket: cfg.bucket, region: cfg.region || 'us-east-1', bandwidthMbps: cfg.bandwidthMbps,
    accessKeySet: !!cfg.accessKey, secretKeySet: !!cfg.secretKey,
    configured: !!(cfg.bucket && cfg.accessKey && cfg.secretKey),
  });
});
app.post('/api/account/s3-drive-s3-config', requireUnlocked, requireAuth, async (req, res) => {
  (await setS3DriveConfig(req.session.userId, req.body || {}));
  log('info', 'S3 Drive S3 config updated', { userId: req.session.userId });
  res.json({ ok: true });
});

app.get('/api/account/s3-drive-public-key', requireUnlocked, requireAuth, async (req, res) => {
  const pw = (await getS3DrivePublicPassword(req.session.userId));
  res.json({ isSet: !!pw });
});
app.post('/api/account/s3-drive-public-key', requireUnlocked, requireAuth, async (req, res) => {
  const password = String(req.body?.password || '');
  if (!password) return res.status(400).json({ error: 'password is required' });
  (await setS3DrivePublicPassword(req.session.userId, password));
  log('info', 'S3 Drive Public share password updated', { userId: req.session.userId });
  res.json({ ok: true });
});

app.get('/api/devices/:id/s3-drive/private-key', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const pw = (await getS3DrivePrivatePassword(req.params.id));
  res.json({ isSet: !!pw });
});
app.post('/api/devices/:id/s3-drive/private-key', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const password = String(req.body?.password || '');
  if (!password) return res.status(400).json({ error: 'password is required' });
  (await setS3DrivePrivatePassword(req.params.id, password));
  // Setting a fresh password directly means the owner wants THIS device's own prefix again —
  // clear any prior recovery pointer so it doesn't keep pointing at another device's data.
  (await db.prepare("DELETE FROM settings WHERE key=?").run('s3_drive_private_prefix_override:' + req.params.id));
  const enabled = (await getS3DriveEnabled(req.params.id));
  if (enabled) {
    const ownerUserId = (await resolveS3DriveOwnerUserId(req.params.id, req));
    emitToDevice(req.params.id, 'command', (await buildS3DriveCommand(req.params.id, ownerUserId, enabled, true)));
  }
  log('info', 'S3 Drive Private share password updated', { deviceId: req.params.id });
  res.json({ ok: true });
});

// Recovery after a crash/reinstall — see the "Addendum" section of this feature's plan doc for the
// full narrative. wipeDeviceDataTables() never touches the generic `settings` table, so an old
// device's Private password survives indefinitely even after that device row is deleted — this
// lets a brand-new device (fresh random deviceId, minted by DeviceIdentity.cs on every OS
// reinstall) adopt an old device's S3 prefix + password without ever re-entering it by hand.
app.get('/api/devices/:id/s3-drive/recoverable', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const ownerUserId = (await resolveS3DriveOwnerUserId(req.params.id, req));
  const rows = (await db.prepare(
    `SELECT d.id, d.name, d.last_seen FROM devices d
     WHERE d.owner_user_id=? AND d.platform='windows' AND d.agent_kind='remote_assist' AND d.id<>?
       AND EXISTS (SELECT 1 FROM settings s WHERE s.key = 's3_drive_private_enc_pw:' || d.id)
     ORDER BY d.last_seen DESC LIMIT 20`
  ).all(ownerUserId, req.params.id));
  res.json({ candidates: rows.map(r => ({ id: r.id, name: decryptText(r.name) || r.id, lastSeen: r.last_seen })) });
});
app.post('/api/devices/:id/s3-drive/recover-private', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const sourceDeviceId = String(req.body?.sourceDeviceId || '').trim();
  if (!sourceDeviceId) return res.status(400).json({ error: 'sourceDeviceId is required' });
  if (sourceDeviceId === req.params.id) return res.status(400).json({ error: 'Cannot recover from the same device' });
  const ownerUserId = (await resolveS3DriveOwnerUserId(req.params.id, req));
  // If the source device row still exists, it MUST belong to the same owner — blocks fishing for
  // another account's still-online device's password via this route. If the row is already gone
  // (hard-deleted), fall through — device IDs are 128-bit random GUIDs never listed/enumerable
  // anywhere, so knowing one at all is itself reasonable evidence of prior legitimate access.
  const sourceDeviceRow = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(sourceDeviceId));
  if (sourceDeviceRow && sourceDeviceRow.owner_user_id !== ownerUserId) {
    return res.status(403).json({ error: 'That device does not belong to your account' });
  }
  const sourceRow = (await db.prepare("SELECT value FROM settings WHERE key=?").get('s3_drive_private_enc_pw:' + sourceDeviceId));
  if (!sourceRow) return res.status(404).json({ error: 'No stored Private password found for that device ID' });
  // Copy the still-encrypted password value forward to this device's own key, and point the prefix
  // at the OLD device's S3 path. Two independent copy-forward actions, no permanent indirection —
  // setting a fresh password later (the route above) cleanly overwrites/un-recovers this device.
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('s3_drive_private_enc_pw:' + req.params.id, sourceRow.value));
  (await setS3DrivePrivatePrefixOverride(req.params.id, sourceDeviceId));
  const enabled = (await getS3DriveEnabled(req.params.id));
  if (enabled) {
    emitToDevice(req.params.id, 'command', (await buildS3DriveCommand(req.params.id, ownerUserId, enabled, true)));
  }
  log('info', 'S3 Drive Private share recovered from another device', { deviceId: req.params.id, sourceDeviceId });
  res.json({ ok: true });
});
};
