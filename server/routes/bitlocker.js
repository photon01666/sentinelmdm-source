// routes/bitlocker.js - BitLocker remote enable + recovery-key vault (Hop-2 via bastionClient).
// Extracted verbatim from server.js L7808-L7898.
// The only transform applied is require('./bastionClient') ->
// require('../bastionClient'): that specifier must resolve to server/bastionClient.js
// from one directory deeper. Everything else is byte-identical.
module.exports = ({ app, db, decryptText, encryptText, ingestBitlockerResult, log, randomUUID, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked }) => {
// ── BitLocker — remote enable + recovery-key vault ─────────────────────────────────────────────
// Enable/status calls run inline over Hop-2 (bastionClient.bitlockerEnable/bitlockerStatus) — no
// C# agent involvement, no bastion-side caching (see bitlocker_enable()/bitlocker_status() in
// the support service). Any RecoveryPassword key protector either call returns is persisted here
// (encryptText()'d, deduped by the bitlocker_keys table's UNIQUE(device_id,key_protector_id))
// so a key survives independently of the device ever reconnecting again — that persistence is
// the actual point of the feature, not just a progress display.

app.post('/api/devices/:id/bitlocker/enable', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../bastionClient');
  // Defaults to C: (the OS drive) but any currently-attached volume can be targeted — see the
  // drive-letter selector in the BitLocker panel. Validated here too (not just bastion-side) —
  // never trust a client-supplied value that ends up in a PowerShell script template unchecked.
  const mountPoint = String(req.body?.mountPoint || 'C:').trim().toUpperCase();
  if (!/^[A-Z]:$/.test(mountPoint)) return res.status(400).json({ error: 'invalid drive letter' });
  let result;
  try { result = (await bastionClient.bitlockerEnable(req.params.id, mountPoint)); }
  catch (e) { return res.status(502).json({ error: e.bastionError || e.message || 'BitLocker enable failed' }); }
  if (!result?.ok) return res.status(400).json({ error: result?.error || 'BitLocker enable failed' });
  const { newKeys, statusSummary } = (await ingestBitlockerResult(req.params.id, result));
  log('info', 'BitLocker enable ran', { deviceId: req.params.id, alreadyEnabled: !!result.alreadyEnabled, newKeys });
  res.json({ ok: true, alreadyEnabled: !!result.alreadyEnabled, newKeys, ...statusSummary });
});

// Live status — falls back to the last durable snapshot (settings['bitlocker_status:<id>']) when
// the device is offline, so the WebUI still shows a last-known state instead of going blank.
app.get('/api/devices/:id/bitlocker/status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../bastionClient');
  let result;
  try { result = (await bastionClient.bitlockerStatus(req.params.id)); } catch (e) { result = { ok: false, error: e.message }; }
  if (result?.ok) {
    const { statusSummary } = (await ingestBitlockerResult(req.params.id, result));
    return res.json({ ok: true, live: true, ...statusSummary });
  }
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('bitlocker_status:' + req.params.id));
  if (row) return res.json({ ok: true, live: false, error: result?.error, ...JSON.parse(row.value) });
  res.json({ ok: false, live: false, error: result?.error || 'No status available yet', volumes: [] });
});

// Metadata only (id/volume/keyProtectorId/createdAt) — never the decrypted key itself. Matches
// the file-backup/S3-drive masked-secret discipline: the actual value only ever leaves the server
// via the explicit download route below.
app.get('/api/devices/:id/bitlocker/keys', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const rows = (await db.prepare('SELECT id,volume,key_protector_id,created_at FROM bitlocker_keys WHERE device_id=? ORDER BY created_at DESC').all(req.params.id));
  res.json({ ok: true, keys: rows.map(r => ({ id: r.id, volume: r.volume, keyProtectorId: r.key_protector_id, createdAt: r.created_at })) });
});

app.get('/api/devices/:id/bitlocker/keys/:keyId/download', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const row = (await db.prepare('SELECT * FROM bitlocker_keys WHERE id=? AND device_id=?').get(req.params.keyId, req.params.id));
  if (!row) return res.status(404).json({ error: 'Key not found' });
  const recoveryKey = decryptText(row.recovery_key);
  const device = (await db.prepare('SELECT name FROM devices WHERE id=?').get(req.params.id));
  const deviceName = (device?.name && !String(device.name).startsWith('ENC:')) ? device.name : (decryptText(device?.name) || req.params.id);
  const body = `BitLocker Recovery Key\r\nDevice: ${deviceName}\r\nVolume: ${row.volume}\r\nKey Protector ID: ${row.key_protector_id}\r\nCaptured: ${new Date(row.created_at).toISOString()}\r\n\r\nRecovery Key: ${recoveryKey}\r\n`;
  res.set('Content-Disposition', `attachment; filename="BitLocker-Recovery-${row.volume.replace(/[^A-Za-z0-9]/g, '')}-${req.params.id.slice(0, 12)}.txt"`);
  res.type('text/plain').send(body);
});

app.delete('/api/devices/:id/bitlocker/keys/:keyId', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const info = (await db.prepare('DELETE FROM bitlocker_keys WHERE id=? AND device_id=?').run(req.params.keyId, req.params.id));
  if (!info.changes) return res.status(404).json({ error: 'Key not found' });
  log('info', 'BitLocker recovery key deleted', { deviceId: req.params.id, keyId: req.params.keyId });
  res.json({ ok: true });
});
};
