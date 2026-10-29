// routes/file-backup.js — File Backup routes: per-account S3 config + encryption password,
// backup run / run-status / list / restore, stitched-chain download, and manual delete.
// 11 routes extracted VERBATIM from server.js L6862-L7050 and registered in place via
// require('./routes/file-backup')({ ...deps }) — route-registration order is unchanged.
//
// The feature's helper cluster (getFileBackupS3Config/setFileBackupS3Config,
// getFileBackupEncryptionPassword/setFileBackupEncryptionPassword, resolveFileBackupSettingsForOwner,
// resolveFileBackupSettings, getFileBackupSchedule/setFileBackupSchedule, getFileBackupFolders/
// setFileBackupFolders, pruneFileBackups, startFileBackupRun) deliberately STAYS in server.js:
// getFileBackupSchedule and startFileBackupRun are also used by the File Backup scheduled-run
// setInterval poller (server.js ~L16711/~L16725, worker-only), so they are injected as ctx deps
// below and there is exactly one implementation of each.
//
// The only edit to the copied code is the relative-require rebase (5 call sites): the bastionClient
// specifier now points one directory up, so it still resolves to the same server-root module
// instead of looking for routes/bastionClient.js, which does not exist.

module.exports = ({ app, db, getFileBackupEncryptionPassword, getFileBackupS3Config, log, randomUUID, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked, resolveFileBackupSettings, setFileBackupEncryptionPassword, setFileBackupS3Config, startFileBackupRun }) => {
app.get('/api/account/file-backup-key', requireUnlocked, requireAuth, async (req, res) => {
  const pw = (await getFileBackupEncryptionPassword(req.session.userId));
  res.json({ isSet: !!pw });
});
app.post('/api/account/file-backup-key', requireUnlocked, requireAuth, async (req, res) => {
  const password = String(req.body?.password || '');
  if (!password) return res.status(400).json({ error: 'password is required' });
  (await setFileBackupEncryptionPassword(req.session.userId, password));
  log('info', 'File Backup personal encryption password updated', { userId: req.session.userId });
  res.json({ ok: true });
});

app.get('/api/account/file-backup-s3-config', requireUnlocked, requireAuth, async (req, res) => {
  const cfg = (await getFileBackupS3Config(req.session.userId));
  res.json({
    endpoint: cfg.endpoint, bucket: cfg.bucket, region: cfg.region || 'us-east-1', bandwidthMbps: cfg.bandwidthMbps,
    accessKeySet: !!cfg.accessKey, secretKeySet: !!cfg.secretKey,
    configured: !!(cfg.bucket && cfg.accessKey && cfg.secretKey),
  });
});
app.post('/api/account/file-backup-s3-config', requireUnlocked, requireAuth, async (req, res) => {
  (await setFileBackupS3Config(req.session.userId, req.body || {}));
  log('info', 'File Backup S3 config updated', { userId: req.session.userId });
  res.json({ ok: true });
});

// Fire-and-forget: a real backup routinely takes many minutes (SCP pull + tar + encrypt + rclone
// upload of potentially GBs), far past Cloudflare's ~100s proxy timeout on the browser's request —
// awaiting it synchronously produced exactly that failure live ("JSON.parse: unexpected character
// at line 1 column 1" — CF's HTML timeout page where JSON was expected, same failure class as the
// Telemetry v1 Cloudflare-timeout bug documented elsewhere in this codebase). Insert the row,
// respond immediately, keep working in the background; the WebUI polls run-status below. Only the
// server.js -> bastion hop (internal swarm network, no Cloudflare involved) does the actual wait.
app.post('/api/devices/:id/file-backup/run', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const row = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(req.params.id));
  const userId = row?.owner_user_id || req.session.userId;
  const kind = req.body?.kind === 'incremental' ? 'incremental' : 'full';
  const result = (await startFileBackupRun(req.params.id, userId, kind));
  if (!result.ok) return res.status(result.runId ? 409 : 400).json(result);
  res.json(result);
});

// Cheap polling target — reads the tracked row directly, no live bastion/S3 round trip (that's
// what makes it safe to poll every few seconds without hammering bastion).
app.get('/api/devices/:id/file-backup/run-status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const runId = String(req.query.runId || '');
  const row = runId
    ? (await db.prepare('SELECT id,kind,status,s3_key,size_bytes,error,started_at,completed_at,restored_to,backup_kind FROM file_backup_runs WHERE id=? AND device_id=?').get(runId, req.params.id))
    : (await db.prepare('SELECT id,kind,status,s3_key,size_bytes,error,started_at,completed_at,restored_to,backup_kind FROM file_backup_runs WHERE device_id=? ORDER BY started_at DESC LIMIT 1').get(req.params.id));
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json(row);
});

app.get('/api/devices/:id/file-backup/list', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const { s3, encryptionPassword } = (await resolveFileBackupSettings(req.params.id, req));
  const history = (await db.prepare("SELECT id,kind,status,s3_key,size_bytes,profiles,error,started_at,completed_at,backup_kind FROM file_backup_runs WHERE device_id=? AND kind='backup' ORDER BY started_at DESC LIMIT 50").all(req.params.id))
    .map(r => ({ ...r, profiles: r.profiles ? JSON.parse(r.profiles) : [] }));
  if (!s3.bucket) return res.json({ ok: true, backups: [], history });
  const bastionClient = require('../bastionClient');
  try {
    const remote = (await bastionClient.fileBackupList(req.params.id, { ...s3, encryptionPassword }));
    res.json({ ok: remote.ok !== false, backups: remote.backups || [], error: remote.error, history });
  } catch (e) {
    res.json({ ok: false, backups: [], error: e.message, history });
  }
});

// Same fire-and-forget + poll design as run() above — a restore does an equally long rclone
// download + openssl decrypt + tar extract + scp push, just as vulnerable to the CF timeout.
app.post('/api/devices/:id/file-backup/restore', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const { s3, encryptionPassword } = (await resolveFileBackupSettings(req.params.id, req));
  if (!s3.bucket) return res.status(400).json({ error: "Set up this device owner's S3 bucket in the File Backup tab first" });
  if (!encryptionPassword) return res.status(400).json({ error: 'Set your backup encryption password first' });
  const backupKey = String(req.body?.backupKey || '');
  if (!backupKey) return res.status(400).json({ error: 'backupKey is required' });
  const destPath = String(req.body?.destPath || '').trim().replace(/\\+$/, '');
  if (destPath && !/^[A-Za-z]:\\[^\r\n]*$/.test(destPath)) return res.status(400).json({ error: 'Invalid restore destination path' });
  const already = (await db.prepare("SELECT id FROM file_backup_runs WHERE device_id=? AND kind='restore' AND status='running'").get(req.params.id));
  if (already) return res.status(409).json({ error: 'A restore is already running for this device', runId: already.id });
  const bastionClient = require('../bastionClient');
  const runId = randomUUID();
  (await db.prepare("INSERT INTO file_backup_runs (id,device_id,kind,status,s3_key,started_at) VALUES (?,?,'restore','running',?,?)").run(runId, req.params.id, backupKey, Date.now()));
  bastionClient.fileBackupRestore(req.params.id, { ...s3, encryptionPassword }, backupKey, destPath)
    .then(async result => {
      (await db.prepare('UPDATE file_backup_runs SET status=?,error=?,completed_at=?,restored_to=? WHERE id=?')
        .run(result.ok ? 'completed' : 'failed', result.ok ? null : (result.error || 'unknown error'), Date.now(), result.restoredTo || null, runId));
      log(result.ok ? 'info' : 'warn', 'File Backup restore finished', { deviceId: req.params.id, ok: result.ok, backupKey, error: result.error });
    })
    .catch(async e => {
      (await db.prepare('UPDATE file_backup_runs SET status=?,error=?,completed_at=? WHERE id=?').run('failed', e.message, Date.now(), runId));
      log('error', 'File Backup restore failed', { deviceId: req.params.id, backupKey, error: e.message });
    });
  res.json({ ok: true, runId, status: 'running' });
});

// Download now stitches the full chain (base full backup + every incremental up to and including
// the picked one, same chain-replay bastion's restore already does) and serves ONE complete,
// already-decrypted zip — instead of the raw single ciphertext .tar.enc object it used to stream
// straight through. Building that (rclone download + openssl decrypt + tar extract per chain
// entry, then zip) is at least as long-running as a restore — same fire-and-forget + poll design
// as run()/restore() above, or a multi-incremental chain would routinely blow past Cloudflare's
// ~100s proxy timeout with zero bytes sent yet (see the `Telemetry kill-switch` docs/ARCHITECTURE.md
// invariant for the same failure class hit before). bastion's build_stitched_backup_archive()
// requires a hex run id (baked into on-disk staging filenames, validated by a strict regex) —
// generate one here instead of the usual randomUUID(), rather than relaxing bastion's regex.
app.post('/api/devices/:id/file-backup/download', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const { s3, encryptionPassword } = (await resolveFileBackupSettings(req.params.id, req));
  if (!s3.bucket) return res.status(400).json({ error: "Set up this device owner's S3 bucket in the File Backup tab first" });
  if (!encryptionPassword) return res.status(400).json({ error: 'Set your backup encryption password first' });
  const backupKey = String(req.body?.backupKey || '');
  if (!backupKey) return res.status(400).json({ error: 'backupKey is required' });
  const already = (await db.prepare("SELECT id FROM file_backup_runs WHERE device_id=? AND kind='download' AND status='running'").get(req.params.id));
  if (already) return res.status(409).json({ error: 'A download is already being prepared for this device', runId: already.id });
  const bastionClient = require('../bastionClient');
  const runId = require('crypto').randomBytes(8).toString('hex');
  (await db.prepare("INSERT INTO file_backup_runs (id,device_id,kind,status,s3_key,started_at) VALUES (?,?,'download','running',?,?)").run(runId, req.params.id, backupKey, Date.now()));
  bastionClient.fileBackupPrepareDownload(req.params.id, { ...s3, encryptionPassword }, backupKey, runId)
    .then(async result => {
      (await db.prepare('UPDATE file_backup_runs SET status=?,size_bytes=?,error=?,completed_at=? WHERE id=?')
        .run(result.ok ? 'completed' : 'failed', result.size || 0, result.ok ? null : (result.error || 'unknown error'), Date.now(), runId));
      log(result.ok ? 'info' : 'warn', 'File Backup download prepared', { deviceId: req.params.id, ok: result.ok, backupKey, error: result.error });
    })
    .catch(async e => {
      (await db.prepare('UPDATE file_backup_runs SET status=?,error=?,completed_at=? WHERE id=?').run('failed', e.message, Date.now(), runId));
      log('error', 'File Backup download prepare failed', { deviceId: req.params.id, backupKey, error: e.message });
    });
  res.json({ ok: true, runId, status: 'running' });
});

// Streams the zip build_stitched_backup_archive() already finished writing bastion-side (fast —
// all the slow work happened during the POST above) and deletes it bastion-side once fully sent.
// Only reachable once the polled run row shows status:'completed' for this exact runId+kind.
app.get('/api/devices/:id/file-backup/download/:runId/file', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const row = (await db.prepare("SELECT id,kind,status,s3_key FROM file_backup_runs WHERE id=? AND device_id=?").get(req.params.runId, req.params.id));
  if (!row || row.kind !== 'download') return res.status(404).json({ error: 'Not found' });
  if (row.status !== 'completed') return res.status(409).json({ error: `Download not ready (status: ${row.status})` });
  const bastionClient = require('../bastionClient');
  const label = bastionClient.labelForDevice(req.params.id);
  const internalUrl = process.env.BASTION_INTERNAL_URL || 'http://bastion:9098';
  const key = require('fs').readFileSync('/run/secrets/sentinel_bastion_internal_key', 'utf8').trim();
  try {
    const bastionRes = await fetch(`${internalUrl}/api/sessions/${encodeURIComponent(label)}/file-backup/download-fetch?runId=${encodeURIComponent(req.params.runId)}`, {
      headers: { 'X-Api-Key': key },
    });
    if (!bastionRes.ok) {
      const err = await bastionRes.text().catch(() => 'download failed');
      return res.status(502).json({ error: err.slice(0, 400) });
    }
    const zipName = `${(row.s3_key || 'backup').split('/').pop().replace(/\.tar\.enc$/, '')}.zip`;
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', `attachment; filename="${zipName}"`);
    const reader = bastionRes.body?.getReader?.() || null;
    if (reader) {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
      res.end();
    } else {
      const buf = await bastionRes.arrayBuffer();
      res.end(Buffer.from(buf));
    }
  } catch (e) {
    log('error', 'File Backup download-fetch failed', { deviceId: req.params.id, runId: req.params.runId, error: e.message });
    if (!res.headersSent) res.status(502).json({ error: e.message });
  }
});

// Manual single-backup delete — pure S3 delete via bastionClient.fileBackupDelete (same helper
// pruneFileBackups already uses), so this works even while the device itself is offline. Only
// removes the S3 object; does NOT touch file_backup_runs history rows (the run stays listed with
// its original status — the backup it produced is just gone from S3, same as retention pruning).
app.post('/api/devices/:id/file-backup/delete', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const { s3 } = (await resolveFileBackupSettings(req.params.id, req));
  if (!s3.bucket) return res.status(400).json({ error: "Set up this device owner's S3 bucket in the File Backup tab first" });
  const backupKey = String(req.body?.backupKey || '');
  if (!backupKey) return res.status(400).json({ error: 'backupKey is required' });
  const bastionClient = require('../bastionClient');
  try {
    const result = (await bastionClient.fileBackupDelete(s3, backupKey));
    if (!result?.ok) return res.status(502).json({ error: result?.error || 'Delete failed' });
    log('info', 'File Backup manually deleted', { deviceId: req.params.id, key: backupKey });
    res.json({ ok: true });
  } catch (e) {
    log('error', 'File Backup delete failed', { deviceId: req.params.id, key: backupKey, error: e.message });
    res.status(502).json({ error: e.message });
  }
});
};
