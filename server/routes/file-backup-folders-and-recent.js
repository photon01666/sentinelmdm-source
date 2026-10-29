// routes/file-backup-folders-and-recent.js — File Backup folder selection + fleet run history:
// per-device well-known/custom backup folders, the folder-picker modal's live browse + path-size
// primitives, and the fleet-wide recent-backups view. 5 routes + the setFileBackupFolders helper,
// extracted VERBATIM from server.js L5707-L5776 and registered in place via
// require('./routes/file-backup-folders-and-recent')({ ...deps }) — route-registration order is
// unchanged.
//
// The rest of the File Backup helper cluster deliberately STAYS in server.js (Rule A — a helper
// with ANY caller outside the block must not move): getFileBackupFolders is also called by
// startFileBackupRun (which stays: routes/file-backup.js receives it as ctx and the scheduled-run
// setInterval poller calls it), and FILE_BACKUP_KNOWN_FOLDERS is used by that staying
// getFileBackupFolders. Both are injected as ctx deps below, so there is exactly one implementation
// of each. FILE_BACKUP_MAX_CUSTOM_PATHS is used only by this block's setFileBackupFolders, but it
// sits directly above getFileBackupFolders in server.js, so no contiguous range can include it
// without also moving the shared getter — it too is left in server.js and injected.
//
// The only edits to the copied code are the relative-require rebases (2 call sites): the
// bastionClient specifier now points one directory up, so it still resolves to the same
// server-root module instead of looking for routes/bastionClient.js, which does not exist.

module.exports = ({ FILE_BACKUP_KNOWN_FOLDERS, FILE_BACKUP_MAX_CUSTOM_PATHS, app, db, decryptText, getFileBackupFolders, log, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked }) => {
async function setFileBackupFolders(deviceId, partial) {
  const merged = (await getFileBackupFolders(deviceId));
  if (Array.isArray(partial.wellKnown)) {
    merged.wellKnown = partial.wellKnown.filter(f => FILE_BACKUP_KNOWN_FOLDERS.includes(f));
  }
  if (Array.isArray(partial.customPaths)) {
    // Never trust a client-supplied sizeBytes blindly for anything security-sensitive — it's
    // purely a UI convenience cache here (the actual backup pulls whatever's really on disk at
    // run time), so light validation (finite, non-negative) is enough.
    merged.customPaths = partial.customPaths
      .filter(e => e && typeof e.path === 'string' && /^[A-Za-z]:\\/.test(e.path))
      .slice(0, FILE_BACKUP_MAX_CUSTOM_PATHS)
      .map(e => ({
        path: e.path,
        sizeBytes: Number.isFinite(Number(e.sizeBytes)) ? Math.max(0, Math.round(Number(e.sizeBytes))) : null,
        addedAt: Number.isFinite(Number(e.addedAt)) ? Number(e.addedAt) : Date.now(),
      }));
  }
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('file_backup_folders:' + deviceId, JSON.stringify(merged)));
  return merged;
}

app.get('/api/devices/:id/file-backup/folders', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  res.json((await getFileBackupFolders(req.params.id)));
});
app.post('/api/devices/:id/file-backup/folders', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const saved = (await setFileBackupFolders(req.params.id, req.body || {}));
  log('info', 'File Backup folders updated', { deviceId: req.params.id, wellKnown: saved.wellKnown, customCount: saved.customPaths.length });
  res.json({ ok: true, ...saved });
});

// Folder-picker modal — live remote directory browse (path='' lists every local drive letter) and
// a one-shot recursive size lookup for the folder about to be confirmed. Both need a connected
// tunnel; bastion returns {ok:false,error:'session not connected'} otherwise, same as every other
// live Hop-2 action elsewhere in this file — no separate live-connection gate needed here.
app.post('/api/devices/:id/file-backup/browse', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../bastionClient');
  const result = (await bastionClient.fileBackupBrowse(req.params.id, String(req.body?.path || '')));
  res.status(result.ok ? 200 : 400).json(result);
});
app.post('/api/devices/:id/file-backup/path-size', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../bastionClient');
  const result = (await bastionClient.fileBackupPathSize(req.params.id, String(req.body?.path || '')));
  res.status(result.ok ? 200 : 400).json(result);
});

// Fleet-wide "is this actually happening" view — most recent backup runs across every device the
// caller can see (all Windows RA devices for admin; only your own for public/business_sub), so a
// scheduled backup silently failing for weeks doesn't go unnoticed. Read-only, no bastion/S3 round
// trip — just the tracked history table, same cheap-poll-safe shape as run-status above.
app.get('/api/remote-assist/file-backup/recent', requireUnlocked, requireAuth, async (req, res) => {
  const isAdmin = req.session.role === 'admin';
  const baseSql = `SELECT r.id, r.device_id, r.status, r.s3_key, r.size_bytes, r.error, r.started_at, r.completed_at, d.name as device_name
    FROM file_backup_runs r JOIN devices d ON r.device_id = d.id
    WHERE r.kind='backup' AND d.platform='windows' AND d.agent_kind='remote_assist'`;
  let rows;
  if (isAdmin) {
    rows = (await db.prepare(`${baseSql} ORDER BY r.started_at DESC LIMIT 50`).all());
  } else if (req.session.account_type === 'public' || req.session.account_type === 'business_sub') {
    const ownerId = req.session.account_type === 'business_sub' ? req.session.parent_owner_id : req.session.userId;
    rows = (await db.prepare(`${baseSql} AND d.owner_user_id=? ORDER BY r.started_at DESC LIMIT 50`).all(ownerId));
  } else {
    return res.json({ runs: [] });
  }
  res.json({ runs: rows.map(r => ({
    id: r.id, deviceId: r.device_id, deviceName: decryptText(r.device_name) || r.device_id,
    status: r.status, sizeBytes: r.size_bytes, error: r.error, startedAt: r.started_at, completedAt: r.completed_at,
  })) });
});
};
