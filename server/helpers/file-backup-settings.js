// File Backup: per-account S3 connection config + encryption-password accessors.
//
// A HELPER module, not a route module: it registers nothing. Secrets are
// encrypted at rest and never round-tripped to the browser -- GET returns only
// booleans for whether each secret is set.
//
// Both field lists stay private: FILE_BACKUP_S3_FIELDS is read only by the
// accessors below, and FILE_BACKUP_S3_SECRET_FIELDS currently has no reader
// anywhere in the codebase. It is carried over unchanged rather than dropped,
// so this remains a pure move -- but it is a genuine loose end.

module.exports = ({ db, decryptText, encryptText }) => {
const FILE_BACKUP_S3_FIELDS = ['endpoint', 'bucket', 'accessKey', 'secretKey', 'region'];
const FILE_BACKUP_S3_SECRET_FIELDS = new Set(['accessKey', 'secretKey']);

async function getFileBackupS3Config(userId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('file_backup_s3:' + userId));
  const empty = { endpoint: '', bucket: '', accessKey: '', secretKey: '', region: '', bandwidthMbps: 10 };
  if (!row) return empty;
  try {
    const cfg = JSON.parse(decryptText(row.value) || '{}');
    return { ...empty, ...cfg, bandwidthMbps: Number(cfg.bandwidthMbps) || 10 };
  } catch { return empty; }
}
async function setFileBackupS3Config(userId, partial) {
  const existing = (await getFileBackupS3Config(userId));
  const merged = { ...existing };
  for (const field of FILE_BACKUP_S3_FIELDS) {
    const value = partial[field];
    if (value === undefined || value === null || value === '') continue; // blank = leave unchanged (secrets AND non-secrets)
    merged[field] = String(value);
  }
  const mbps = Number(partial.bandwidthMbps);
  if (Number.isFinite(mbps) && mbps > 0) merged.bandwidthMbps = Math.round(mbps);
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('file_backup_s3:' + userId, encryptText(JSON.stringify(merged))));
}

async function getFileBackupEncryptionPassword(userId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('file_backup_enc_pw:' + userId));
  return row ? decryptText(row.value) : '';
}
async function setFileBackupEncryptionPassword(userId, password) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('file_backup_enc_pw:' + userId, encryptText(password)));
}

async function resolveFileBackupSettingsForOwner(userId) {
  const [s3, encryptionPassword] = await Promise.all([
    getFileBackupS3Config(userId),
    getFileBackupEncryptionPassword(userId),
  ]);
  return { s3, encryptionPassword };
}
// Whose S3 config + password apply to THIS device: the owner's, if it has one — otherwise the
// CALLING admin's own (an unowned/admin-fleet device is only reachable here by an admin in the
// first place, per requireDeviceController()'s existing ZK-owner-only gate).
async function resolveFileBackupSettings(deviceId, req) {
  const row = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(deviceId));
  const userId = row?.owner_user_id || req.session.userId;
  return resolveFileBackupSettingsForOwner(userId);
}
return {
  getFileBackupEncryptionPassword,
  getFileBackupS3Config,
  resolveFileBackupSettings,
  resolveFileBackupSettingsForOwner,
  setFileBackupEncryptionPassword,
  setFileBackupS3Config,
};
};
