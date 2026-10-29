// S3 bucket network drive: per-account + per-device settings and command builder.
//
// A HELPER module, not a route module: it registers nothing. Public share is
// per-ACCOUNT (one password, fixed 'public/' prefix, so shares can read each
// other); private share is per-DEVICE (own password, own prefix). The S3
// connection config is account-wide. Config and secrets reach the device over
// its own Socket.IO control channel ('set_s3_drive'), never via bastion.
//
// S3_DRIVE_S3_FIELDS and resolveS3DriveSettingsForOwner stay private -- read
// only from within this file.

module.exports = ({ db, decryptText, encryptText }) => {
const S3_DRIVE_S3_FIELDS = ['endpoint', 'bucket', 'accessKey', 'secretKey', 'region'];

async function getS3DriveConfig(userId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('s3_drive_s3:' + userId));
  const empty = { endpoint: '', bucket: '', accessKey: '', secretKey: '', region: '', bandwidthMbps: 10 };
  if (!row) return empty;
  try {
    const cfg = JSON.parse(decryptText(row.value) || '{}');
    return { ...empty, ...cfg, bandwidthMbps: Number(cfg.bandwidthMbps) || 10 };
  } catch { return empty; }
}
async function setS3DriveConfig(userId, partial) {
  const existing = (await getS3DriveConfig(userId));
  const merged = { ...existing };
  for (const field of S3_DRIVE_S3_FIELDS) {
    const value = partial[field];
    if (value === undefined || value === null || value === '') continue; // blank = leave unchanged (secrets AND non-secrets)
    merged[field] = String(value);
  }
  const mbps = Number(partial.bandwidthMbps);
  if (Number.isFinite(mbps) && mbps > 0) merged.bandwidthMbps = Math.round(mbps);
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('s3_drive_s3:' + userId, encryptText(JSON.stringify(merged))));
}

async function getS3DrivePublicPassword(userId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('s3_drive_public_enc_pw:' + userId));
  return row ? decryptText(row.value) : '';
}
async function setS3DrivePublicPassword(userId, password) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('s3_drive_public_enc_pw:' + userId, encryptText(password)));
}

async function getS3DrivePrivatePassword(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('s3_drive_private_enc_pw:' + deviceId));
  return row ? decryptText(row.value) : '';
}
async function setS3DrivePrivatePassword(deviceId, password) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('s3_drive_private_enc_pw:' + deviceId, encryptText(password)));
}

// Recovery pointer (see the "recover-private" route below) — plain deviceId, not a secret, so
// stored unencrypted like other non-sensitive settings rows (e.g. file_backup_schedule).
async function getS3DrivePrivatePrefixOverride(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('s3_drive_private_prefix_override:' + deviceId));
  return row ? row.value : null;
}
async function setS3DrivePrivatePrefixOverride(deviceId, sourceDeviceId) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('s3_drive_private_prefix_override:' + deviceId, sourceDeviceId));
}

async function resolveS3DriveSettingsForOwner(userId) {
  const [s3, publicPassword] = await Promise.all([
    getS3DriveConfig(userId),
    getS3DrivePublicPassword(userId),
  ]);
  return { s3, publicPassword };
}
// Whose S3 config + Public password apply to THIS device: the owner's, if it has one — otherwise
// the CALLING admin's own (same "unowned device falls back to the calling admin" rule File Backup
// already uses via resolveFileBackupSettings — an unowned/admin-fleet device is only reachable here
// by an admin in the first place, per requireDeviceController()'s existing ZK-owner-only gate).
async function resolveS3DriveOwnerUserId(deviceId, req) {
  const row = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(deviceId));
  return row?.owner_user_id || req.session.userId;
}

async function getS3DriveEnabled(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('s3_drive:' + deviceId));
  if (!row) return false;
  try { return !!JSON.parse(row.value).enabled; } catch { return false; }
}
async function setS3DriveEnabled(deviceId, enabled) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('s3_drive:' + deviceId, JSON.stringify({ enabled: !!enabled })));
}

// Agent command payload — folds in the account's Public password AND this device's own Private
// password/prefix (never exposed to the browser), same non-negotiable as vpnCommand()'s egressUuid.
async function buildS3DriveCommand(deviceId, ownerUserId, enabled, resync) {
  const [{ s3, publicPassword }, privatePassword, prefixOverride] = await Promise.all([
    resolveS3DriveSettingsForOwner(ownerUserId),
    getS3DrivePrivatePassword(deviceId),
    getS3DrivePrivatePrefixOverride(deviceId),
  ]);
  return {
    command: 'set_s3_drive', enabled: !!enabled, resync: !!resync,
    endpoint: s3.endpoint, bucket: s3.bucket, accessKey: s3.accessKey, secretKey: s3.secretKey,
    region: s3.region, bandwidthMbps: s3.bandwidthMbps,
    publicEncryptionPassword: publicPassword || null,
    privateEncryptionPassword: privatePassword || null,
    privatePrefix: 'private/' + (prefixOverride || deviceId) + '/',
    publicPrefix: 'public/',
  };
}
return {
  buildS3DriveCommand,
  getS3DriveConfig,
  getS3DriveEnabled,
  getS3DrivePrivatePassword,
  getS3DrivePrivatePrefixOverride,
  getS3DrivePublicPassword,
  resolveS3DriveOwnerUserId,
  setS3DriveConfig,
  setS3DriveEnabled,
  setS3DrivePrivatePassword,
  setS3DrivePrivatePrefixOverride,
  setS3DrivePublicPassword,
};
};
