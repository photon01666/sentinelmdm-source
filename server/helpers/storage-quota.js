// helpers/storage-quota.js — public-account storage quota helpers.
//
// A HELPER module, not a route module: it registers nothing.
//
//   calculateStorageBytes   export   Sum storage across all owned-device tables
//   checkStorageQuota       export   Block new media when account is at/over quota
//
// ctx deps (2):
//   STORAGE_QUOTA_BYTES    binding    server.js L2494
//   db                     binding    server.js L699
//
// The require call must sit at or after L2495 (last non-hoisted dep STORAGE_QUOTA_BYTES
// is initialised at L2494) and at or before L3550 (earliest export consumer is L3551).
//
// relative requires: none

module.exports = ({ STORAGE_QUOTA_BYTES, db }) => {
async function calculateStorageBytes(userId) {
  // Approximate storage used by the account across all owned devices.
  // Media (photos/audio/screenshots) = base64 data; files = explicit size;
  // zk_payloads = encrypted data length; applocker files = tracked size.
  // Stream recordings (R2 without DB size) are NOT counted here — their
  // storage is charged against R2 limits, not the account quota.
  const deviceSubquery = 'SELECT id FROM devices WHERE owner_user_id=?';
  const rows = await Promise.all([
    db.prepare(`SELECT COALESCE(SUM(CAST(LENGTH(data) AS BIGINT) * 3 / 4), 0) AS bytes FROM media WHERE device_id IN (${deviceSubquery})`).get(userId),
    db.prepare(`SELECT COALESCE(SUM(CAST(size AS BIGINT)), 0) AS bytes FROM files WHERE device_id IN (${deviceSubquery})`).get(userId),
    db.prepare(`SELECT COALESCE(SUM(CAST(LENGTH(payload) AS BIGINT)), 0) AS bytes FROM zk_payloads WHERE device_id IN (${deviceSubquery})`).get(userId),
    db.prepare(`SELECT COALESCE(SUM(CAST(size_bytes AS BIGINT)), 0) AS bytes FROM applocker_blocked_files WHERE device_id IN (${deviceSubquery})`).get(userId),
  ]);
  return rows.reduce((sum, r) => sum + Number(r.bytes || 0), 0);
}
async function checkStorageQuota(userId, newBytes) {
  const used = await calculateStorageBytes(userId);
  if (used + newBytes > STORAGE_QUOTA_BYTES) {
    return { ok: false, used, quota: STORAGE_QUOTA_BYTES, needed: newBytes, remaining: Math.max(0, STORAGE_QUOTA_BYTES - used) };
  }
  return { ok: true, used, quota: STORAGE_QUOTA_BYTES };
}

  return { calculateStorageBytes, checkStorageQuota };
};