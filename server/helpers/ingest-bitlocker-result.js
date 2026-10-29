// helpers/ingest-bitlocker-result.js — BitLocker recovery-key ingest + status summary.
//
// A HELPER module, not a route module: it registers nothing. Shared by the routes/bitlocker
// module and the BitLocker status poller further down (both inject it).
//
//   ingestBitlockerResult   export   Ingest BitLocker volumes from a device result
//
// ctx deps (4):
//   db           binding    server.js L699
//   encryptText  function   server.js L158  (hoisted)
//   log          function   server.js L423  (hoisted)
//   randomUUID   destructure server.js L16
//
// The require call must sit at or after L700 (last non-hoisted dep db)
// and at or before L4470 (earliest export consumer is L4471).
//
// relative requires: none

module.exports = ({ db, encryptText, log, randomUUID }) => {

async function ingestBitlockerResult(deviceId, result) {
const volumes = Array.isArray(result?.volumes) ? result.volumes : [];
let newKeys = 0;
for (const vol of volumes) {
const protectors = Array.isArray(vol?.keyProtectors) ? vol.keyProtectors : [];
for (const kp of protectors) {
  if (kp?.type !== 'RecoveryPassword' || !kp.recoveryPassword || !kp.id) continue;
  try {
    const insert = (await db.prepare(
      `INSERT INTO bitlocker_keys (id,device_id,volume,key_protector_id,recovery_key,created_at)
       VALUES (?,?,?,?,?,?) ON CONFLICT(device_id,key_protector_id) DO NOTHING`
    ).run(randomUUID(), deviceId, vol.mountPoint || 'C:', kp.id, encryptText(kp.recoveryPassword), Date.now()));
    if (insert.changes) newKeys++;
  } catch (e) { log('warn', 'BitLocker key ingest failed', { deviceId, error: e.message }); }
}
}
const statusSummary = {
volumes: volumes.map(v => ({
  mountPoint: v.mountPoint, volumeType: v.volumeType, protectionStatus: v.protectionStatus,
  volumeStatus: v.volumeStatus, encryptionPercentage: v.encryptionPercentage,
})),
updatedAt: Date.now(),
};
(await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
.run('bitlocker_status:' + deviceId, JSON.stringify(statusSummary)));
return { newKeys, statusSummary };
}

  return { ingestBitlockerResult };
};