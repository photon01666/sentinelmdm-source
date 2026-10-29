// helpers/sync-device-display-name.js — sync display name to bastion.
//
// A HELPER module, not a route module: it registers nothing.
//
//   syncDeviceDisplayNameToBastion   export   self-healing bastion display name sync
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 3 deps: db (binding L646), decryptText (function L162, hoisted), pushDeviceDisplayNameToBastion (destructure L3330).  The call must sit at or after L3331; the earliest consumer of
// the export is L3709, so at or before L3708.  L3332 satisfies both.
//
// relative requires: none

module.exports = ({ db, decryptText, pushDeviceDisplayNameToBastion }) => {
// Self-healing counterpart — looks up the device's OWN current name and pushes it, for the
// provisionSession() call sites (session create/reconnect) that don't already have it in scope.
// Fire-and-forget: callers do `.catch(...)`, never `await`, on their response-critical path.
async function syncDeviceDisplayNameToBastion(deviceId) {
  const dev = (await db.prepare('SELECT name, platform, agent_kind FROM devices WHERE id=?').get(deviceId));
  if (!dev || dev.platform !== 'windows' || dev.agent_kind !== 'remote_assist') return;
  const name = (dev.name && !String(dev.name).startsWith('ENC:')) ? dev.name : (decryptText(dev.name) || '');
  if (!name) return;
  (await pushDeviceDisplayNameToBastion(deviceId, name));
}

  return {
    syncDeviceDisplayNameToBastion,
  };
};