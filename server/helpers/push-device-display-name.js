// helpers/push-device-display-name.js — push display name to bastion.
//
// A HELPER module, not a route module: it registers nothing.
//
//   pushDeviceDisplayNameToBastion   export   push device name to bastion session
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: db (binding L646).  The call must sit at or after L647; the earliest consumer of
// the export is L3352, so at or before L3351.  L3330 satisfies both.
//
// The block lazily requires the support client at the server root.

module.exports = ({ db }) => {
// Keeps the support service's display (session cards + alert text) in sync with the
// SentinelMDM device name — Windows Remote Assist devices only (Android devices have no support
// session at all). Best-effort: never blocks the rename itself if the support service is
// unreachable at this exact moment — the session layer also re-pushes the current name on every
// session create/reconnect, so a missed push here self-heals the next time the device connects.
async function pushDeviceDisplayNameToBastion(deviceId, name) {
  const dev = (await db.prepare('SELECT platform, agent_kind FROM devices WHERE id=?').get(deviceId));
  if (!dev || dev.platform !== 'windows' || dev.agent_kind !== 'remote_assist') return;
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return;
  (await bastionClient.setDisplayName(deviceId, name));
}

  return {
    pushDeviceDisplayNameToBastion,
  };
};