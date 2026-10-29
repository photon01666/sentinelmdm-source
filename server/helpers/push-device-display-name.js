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
// REBASE note: The block lazily requires ./bastionClient — rebased to ../bastionClient
// (bastionClient.js lives at the server root; verified resolvable from helpers/).

module.exports = ({ db }) => {
// Keeps the bastion's own display (session cards + Signal alert text) in sync with the
// SentinelMDM device name — Windows Remote Assist devices only (Android devices have no bastion
// session at all). Best-effort: never blocks the rename itself if bastion happens to be
// unreachable at this exact moment — provisionSession() also re-pushes the current name on every
// session create/reconnect (see bastionClient.js), so a missed push here self-heals the next
// time the device connects. See bastion-web.py's display_name_for() doc comment.
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