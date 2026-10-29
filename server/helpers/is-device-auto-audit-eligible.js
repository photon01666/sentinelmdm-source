// helpers/is-device-auto-audit-eligible.js - check whether a device is eligible for auto-audit.
//
// A HELPER module, not a route module: it registers nothing.
//
//   isDeviceAutoAuditEligible   export   RA-capable + online device check
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: db (binding L699).  The call must sit at or after L700; the earliest consumer of
// the export is L7528, so at or before L7527.  L7425 satisfies both.
//
// REBASE note: The block lazily requires ./bastionClient — rebased to ../bastionClient
// (bastionClient.js lives at the server root; verified resolvable from helpers/).

module.exports = ({ db }) => {
// Is this device eligible for auto-audit (RA-capable + online)?
async function isDeviceAutoAuditEligible(deviceId) {
  try {
    const dev = (await db.prepare(
      "SELECT id, platform, agent_kind, online FROM devices WHERE id=?"
    ).get(deviceId));
    if (!dev) return false;
    if (dev.agent_kind !== 'remote_assist') return false;
    if (dev.platform !== 'windows' && dev.platform !== 'linux') return false;
    if (!dev.online) return false;
    // Bastion Hop-1 reverse tunnel is separate from the Socket.IO control channel —
    // the device can be Socket.IO-online but have its reverse tunnel down, in which
    // case every bastion call (runAudit / forensics / PowerShell) will silently fail.
    // Bail early instead of running the full 5-min poll loop only to land in the
    // stale-data guard.
    const bastionClient = require('../bastionClient');
    if (!bastionClient.configured()) return false;
    try {
      const st = await bastionClient.sessionStatus(deviceId);
      if (!st?.connected) return false;
    } catch (_) { return false; }
    return true;
  } catch { return false; }
}

  return {
    isDeviceAutoAuditEligible,
  };
};