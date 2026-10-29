// helpers/require-remote-assist-device.js — middleware to require RA device.
//
// A HELPER module, not a route module: it registers nothing.
//
//   requireRemoteAssistDevice   export   middleware that enforces RA device type
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: db (binding L646).  The call must sit at or after L647; the earliest consumer of
// the export is L3700, so at or before L3699.  L3520 satisfies both.
//
// relative requires: none

module.exports = ({ db }) => {
async function requireRemoteAssistDevice(req, res, next) {
  try {
    const row = (await db.prepare("SELECT platform, agent_kind FROM devices WHERE id=?").get(req.params.id));
    if (!row || row.agent_kind !== 'remote_assist' || (row.platform !== 'windows' && row.platform !== 'linux'))
      return res.status(404).json({ error: 'Not a SentinelRemoteAssist device' });
    req.raPlatform = row.platform;
    next();
  } catch (e) { next(e); }
}

  return {
    requireRemoteAssistDevice,
  };
};