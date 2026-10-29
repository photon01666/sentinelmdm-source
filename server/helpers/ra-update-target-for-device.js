// helpers/ra-update-target-for-device.js — resolve RA update target.
//
// A HELPER module, not a route module: it registers nothing.
//
//   raUpdateTargetForDevice   export   resolve account+adminAgent for RA update
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: db (binding L646).  The call must sit at or after L647; the earliest consumer of
// the export is L3673, so at or before L3672.  L3660 satisfies both.
//
// relative requires: none

module.exports = ({ db }) => {
// Resolves the (account_id, admin_agent) pair bastion needs to rebuild+push the right account-
// linked exe variant for a device — derived from the OWNING account, never the caller's own
// session, since an admin pushing an update still targets the device's real owner's build.
async function raUpdateTargetForDevice(deviceId) {
  const row = (await db.prepare(
    "SELECT d.owner_user_id, u.account_type FROM devices d LEFT JOIN users u ON d.owner_user_id=u.id WHERE d.id=?"
  ).get(deviceId));
  if (!row?.owner_user_id) return null;
  const adminAgent = row.account_type === 'admin' || row.account_type === 'admin_created';
  return { accountId: row.owner_user_id, adminAgent };
}

  return {
    raUpdateTargetForDevice,
  };
};