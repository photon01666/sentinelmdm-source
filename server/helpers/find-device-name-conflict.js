// helpers/find-device-name-conflict.js — rename conflict check.
//
// A HELPER module, not a route module: it registers nothing.
//
//   findDeviceNameConflict   export   check for device name conflicts
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 2 deps: db (binding L646), decryptText (function L162, hoisted).  The call must sit at or after L647; the earliest consumer of
// the export is L3380, so at or before L3379.  L3328 satisfies both.
//
// relative requires: none

module.exports = ({ db, decryptText }) => {
// Rename conflict check — scoped to devices the SAME requester can see, mirroring
// requireDeviceAccess's own visibility model (admin=fleet-wide, public/business_sub=their own
// devices only). Deliberately NOT a global uniqueness check across every account on the
// platform — that would leak one customer's device names to another via a 409 response, and
// "two devices YOU manage both named X" is the actual mistake this guards against, not
// "someone else, somewhere, already picked this name". Full-table decrypt-and-compare is fine
// at this fleet size (no index needed) — same cost class as the EDR poller's per-device decrypt.
async function findDeviceNameConflict(name, excludeDeviceId, req) {
  let rows;
  if (req.session?.role === 'admin') {
    rows = (await db.prepare('SELECT id, name FROM devices WHERE id<>?').all(excludeDeviceId));
  } else if (req.session?.account_type === 'public') {
    rows = (await db.prepare('SELECT id, name FROM devices WHERE owner_user_id=? AND id<>?').all(req.session.userId, excludeDeviceId));
  } else if (req.session?.account_type === 'business_sub') {
    rows = (await db.prepare('SELECT id, name FROM devices WHERE owner_user_id=? AND id<>?').all(req.session.parent_owner_id, excludeDeviceId));
  } else {
    return null;
  }
  const target = name.trim().toLowerCase();
  for (const row of rows) {
    const existing = (row.name && !String(row.name).startsWith('ENC:')) ? row.name : (decryptText(row.name) || '');
    if (existing.trim().toLowerCase() === target) return row.id;
  }
  return null;
}

  return {
    findDeviceNameConflict,
  };
};