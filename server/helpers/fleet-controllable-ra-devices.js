// helpers/fleet-controllable-ra-devices.js — fleet-controllable RA device IDs.
//
// A HELPER module, not a route module: it registers nothing.
//
//   fleetControllableRemoteAssistDeviceIds   export   get controllable RA device IDs for fleet ops
//
// RELOCATE: wiring line must sit at/after L628 and at/before L3460 — placed at L3460.
// 3 deps: db (binding L625), deviceOwnerInfo (destructure L627), groupOwnerKey (function L3921, hoisted).
//
// relative requires: none

module.exports = ({ db, deviceOwnerInfo, groupOwnerKey }) => {
// groupId (optional) scopes the fleet action to one of the caller's own sidebar device groups
// (device_groups/ui_group_id — see "Sidebar device groups" below) instead of every controllable
// device. Reuses groupOwnerKey() (defined further down, hoisted — function declarations are
// visible throughout the module regardless of source order) so a group id can only ever resolve
// to a group the caller themselves created; an unknown or someone-else's group id fails safe to
// an empty device list rather than 403ing or silently falling back to "all devices".
async function fleetControllableRemoteAssistDeviceIds(req, groupId) {
  if (groupId) {
    const owner = groupOwnerKey(req);
    const g = owner && (await db.prepare('SELECT id FROM device_groups WHERE id=? AND owner_key=?').get(groupId, owner));
    if (!g) return [];
  }
  const rows = groupId
    ? await db.prepare("SELECT id, name FROM devices WHERE platform='windows' AND agent_kind='remote_assist' AND ui_group_id=?").all(groupId)
    : await db.prepare("SELECT id, name FROM devices WHERE platform='windows' AND agent_kind='remote_assist'").all();
  const out = [];
  const isAdmin = req.session?.role === 'admin';
  for (const row of rows) {
    const { isZk, ownerUserId } = (await deviceOwnerInfo(row.id));
    if (isZk) {
      // ZK devices are controllable ONLY by their owning public user (or that owner's business
      // sub-users) — an admin session gets no bypass here, matching requireDeviceController().
      const isOwner = (req.session?.account_type === 'public' && req.session.userId === ownerUserId)
        || (req.session?.account_type === 'business_sub' && req.session.parent_owner_id === ownerUserId);
      if (!isOwner) continue;
    } else if (!isAdmin) {
      // Non-ZK = admin-fleet device — only an admin session may act on it, even in fleet mode.
      // Without this, a public/business_sub caller's fleet action would silently also sweep in
      // every admin-fleet Windows device, which isn't theirs and isn't ZK-gated to catch it.
      continue;
    }
    out.push(row);
  }
  return out;
}

  return {
    fleetControllableRemoteAssistDeviceIds,
  };
};