// helpers/group-owner-key.js — sidebar device group owner key resolution.
//
// A HELPER module, not a route module: it registers nothing.
//
//   groupOwnerKey   export   resolve the owner key for sidebar device groups
//
// RELOCATE: wiring line must sit at/after L1 and at/before L3459 — placed at L3459.
// 0 deps.
//
// relative requires: none

module.exports = () => {
// ── Sidebar device groups (WebUI organization only) ──────────────────────────
// Groups are PRIVATE to the user who creates them, scoped by owner_key:
//   • admin   → owner_key 'usr:<username>' (admin may have a null session.userId — see
//     the E2E-chat note); admin groups apply to admin-fleet devices only.
//   • public  → owner_key 'uid:<userId>'; a public user groups ONLY their own devices.
// Sub-users (admin_created) cannot create groups. A device's ui_group_id only ever points at
// a group owned by its controlling party, so the two parties never group the same device.
//   • business_sub → the fleet OWNER's key ('uid:<parent_owner_id>'). They own no groups of their
//     own; they READ the owner's grouping — same owner-resolution the /api/users/me/* alert routes
//     use, and the reason an admin impersonating a support delegate saw an ungrouped flat list.
//     Resolving the owner key here can NOT let them mutate the owner's groups: every write route
//     (POST/PATCH/DELETE /api/device-groups, PATCH /api/devices/:id/ui-group) sits behind
//     requireGroupManager, which admits only admin + public. Widen that gate and this becomes a
//     write path into the customer's layout — a separate consent decision, not a bug fix.
function groupOwnerKey(req) {
  const s = req.session || {};
  if (s.account_type === 'public' && s.userId != null) return 'uid:' + s.userId;
  if (s.account_type === 'business_sub' && s.parent_owner_id != null) return 'uid:' + s.parent_owner_id;
  if (s.role === 'admin') return s.userId != null ? 'uid:' + s.userId : (s.username ? 'usr:' + s.username : null);
  return null;
}

  return {
    groupOwnerKey,
  };
};