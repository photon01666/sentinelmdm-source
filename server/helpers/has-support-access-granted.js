// helpers/has-support-access-granted.js — check if support access has been granted.
//
// A HELPER module, not a route module: it registers nothing.
//
//   hasSupportAccessGranted   export   check if a user has granted support access
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: db (binding L646).  The call must sit at or after L647; the earliest consumer of
// the export is L3107, so at or before L3106.  L2516 satisfies both.
//
// relative requires: none

module.exports = ({ db }) => {
// Hybrid Managed requires "Grant support access" (see the support-access endpoints below) to be
// set up BEFORE the account can subscribe — the security/monitoring escalation service this tier
// sells is only deliverable once support can actually reach the account's devices. Enforced here,
// server-side, so it can't be bypassed by calling the checkout API directly (a UI-only gate would
// only stop the button, not a raw POST). Checked against parent_owner_id, same scoping as every
// other support-access/team query.
async function hasSupportAccessGranted(ownerUserId) {
  if (!ownerUserId) return false;
  const row = (await db.prepare('SELECT id FROM users WHERE parent_owner_id=? AND is_support_delegate=1').get(ownerUserId));
  return !!row;
}

  return {
    hasSupportAccessGranted,
  };
};