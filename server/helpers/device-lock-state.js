// helpers/device-lock-state.js — device lock state lookup.
//
// A HELPER module, not a route module: it registers nothing.
//
//   deviceLockState, isDeviceLocked   members
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 3 deps: decryptText (function L162, hoisted), normIdent (binding L3296), stmts (destructure L2060).  The call must sit at or after L3297; the earliest consumer of
// the export is L3395, so at or before L3394.  L3304 satisfies both.
//
// relative requires: none

module.exports = ({ decryptText, normIdent, stmts }) => {
// Lock state for a device. See the schema comment for the state table.
//   UNLOCKED                  — not a locked public-user device (no new rules apply)
//   ACTIVE                    — welded to ownerUserId; fully immutable
//   RELEASED_PENDING_IDENTITY — account wiped; only a NEW same-email account may rebind
async function deviceLockState(deviceId) {
  const row = (await stmts.getDeviceLock.get(deviceId));
  if (!row || !row.locked_identity_email)
    return { state: 'UNLOCKED', ownerUserId: row?.owner_user_id || null, identityEmail: null };
  const identityEmail = normIdent(decryptText(row.locked_identity_email));
  return {
    state: row.owner_user_id ? 'ACTIVE' : 'RELEASED_PENDING_IDENTITY',
    ownerUserId: row.owner_user_id || null,
    identityEmail,
  };
}
const isDeviceLocked = async deviceId => !!(await stmts.getDeviceLock.get(deviceId))?.locked_identity_email;

  return {
    deviceLockState,
    isDeviceLocked,
  };
};