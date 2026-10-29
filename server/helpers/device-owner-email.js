// helpers/device-owner-email.js — owner email for device-scoped alerts.
//
// A HELPER module, not a route module: it registers nothing.
//
//   deviceOwnerEmail   export   get the owner's email for a device
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 3 deps: db (binding L646), decryptText (function L162, hoisted), deviceOwnerInfo (function L2943, hoisted).  The call must sit at or after L647; the earliest consumer of
// the export is L7223, so at or before L7222.  L2953 satisfies both.
//
// relative requires: none

module.exports = ({ db, decryptText, deviceOwnerInfo }) => {
// Owner account email for device-scoped admin alerts — lets the admin/hybrid Signal feed
// identify WHOSE device an alert is about. Public/hybrid accounts only; admin-fleet/unowned
// devices → null (message stays as-is). Null also on decrypt failure (raw ENC: ciphertext is
// never surfaced — that would be a clue leak to the wrong channel).
async function deviceOwnerEmail(deviceId) {
  try {
    const { ownerUserId } = (await deviceOwnerInfo(deviceId));
    if (!ownerUserId) return null;
    const row = (await db.prepare('SELECT email FROM users WHERE id=?').get(ownerUserId));
    if (!row?.email) return null;
    const em = String(decryptText(row.email) || '');
    if (!em || em.startsWith('ENC:')) return null;
    return em;
  } catch { return null; }
}

  return {
    deviceOwnerEmail,
  };
};