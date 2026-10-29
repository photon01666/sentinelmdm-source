// helpers/device-owner-info.js — device ownership and ZK-control gate.
//
// A HELPER module, not a route module: it registers nothing.
//
//   deviceOwnerInfo   export   resolve device ownership and ZK status
//
// RELOCATE: wiring line must sit at/after L624 and at/before L651 — placed at L648.
// 1 dep: db (binding L623).
//
// relative requires: none

module.exports = ({ db }) => {
// ── Device ownership / ZK-control gate ─────────────────────────────────────
// A device owned by a public user (account_type='public') is ZK-private. Product rule:
// ONLY the owning public user (or their business sub-users, scoped via parent_owner_id + the
// permission map — see requireDeviceController/POST /command) may command/control it — admin
// is locked out. (The sole admin exception — OTA agent update — is handled inline in /command +
// the dedicated /update-apk route, which stays admin-allowed.)
async function deviceOwnerInfo(deviceId) {
  const row = (await db.prepare(
    "SELECT d.owner_user_id, d.locked_identity_email, d.lineage_kind, u.account_type, u.business_mode FROM devices d LEFT JOIN users u ON d.owner_user_id=u.id WHERE d.id=?"
  ).get(deviceId));
  // ZK/owner-only-control = a public owner OR a PUBLIC-kind lineage lock (incl. post-wipe orphan).
  // ADMIN-kind locked devices are admin-fleet: admin + permitted sub-users control them, NOT ZK.
  const isZk = row?.account_type === 'public' || (!!row?.locked_identity_email && row?.lineage_kind !== 'admin');
  return { isZk, ownerUserId: row?.owner_user_id ?? null, businessMode: !!row?.business_mode };
}

  return {
    deviceOwnerInfo,
  };
};