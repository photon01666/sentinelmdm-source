// helpers/extra-device-slots.js — extra-device-slot / comp-slot helpers.
//
// A HELPER module, not a route module: it registers nothing.
//
//   compSlotRow                  export   Raw settings row for a comp account's device slots
//   hybridExtraDevices           export   Extra device slots for Hybrid Managed subscriptions
//   slotRowCount                 export   Parse a slot row's value (clamped, 0 if absent/bad)
//   threeDeviceExtraDevices      export   Extra device slots for the 5 Devices plan
//   unlimitedExtraDevices        export   Extra device slots for the Per Device plan
//
// These helpers handle the per-user extra-device-slot counts that live in the `settings` table,
// mirrored from Stripe subscription add-on line-item quantities. They are read by
// deviceLimitForUser and the subscription panel.
//
// 1 ctx dep: db (binding L699).  The require call must sit at or after L700; the earliest
// consumer of the exports is L3272, so at or before L3271.
//
// relative requires: none

module.exports = ({ db }) => {
// Extra device slots bought on a Hybrid Managed subscription (beyond HYBRID_INCLUDED_DEVICES).
// Mirrored from the Stripe subscription's add-on line-item quantity by upsertStripeSubscription
// (the source of truth); read by deviceLimitForUser / the subscription panel.
async function hybridExtraDevices(userId) {
  if (!Number.isInteger(userId)) return 0;
  const row = (await db.prepare('SELECT value FROM settings WHERE key=?').get(`hybrid_extra_devices:${userId}`));
  const n = parseInt(row && row.value, 10);
  return (Number.isFinite(n) && n > 0) ? Math.min(n, 1000) : 0;
}
// Same for the Per Device plan ($3.00/mo per slot over the 1 included).
async function unlimitedExtraDevices(userId) {
  if (!Number.isInteger(userId)) return 0;
  const row = (await db.prepare('SELECT value FROM settings WHERE key=?').get(`unlimited_extra_devices:${userId}`));
  const n = parseInt(row && row.value, 10);
  return (Number.isFinite(n) && n > 0) ? Math.min(n, 1000) : 0;
}
// Same for the 5 Devices plan ($5.00/mo per slot over the 5 included).
async function threeDeviceExtraDevices(userId) {
  if (!Number.isInteger(userId)) return 0;
  const row = (await db.prepare('SELECT value FROM settings WHERE key=?').get(`three_extra_devices:${userId}`));
  const n = parseInt(row && row.value, 10);
  return (Number.isFinite(n) && n > 0) ? Math.min(n, 1000) : 0;
}
// Raw settings row for a comp account's device slots (crypto-paid comps store their purchased
// device count here; admin-granted comps have no row = unlimited). Returns null when absent so
// callers can distinguish "no row (unlimited)" from "row = 0 (1 device)".
async function compSlotRow(userId, prefix) {
  if (!Number.isInteger(userId)) return null;
  return (await db.prepare('SELECT value FROM settings WHERE key=?').get(`${prefix}:${userId}`)) || null;
}
function slotRowCount(row) {
  const n = parseInt(row && row.value, 10);
  return (Number.isFinite(n) && n > 0) ? Math.min(n, 1000) : 0;
}

  return { compSlotRow, hybridExtraDevices, slotRowCount, threeDeviceExtraDevices, unlimitedExtraDevices };
};
