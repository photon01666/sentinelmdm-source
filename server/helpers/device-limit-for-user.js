// helpers/device-limit-for-user.js — device limit per user by plan.
//
// A HELPER module, not a route module: it registers nothing.
//
//   deviceLimitForUser   export   get max devices a user may own by plan
//
// RELOCATE: wiring line must sit at/after L2874 and at/before L3128 — placed at L3128.
// 14 deps: HYBRID_FLAT_LEGACY_PRICES (binding L2343), HYBRID_INCLUDED_DEVICES (binding L2317),
// PLAN_KEY_BY_PRICE (binding L2394), TRIAL_DEVICE_LIMIT (binding L2279),
// UNLIMITED_FLAT_LEGACY_PRICES (binding L2350), UNLIMITED_INCLUDED_DEVICES (binding L2323),
// compPlanFor (destructure L2873), compSlotRow (destructure L2404), db (binding L625),
// decryptText (function L163, hoisted), hybridExtraDevices (destructure L2404),
// slotRowCount (destructure L2404), threeDeviceExtraDevices (destructure L2404),
// unlimitedExtraDevices (destructure L2404).
//
// relative requires: none

module.exports = ({ HYBRID_FLAT_LEGACY_PRICES, HYBRID_INCLUDED_DEVICES, PLAN_KEY_BY_PRICE, TRIAL_DEVICE_LIMIT, UNLIMITED_FLAT_LEGACY_PRICES, UNLIMITED_INCLUDED_DEVICES, compPlanFor, compSlotRow, db, decryptText, hybridExtraDevices, slotRowCount, threeDeviceExtraDevices, unlimitedExtraDevices }) => {
// Max devices a PUBLIC (FamilySafe) account may own, by plan: unlimited_* → Infinity (no cap);
// 1device_* → 5 + any extra device slots bought ($5/mo each, stored via
// threeDeviceExtraDevices); hybrid_* → Infinity (unlimited devices included). Mirrors
// userHasActiveSubscription's lookup (by user_id, then email fallback). Used to gate
// enrollment-ticket issuance.
async function deviceLimitForUser(userRow) {
  if (!userRow) return 1;
  const comp = (await compPlanFor(userRow));                          // admin comp overrides Stripe state
  if (comp) {
    // Per-device comps (crypto-paid) store their purchased device count in crypto_slots:{id};
    // admin-granted comps have no such row → unlimited.
    if (comp === 'unlimited' || comp === 'hybrid') {
      const srow = (await compSlotRow(userRow.id, 'crypto_slots'));
      return srow ? 1 + slotRowCount(srow) : Infinity;
    }
    // Comp caps mirror the equivalent live-subscription tier INCLUDING any addon slots bought
    // while the account was on that Stripe plan (three_extra_devices rows).
    return 5 + (await threeDeviceExtraDevices(userRow.id));
  }
  let row = (await db.prepare("SELECT status, price_id FROM subscriptions WHERE user_id=? ORDER BY created_at DESC LIMIT 1").get(userRow.id));
  if (!row) {
    const em = String(decryptText(userRow.email) || '').toLowerCase();
    if (em) row = (await db.prepare("SELECT status, price_id FROM subscriptions WHERE LOWER(email)=? ORDER BY created_at DESC LIMIT 1").get(em));
  }
  const live = !!row && ['trialing', 'active', 'past_due'].includes(row.status);
  const planKey = live ? PLAN_KEY_BY_PRICE[row.price_id] : null;
  // Per-device billing: base price covers the included devices; extra add-on line items add slots.
  // Legacy FLAT subscribers keep their original caps (flat Hybrid/Unlimited = no cap).
  if (planKey && planKey.startsWith('hybrid'))
    return HYBRID_FLAT_LEGACY_PRICES.has(row.price_id) ? Infinity
         : HYBRID_INCLUDED_DEVICES + (await hybridExtraDevices(userRow.id));
  if (planKey && planKey.startsWith('unlimited'))
    return UNLIMITED_FLAT_LEGACY_PRICES.has(row.price_id) ? Infinity
         : UNLIMITED_INCLUDED_DEVICES + (await unlimitedExtraDevices(userRow.id));
  if (planKey && planKey.startsWith('1device'))  return 5 + (await threeDeviceExtraDevices(userRow.id));
  return TRIAL_DEVICE_LIMIT;                                             // Free trial / no live paid sub (10)
}

  return {
    deviceLimitForUser,
  };
};