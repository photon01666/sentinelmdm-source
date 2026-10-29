// helpers/stripe-subscription.js - reading and writing a user's Stripe subscription state.
//
// A HELPER module, not a route module: it registers nothing. It exists to serve the billing,
// ownership-lifecycle, account-wipe and Stripe-webhook routes, all of which receive these as
// ctx deps.
//
//   stripeSubOut               export   row -> API-safe shape (null-safe)
//   sessionUserEmail           export   the email to bill, from a session row
//   getUserSubscriptionRow     export   the user's current subscription row
//   upsertStripeSubscription   export   insert-or-update a user's subscription state
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// Only `decryptText` is a `function` declaration and hoists; the other ten are `const`
// bindings all above L2826 (the price/plan tables at L2678-L2770, plus `db` at L723).
// The lowest is PLAN_KEY_BY_PRICE at L2770, so the call must sit at or after L2771 —
// and the earliest consumer of the exports is L2896, so at or before L2895. L2826
// satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ HYBRID_EXTRA_DEVICE_ANNUAL_PRICE, HYBRID_EXTRA_DEVICE_PRICE, HYBRID_LEGACY9_EXTRA_DEVICE_PRICE, HYBRID_LEGACY_EXTRA_DEVICE_PRICE, PLAN_KEY_BY_PRICE, PLAN_META, THREE_DEVICE_EXTRA_PRICE, UNLIMITED_EXTRA_DEVICE_ANNUAL_PRICE, UNLIMITED_EXTRA_DEVICE_PRICE, db, decryptText }) => {
function stripeSubOut(row) {
  if (!row) return null;
  const m = /** @type {any} */ (PLAN_META[row.price_id] || {});
  return { status: row.status, price_id: row.price_id,
           plan_key: PLAN_KEY_BY_PRICE[row.price_id] || null,
           plan_label: m.label || null, amount: m.amount || null, interval: m.interval || null,
           trial_end: row.trial_end, current_period_end: row.current_period_end,
           cancel_at_period_end: !!row.cancel_at_period_end };
}
async function sessionUserEmail(req) {
  try { const u = (await db.prepare('SELECT email FROM users WHERE id=?').get(req.session.userId));
        return u ? String(decryptText(u.email) || '').toLowerCase() : ''; } catch { return ''; }
}
async function getUserSubscriptionRow(req) {
  let row = (await db.prepare('SELECT * FROM subscriptions WHERE user_id=? ORDER BY created_at DESC LIMIT 1').get(req.session.userId));
  if (!row) { const e = (await sessionUserEmail(req)); if (e) row = (await db.prepare('SELECT * FROM subscriptions WHERE LOWER(email)=? AND (user_id IS NULL OR user_id=?) ORDER BY created_at DESC LIMIT 1').get(e, req.session.userId)); }
  return row;
}
async function upsertStripeSubscription(sub, email, userId = null) {
  const now = Date.now();
  const customer = typeof sub.customer === 'string' ? sub.customer : (sub.customer && sub.customer.id) || null;
  const priceId  = sub.items && sub.items.data && sub.items.data[0] && sub.items.data[0].price ? sub.items.data[0].price.id : null;
  const trialEnd = sub.trial_end ? sub.trial_end * 1000 : null;
  const cpe      = sub.current_period_end ? sub.current_period_end * 1000 : null;
  const cancel   = sub.cancel_at_period_end ? 1 : 0;
  const em       = email ? String(email).toLowerCase() : null;
  // user_id is set when a checkout was started from the logged-in dashboard (via
  // client_reference_id / subscription metadata). COALESCE so it's never wiped once bound.
  const uid      = Number.isInteger(userId) ? userId : null;
  if ((await db.prepare('SELECT id FROM subscriptions WHERE stripe_subscription_id=?').get(sub.id))) {
    (await db.prepare(`UPDATE subscriptions SET email=COALESCE(?,email), user_id=COALESCE(?,user_id), stripe_customer_id=?, status=?, price_id=?, trial_end=?, current_period_end=?, cancel_at_period_end=?, updated_at=? WHERE stripe_subscription_id=?`)
      .run(em, uid, customer, sub.status, priceId, trialEnd, cpe, cancel, now, sub.id));
  } else {
    (await db.prepare(`INSERT INTO subscriptions (email,user_id,stripe_customer_id,stripe_subscription_id,status,price_id,trial_end,current_period_end,cancel_at_period_end,created_at,updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`)
      .run(em, uid, customer, sub.id, sub.status, priceId, trialEnd, cpe, cancel, now, now));
  }
  // Mirror extra-device add-on quantities (source of truth = the Stripe subscription's line
  // items) into the settings table so deviceLimitForUser / the subscription panel can resolve
  // them without a Stripe round-trip. Runs for checkout/subscription webhooks and the dashboard
  // slot-change flow alike; removes the entry when the add-on is gone. Hybrid Managed, Per
  // Device and 5 Devices each have their own add-on price id(s) + settings key.
  const boundUid = Number.isInteger(uid) ? uid
    : (em ? (await db.prepare('SELECT user_id FROM subscriptions WHERE stripe_subscription_id=?').get(sub.id))?.user_id : null);
  const HYBRID_ADDON_IDS = new Set([HYBRID_EXTRA_DEVICE_PRICE, HYBRID_EXTRA_DEVICE_ANNUAL_PRICE,
                                    HYBRID_LEGACY_EXTRA_DEVICE_PRICE, HYBRID_LEGACY9_EXTRA_DEVICE_PRICE].filter(Boolean));
  const UNLIMITED_ADDON_IDS = new Set([UNLIMITED_EXTRA_DEVICE_PRICE, UNLIMITED_EXTRA_DEVICE_ANNUAL_PRICE].filter(Boolean));
  if (Number.isInteger(boundUid)) {
    let hybridExtra = 0, threeExtra = 0, unlimitedExtra = 0;
    for (const it of (sub.items && sub.items.data) || []) {
      if (!it.price || !Number.isFinite(Number(it.quantity))) continue;
      const qty = Math.floor(Number(it.quantity));
      if (HYBRID_ADDON_IDS.has(it.price.id))
        hybridExtra = Math.max(hybridExtra, qty);
      else if (UNLIMITED_ADDON_IDS.has(it.price.id))
        unlimitedExtra = Math.max(unlimitedExtra, qty);
      else if (it.price.id === THREE_DEVICE_EXTRA_PRICE)
        threeExtra = Math.max(threeExtra, qty);
    }
    for (const [prefix, n] of [['hybrid_extra_devices', hybridExtra], ['three_extra_devices', threeExtra],
                               ['unlimited_extra_devices', unlimitedExtra]]) {
      const key = `${prefix}:${boundUid}`;
      if (n > 0)
        (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(key, String(n)));
      else
        (await db.prepare("DELETE FROM settings WHERE key=?").run(key));
    }
  }
}

  return {
    getUserSubscriptionRow,
    sessionUserEmail,
    stripeSubOut,
    upsertStripeSubscription,
  };
};
