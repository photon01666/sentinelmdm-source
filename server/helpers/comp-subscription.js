// helpers/comp-subscription.js — admin comp subscription helpers.
//
// A HELPER module, not a route module: it registers nothing.
//
//   compPlanFor, compSubInfo, userHasActiveSubscription   members
//
// RELOCATE: wiring line must sit at/after L2413 and at/before L2882 — placed at L2882.
// 3 deps: COMP_PLAN_LABEL (binding L2412), db (binding L625), decryptText (function L163, hoisted).
//
// relative requires: none

module.exports = ({ COMP_PLAN_LABEL, db, decryptText }) => {
// Admin-granted complimentary ("comp") subscription — a FREE override that makes a public account
// behave as if it holds a live paid plan (exempt from the trial lock + 48h auto-wipe; device cap
// follows the comp plan). Stored on the users row (NOT in `subscriptions`) so a Stripe webhook can
// never clobber it, and it takes priority over real billing state. Accepts a user ROW (uses its
// comp_* fields when loaded, else re-reads by id) or a bare userId. Returns the ACTIVE comp plan
// key ('unlimited' | '1device') or null (none / expired).
async function compPlanFor(userRowOrId) {
  let plan, exp;
  if (userRowOrId && typeof userRowOrId === 'object' && 'comp_plan' in userRowOrId) {
    plan = userRowOrId.comp_plan; exp = userRowOrId.comp_expires_at;
  } else {
    const id = (userRowOrId && typeof userRowOrId === 'object') ? userRowOrId.id : userRowOrId;
    if (id == null) return null;
    const r = (await db.prepare('SELECT comp_plan, comp_expires_at FROM users WHERE id=?').get(id));
    if (!r) return null;
    plan = r.comp_plan; exp = r.comp_expires_at;
  }
  if (!plan) return null;
  if (exp != null && Number(exp) <= Date.now()) return null;          // lapsed comp → no longer active
  return String(plan);
}
// Display view of an active comp for a user id (for /api/subscription + /api/users). null = none.
async function compSubInfo(userId) {
  const plan = (await compPlanFor(userId));
  if (!plan) return null;
  const r = (await db.prepare('SELECT comp_expires_at FROM users WHERE id=?').get(userId));
  return { plan, label: COMP_PLAN_LABEL[plan] || plan, expires_at: (r && r.comp_expires_at) || null };
}
// True if the user has a live Stripe subscription (trialing/active/past_due) — matched by user_id
// first, then by account email (covers webhook rows not yet linked to the id) — OR an admin comp.
// A subscribed (or comped) user is exempt from trial lock/wipe.
async function userHasActiveSubscription(userRow) {
  if (!userRow) return false;
  if ((await compPlanFor(userRow))) return true;                      // admin comp = treated as subscribed
  let row = (await db.prepare("SELECT status FROM subscriptions WHERE user_id=? ORDER BY created_at DESC LIMIT 1").get(userRow.id));
  if (!row) {
    const em = String(decryptText(userRow.email) || '').toLowerCase();
    if (em) row = (await db.prepare("SELECT status FROM subscriptions WHERE LOWER(email)=? ORDER BY created_at DESC LIMIT 1").get(em));
  }
  return !!row && ['trialing', 'active', 'past_due'].includes(row.status);
}

  return {
    compPlanFor,
    compSubInfo,
    userHasActiveSubscription,
  };
};