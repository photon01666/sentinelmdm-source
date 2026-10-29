// helpers/business-mode.js — Business-mode eligibility + trial lock state.
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// device-access (trialLockState) and user-management (businessModeQualifies)
// route wirings, plus trialInfo's body — all BELOW the wiring line.
//
//   businessModeQualifies   export   annual/unlimited/hybrid plan or live trial
//   trialLockState          export   locked once the trial expired with no sub
//
// Wiring RELOCATED above its earliest eager consumer (device-access wiring,
// L2483) via D1b R2 (dep-first) + R1. Deps:
//   * BUSINESS_MODE_QUALIFYING_PLANS — stable const from
//     helpers/business-mode-plans.js, wired above this line.
//   * PLAN_KEY_BY_PRICE (L2187-era) / TRIAL_WIPE_GRACE_MS — stable consts above.
//   * compPlanFor / userHasActiveSubscription — from the comp-subscription wiring,
//     RELOCATED above this line (D1b R2 wiring move).
//   * trialInfo — hoisted function declaration (still inline at this point), so
//     usable from any line; captured by value.
//   * db travels as the LIVE getter `getDb: () => db` (reads rewritten to
//     `getDb().prepare`). decryptText (L133) by value.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ BUSINESS_MODE_QUALIFYING_PLANS, PLAN_KEY_BY_PRICE, TRIAL_WIPE_GRACE_MS, compPlanFor, decryptText, getDb, trialInfo, userHasActiveSubscription }) => {

async function businessModeQualifies(userRow) {
  if (!userRow) return false;
  const comp = (await compPlanFor(userRow));
  if (comp === 'unlimited' || comp === 'hybrid') return true;
  const t = trialInfo(userRow);
  if (t && t.state !== 'expired') return true;                          // pending or active trial
  let row = (await getDb().prepare("SELECT status, price_id FROM subscriptions WHERE user_id=? ORDER BY created_at DESC LIMIT 1").get(userRow.id));
  if (!row) {
    const em = String(decryptText(userRow.email) || '').toLowerCase();
    if (em) row = (await getDb().prepare("SELECT status, price_id FROM subscriptions WHERE LOWER(email)=? ORDER BY created_at DESC LIMIT 1").get(em));
  }
  const live = !!row && ['trialing', 'active', 'past_due'].includes(row.status);
  if (!live) return false;
  const planKey = PLAN_KEY_BY_PRICE[row.price_id];
  return !!planKey && BUSINESS_MODE_QUALIFYING_PLANS.has(planKey);
}
// Trial lock state for a user id: locked once the trial has EXPIRED and there's no live subscription.
// While locked, device data is paused (see requireDeviceAccess) and the account is wiped at wipe_at.
async function trialLockState(userId) {
  const u = (await getDb().prepare('SELECT id, email, trial_enabled, trial_started_at FROM users WHERE id=?').get(userId));
  if (!u) return { locked: false, wipe_at: null };
  const t = trialInfo(u);
  if (!t || t.state !== 'expired') return { locked: false, wipe_at: null };
  if ((await userHasActiveSubscription(u))) return { locked: false, wipe_at: null };
  return { locked: true, wipe_at: t.deadline + TRIAL_WIPE_GRACE_MS };
}

return { businessModeQualifies, trialLockState };

};
