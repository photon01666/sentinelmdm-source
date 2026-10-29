// helpers/invalid-plan-message.js — friendly 400 message for missing Stripe price.
//
// A HELPER module, not a route module: it registers nothing.
//
//   invalidPlanMessage   export   user-facing error message for an invalid plan
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 0 deps.  The call must sit at or after L1; the earliest consumer of
// the export is L3115, so at or before L3114.  L2514 satisfies both.
//
// relative requires: none

module.exports = () => {
// Friendlier 400 message when a plan key resolves but its Stripe price id hasn't been created yet
// (currently only possible for hybrid_* — see the STRIPE_PLANS comment above). Card checkout for
// such a plan is correctly rejected before ever calling Stripe; crypto (CRYPTO_PLAN_PRICES) still works.
function invalidPlanMessage(plan) {
  return String(plan || '').startsWith('hybrid')
    ? 'Hybrid Managed requires support access first — grant it, then subscribe from your dashboard.'
    : 'Invalid plan selected';
}

  return {
    invalidPlanMessage,
  };
};