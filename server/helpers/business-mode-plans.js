// helpers/business-mode-plans.js — plans that qualify an account for Business mode.
//
// A HELPER module, not a route module: it registers nothing. Sole consumer:
// helpers/business-mode.js (via its wiring). Extracted DEP-FIRST (D1b R2) so its
// binding can be created ABOVE businessMode's eager consumer (the device-access
// wiring, L2483) — the original const sat at L3435, below that consumer.
//
//   BUSINESS_MODE_QUALIFYING_PLANS   export   annual/unlimited/hybrid plan keys
//
// No ctx deps. No relative require to rebase.

module.exports = () => {

const BUSINESS_MODE_QUALIFYING_PLANS = new Set(['1device_annual', 'unlimited_monthly', 'unlimited_annual', 'hybrid_monthly', 'hybrid_annual']);

return { BUSINESS_MODE_QUALIFYING_PLANS };

};
