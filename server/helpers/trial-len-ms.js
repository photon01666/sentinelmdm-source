// helpers/trial-len-ms.js — per-account free-trial length in ms.
//
// A HELPER module, not a route module: it registers nothing. Consumers:
// helpers/trial-info.js, the admin-support-access route wiring, the trial-sweep
// wiring — all BELOW the wiring line. Extracted DEP-FIRST (D1b R2) so its
// binding can be created ABOVE trialInfo's eager consumer (the checkout route
// wiring, L2554) — the original const sat at L3422, below that consumer.
//
//   TRIAL_LEN_MS   export   TRIAL_DAYS_ACCOUNT * 24h in ms
//
// Stable dep by value: TRIAL_DAYS_ACCOUNT (L2044) — above any position.
//
// No relative require to rebase: the block contains none.

module.exports = ({ TRIAL_DAYS_ACCOUNT }) => {

const TRIAL_LEN_MS = TRIAL_DAYS_ACCOUNT * 24 * 3600 * 1000;   // per-account free-trial length (30d)

return { TRIAL_LEN_MS };

};
