// helpers/wigle-miss-cache.js — WiGLE negative-result cache.
//
// A HELPER module, not a route module: it registers nothing. Extracted DEP-FIRST
// (D1b R2) so its binding can be created ABOVE loadKnownTowers's eager consumer
// (the cell-history wiring) — the original sat at L4437, below it. Sole consumer:
// the wigle-ocid-lookup wiring (wired below).
//
//   _wigleMissCache   export   Map (bssid -> retryAfter), mutated by reference
//                              from helpers/wigle-ocid-lookup.js
//
// No ctx deps. No relative require to rebase.

module.exports = () => {

const _wigleMissCache = new Map(); // bssid -> retryAfter timestamp

return { _wigleMissCache };

};
