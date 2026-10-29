// helpers/ocid-miss-cache.js — OpenCellID negative-result cache + TTLs.
//
// A HELPER module, not a route module: it registers nothing. Extracted DEP-FIRST
// (D1b R2) so its bindings can be created ABOVE loadKnownTowers's eager consumer
// (the cell-history wiring) — the originals sat at L4412-L4414, below it.
// Consumers: helpers/load-known-towers.js (_ocidMissCache) and the
// wigle-ocid-lookup wiring (all three), both wired below.
//
//   _ocidMissCache           export   Map (tower key -> retryAfter), mutated by
//                                     reference from the consumers
//   OCID_MISS_TTL_MS         export   definitive "not in OCID" TTL
//   OCID_TRANSIENT_TTL_MS    export   rate-limit/network failure TTL
//
// No ctx deps. No relative require to rebase.

module.exports = () => {

const _ocidMissCache = new Map(); // tower key -> retryAfter timestamp
const OCID_MISS_TTL_MS = 24 * 60 * 60 * 1000;   // definitive "not in OCID"
const OCID_TRANSIENT_TTL_MS = 5 * 60 * 1000;    // rate-limit / network failure

return { OCID_MISS_TTL_MS, OCID_TRANSIENT_TTL_MS, _ocidMissCache };

};
