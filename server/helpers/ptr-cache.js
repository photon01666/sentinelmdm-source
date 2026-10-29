// helpers/ptr-cache.js — reverse-DNS PTR cache + TTLs.
//
// A HELPER module, not a route module: it registers nothing. Extracted DEP-FIRST
// (D1b R2) so its bindings can be created ABOVE the phish-intel run's eager
// consumer (the phish-lookup wiring, L4491) — the originals sat at L4502-L4504,
// below it. Sole consumer: helpers/phish-intel-lookups.js (wired below).
//
//   _ptrCache          export   Map (ip -> { name, at }), mutated by reference
//   PTR_CACHE_TTL_MS   export   positive-result TTL
//   PTR_CACHE_MAX      export   size cap before a full clear
//
// No ctx deps. No relative require to rebase.

module.exports = () => {

const _ptrCache = new Map(); // ip -> { name, at }
const PTR_CACHE_TTL_MS = 6 * 3600 * 1000;
const PTR_CACHE_MAX = 2000;

return { PTR_CACHE_MAX, PTR_CACHE_TTL_MS, _ptrCache };

};
