// helpers/hwid-key.js — the HMAC key for the hardware-serial searchable index.
//
// A HELPER module, not a route module: it registers nothing. Sole consumer:
// helpers/hwid-hmac.js (via its wiring). Extracted DEP-FIRST (D1b R2) so its
// binding can be created ABOVE hwidHmac's eager consumer (the register route
// wiring, L2522) — the original const sat at L2665, below that consumer.
//
//   HWID_KEY   export   readSecret('sentinel_hwid_key', ...)
//
// Stable dep by value: readSecret (const, L36) — declared above any position.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ readSecret }) => {

const HWID_KEY = readSecret('sentinel_hwid_key', 'HWID_KEY', 'SentinelMDM-hwid-v1');

return { HWID_KEY };

};
