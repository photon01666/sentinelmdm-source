// helpers/hwid-key.js — the HMAC key for the hardware-serial searchable index.
//
// A HELPER module, not a route module: it registers nothing. Sole consumer:
// helpers/hwid-hmac.js (via its wiring). Extracted DEP-FIRST (D1b R2) so its
// binding can be created ABOVE hwidHmac's eager consumer (the register route
// wiring, L2522) — the original const sat at L2665, below that consumer.
//
//   HWID_KEY          export   readSecret('sentinel_hwid_key', ...)
//   HWID_KEY_LEGACY   export   optional readSecret('sentinel_hwid_key_legacy', ...)
//
// The current key is REQUIRED. There is no hardcoded fallback: a missing key is a
// startup error, not a silent public default. HWID_KEY_LEGACY exists only for a
// rolling migration so rows written before the rotation remain findable; new rows
// are always written with HWID_KEY.
//
// Stable dep by value: readSecret (const, L36) — declared above any position.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ readSecret }) => {

const HWID_KEY = (readSecret('sentinel_hwid_key', 'HWID_KEY') || '').trim();
const HWID_KEY_LEGACY = (readSecret('sentinel_hwid_key_legacy', 'HWID_KEY_LEGACY') || '').trim();

if (!HWID_KEY) {
  throw new Error(
    'FATAL: sentinel_hwid_key is not set. Create the Docker secret sentinel_hwid_key ' +
    '(or set HWID_KEY) before starting the server.'
  );
}
if (HWID_KEY_LEGACY && HWID_KEY_LEGACY === HWID_KEY) {
  console.warn('HWID_KEY_LEGACY matches HWID_KEY — ignoring the duplicate legacy key.');
  return { HWID_KEY, HWID_KEY_LEGACY: '' };
}

return { HWID_KEY, HWID_KEY_LEGACY };

};
