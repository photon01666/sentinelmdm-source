// helpers/hwid-hmac.js — deterministic keyed index over the hardware serial.
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// register / flash / admin-commerce route wirings (all below the wiring line).
//
//   hwidHmac            export   HMAC-SHA256(serial.trim().toLowerCase()) with the current key
//   hwidHmacLegacy      export   same with the optional legacy key (migration lookups only)
//   hwidHmacCandidates  export   [current, legacy?] — de-duplicated, current first
//
// Wiring RELOCATED above its earliest eager consumer (register route wiring,
// L2522) via D1b R2 (dep-first: helpers/hwid-key.js) + R1. Deps:
//   * HWID_KEY / HWID_KEY_LEGACY — stable consts from helpers/hwid-key.js.
//   * crypto (L15) — ctx-injected by value (scanner blind spot).
//
// New records must always use hwidHmac() (the current key). hwidHmacCandidates()
// is only for READS during the rotation window so old rows remain findable.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ HWID_KEY, HWID_KEY_LEGACY, crypto }) => {

function hwidHmac(serial) {
  return crypto.createHmac('sha256', HWID_KEY)
    .update(String(serial).trim().toLowerCase()).digest('hex');
}

function hwidHmacLegacy(serial) {
  if (!HWID_KEY_LEGACY) return null;
  return crypto.createHmac('sha256', HWID_KEY_LEGACY)
    .update(String(serial).trim().toLowerCase()).digest('hex');
}

function hwidHmacCandidates(serial) {
  const current = hwidHmac(serial);
  const legacy = hwidHmacLegacy(serial);
  return legacy && legacy !== current ? [current, legacy] : [current];
}

return { hwidHmac, hwidHmacLegacy, hwidHmacCandidates };

};
