// helpers/hwid-hmac.js — deterministic keyed index over the hardware serial.
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// register / flash / admin-commerce route wirings (all below the wiring line).
//
//   hwidHmac   export   HMAC-SHA256(serial.trim().toLowerCase()) as hex
//
// Wiring RELOCATED above its earliest eager consumer (register route wiring,
// L2522) via D1b R2 (dep-first: helpers/hwid-key.js) + R1. Deps:
//   * HWID_KEY — stable const from helpers/hwid-key.js, wired above this line.
//   * crypto (L15) — ctx-injected by value (scanner blind spot).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ HWID_KEY, crypto }) => {

function hwidHmac(serial) {
  return crypto.createHmac('sha256', HWID_KEY)
    .update(String(serial).trim().toLowerCase()).digest('hex');
}

return { hwidHmac };

};
