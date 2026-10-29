// helpers/support-presence.js — support presence (permanently online).
//
// A HELPER module, not a route module: it registers nothing.
//
//   getSupportPresence, setSupportPresence, cors   members
//
// RELOCATE: wiring line must sit at/after L1 and at/before L542 — placed at L542.
// 0 deps.
//
// relative requires: none

module.exports = () => {
// ── Support presence — PERMANENTLY ONLINE ────────────────────────────────────
// The Away / leave-a-message mode was removed: the support team is treated as
// always live, so the visitor widget always shows a realtime chat (never the
// "leave a message" fallback). Kept as functions so existing callers (visitor
// widget poll, guest send response) still receive a presence value — hardcoded
// to 'available'. setSupportPresence is a no-op.
async function getSupportPresence() { return 'available'; }
async function setSupportPresence(_p) { /* no-op — presence is permanently 'available' */ }
const cors = (res) => res.set('Access-Control-Allow-Origin', '*')
  .set('Access-Control-Allow-Headers', 'Content-Type')
  .set('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');

  return {
    getSupportPresence,
    setSupportPresence,
    cors,
  };
};