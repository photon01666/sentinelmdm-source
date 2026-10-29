// helpers/license-key.js — license-key generation + trial-days arithmetic.
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// customer-license-trial / flash / admin-commerce route wirings (all BELOW the
// block — no eager consumer above it).
//
//   genLicenseKey   export   Crockford-ish SENT-xxxx key, uniqueness-checked
//   daysRemaining   export   ceil days until a deadline (null-safe)
//
// IN-PLACE splice at the block position (X = L1661). Resolution: (A) — no eager
// consumer above; deps are ready at the block top.
//   * DAY_MS (L1656) — stable const above the block.
//   * crypto (L15) — ctx-injected by value (scanner blind spot; the server.js
//     binding, not WebCrypto).
//   * db travels as the LIVE getter `getDb: () => db` (LIVE_READS pair; reads
//     are rewritten to `getDb().prepare`), called only inside genLicenseKey.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ DAY_MS, crypto, getDb }) => {

async function genLicenseKey() {
  const A = 'ABCDEFGHJKMNPQRSTVWXYZ0123456789'; // Crockford-ish, no I/L/O/U
  for (let attempt = 0; attempt < 6; attempt++) {
    const r = Array.from(crypto.randomBytes(16)).map(b => A[b % 32]).join('');
    const key = `SENT-${r.slice(0,4)}-${r.slice(4,8)}-${r.slice(8,12)}-${r.slice(12,16)}`;
    if (!(await getDb().prepare('SELECT 1 FROM entitlements WHERE license_key=?').get(key))) return key;
  }
  return 'SENT-' + crypto.randomUUID().replace(/-/g, '').slice(0, 16).toUpperCase();
}

function daysRemaining(deadlineMs) {
  if (!deadlineMs) return null;
  return Math.max(0, Math.ceil((deadlineMs - Date.now()) / DAY_MS));
}

return { daysRemaining, genLicenseKey };

};
