// helpers/is-alert-auto-audit-suppressed.js — check if alert is auto-audit suppressed.
//
// A HELPER module, not a route module: it registers nothing.
//
//   isAlertAutoAuditSuppressed   export   check if an alert is suppressed by auto-audit
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 2 deps: db (binding L646), suppressSig (destructure L6791).  The call must sit at or after L6792; the earliest consumer of
// the export is L6850, so at or before L6849.  L6795 satisfies both.
//
// relative requires: none

module.exports = ({ db, suppressSig }) => {
async function isAlertAutoAuditSuppressed(category, deviceId, message) {
  // Never suppress applocker_audit alerts — every new executable should get its own analysis,
  // even if a similar one was seen before. These are visibility events, not repeat threats.
  if (category === 'applocker_audit') return false;
  const sig = suppressSig(category, deviceId, message);
  try {
    const row = (await db.prepare(
      "SELECT id FROM alert_auto_audits WHERE device_id=? AND suppression_signature=? AND false_positive=1 LIMIT 1"
    ).get(deviceId, sig));
    return !!row;
  } catch { return false; }
}

  return {
    isAlertAutoAuditSuppressed,
  };
};