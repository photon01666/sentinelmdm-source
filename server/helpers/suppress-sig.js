// helpers/suppress-sig.js — suppression signature generation.
//
// A HELPER module, not a route module: it registers nothing.
//
//   suppressSig   export   generate a stable suppression hash for an alert
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 0 deps.  The call must sit at or after L1; the earliest consumer of
// the export is L6818, so at or before L6817.  L6791 satisfies both.
//
// relative requires: none

module.exports = () => {
// Generate a suppression signature: a stable hash of what makes this alert unique.
// Base64url of sha256(category|deviceId|normalized_alert_text) so the same known-
// benign cause doesn't re-audit every time it recurs.
function suppressSig(category, deviceId, message) {
  const crypto = require('crypto');
  // Volatile-token masking must match the alert text that actually ships. The sentry message
  // embeds `Time: ${toLocaleString()}` (e.g. "8/8/2026, 3:45:00 PM" — SINGLE-digit hour, not
  // the 2-digit form the old HH:MM:SS mask matched) and the cred_manager detail ends in
  // PowerShell's culture-formatted $evt.TimeCreated ("08/08/2026 15:45:00"). The old mask left
  // both untouched, so every recurring firing minted a fresh signature, isAlertAutoAuditSuppressed
  // never matched, and the same false positive re-audited + re-paged forever — the 41-alert
  // cred_manager flood. Masks mirror learnNormalizeDetail()'s proven date/time set.
  const norm = String(message || '')
    .replace(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/g, 'IP')
    .replace(/\b\d{1,2}[:/-]\d{1,2}[:/-]\d{2,4}\b/g, 'DATE')
    .replace(/\b\d{1,2}:\d{2}(:\d{2})?\b/g, 'TIME')
    .replace(/\b(?:AM|PM)\b/gi, 'AMPM')
    .slice(0, 300);
  return crypto.createHash('sha256').update(`${category}|${deviceId}|${norm}`).digest('base64url');
}

  return {
    suppressSig,
  };
};