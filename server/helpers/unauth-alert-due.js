// helpers/unauth-alert-due.js — unauth alert cooldown with Redis fallback.
//
// A HELPER module, not a route module: it registers nothing.
//
//   unauthAlertDue   export   check and record unauth alert cooldown
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 3 deps: UNAUTH_ALERT_COOLDOWN_MS (binding L2832), _unauthAlertFallback (binding L2833), kv (destructure L21).  The call must sit at or after L2834; the earliest consumer of
// the export is L2903, so at or before L2902.  L2834 satisfies both.
//
// relative requires: none

module.exports = ({ UNAUTH_ALERT_COOLDOWN_MS, _unauthAlertFallback, kv }) => {
async function unauthAlertDue(path, ip) {
  const key = path + '|' + ip;
  const now = Date.now();
  try {
    const rec = (await kv.getJSON('unauthalert')) || {};
    if (rec[key] && (now - rec[key]) < UNAUTH_ALERT_COOLDOWN_MS) return false;
    for (const k of Object.keys(rec)) if (now - rec[k] > UNAUTH_ALERT_COOLDOWN_MS) delete rec[k];
    rec[key] = now;
    await kv.setJSON('unauthalert', rec, 24 * 60 * 60);
    return true;
  } catch {
    if (_unauthAlertFallback.get(key) && (now - _unauthAlertFallback.get(key)) < UNAUTH_ALERT_COOLDOWN_MS) return false;
    _unauthAlertFallback.set(key, now);
    return true;
  }
}

  return {
    unauthAlertDue,
  };
};