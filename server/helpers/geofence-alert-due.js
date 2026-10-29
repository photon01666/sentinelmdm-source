// helpers/geofence-alert-due.js — geofence alert notification cooldown.
//
// A HELPER module, not a route module: it registers nothing. Consumer: the
// sockets/connection wiring (L4625 — moved below the block by the D1b sanctioned
// wiring-line relocation); the geofence handler calls it at runtime.
//
//   geofenceAlertDue   export   true when an out-of-band alert is due
//
// IN-PLACE splice at the block position (X = L4273). Resolution (A): the earliest
// eager consumer (sockets wiring) sits BELOW the wiring line after the D1b
// relocation; deps are ready at the block top.
//
// Stable deps by value: GEOFENCE_ALERT_COOLDOWN_MS (L4270), _geofAlertFallback
// (Map L4271 — mutated by reference, never reassigned), kv (L21).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ GEOFENCE_ALERT_COOLDOWN_MS, _geofAlertFallback, kv }) => {

async function geofenceAlertDue(deviceId, fenceId, transition) {
  if (!fenceId) return true;
  const key = String(fenceId) + ':' + String(transition || '');
  const now = Date.now();
  try {
    const rec = (await kv.getJSON('geofalert:' + deviceId)) || {};
    if (rec[key] && (now - rec[key]) < GEOFENCE_ALERT_COOLDOWN_MS) return false;
    rec[key] = now;
    await kv.setJSON('geofalert:' + deviceId, rec, 24 * 60 * 60);
    return true;
  } catch (e) {
    let rec = _geofAlertFallback.get(deviceId) || {};
    if (rec[key] && (now - rec[key]) < GEOFENCE_ALERT_COOLDOWN_MS) return false;
    rec[key] = now;
    _geofAlertFallback.set(deviceId, rec);
    return true;
  }
}

return { geofenceAlertDue };

};
