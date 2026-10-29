// helpers/geofence-accept-transition.js — geofence enter/exit flap damping.
//
// A HELPER module, not a route module: it registers nothing. Consumer: the
// sockets/connection wiring (L4608 — moved below the block by the D1b sanctioned
// wiring-line relocation); the geofence handler calls it at runtime.
//
//   geofenceAcceptTransition   export   true when the transition may alert
//
// IN-PLACE splice at the block position (X = L4291). Resolution (A): the earliest
// eager consumer (sockets wiring) sits BELOW the wiring line after the D1b
// relocation; deps are ready at the block top.
//
// Stable deps by value: GEOFENCE_FLAP_WINDOW_MS (L4288), _geofFlapFallback (Map
// L4289 — mutated by reference, never reassigned), kv (L21).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ GEOFENCE_FLAP_WINDOW_MS, _geofFlapFallback, kv }) => {

async function geofenceAcceptTransition(deviceId, fenceId, transition) {
  if (!fenceId || !transition) return true;
  const key = String(fenceId);
  const now = Date.now();
  const apply = (rec) => {
    let e = rec[key];
    if (e && e.mutedUntil && now < e.mutedUntil) return false;
    if (!e) e = rec[key] = { last: null, at: 0, flips: 0, lastDwell: 0 };
    if (transition === 'dwell') {
      if (e.lastDwell && (now - e.lastDwell) < GEOFENCE_FLAP_WINDOW_MS) return false;
      e.lastDwell = now;
      return true;
    }
    if (transition !== 'enter' && transition !== 'exit') return true;   // unknown → pass
    if (!e.last) { e.last = transition; e.at = now; e.flips = 0; return true; }
    if ((now - e.at) >= GEOFENCE_FLAP_WINDOW_MS) {                     // fresh episode
      e.last = transition; e.at = now; e.flips = 0; return true;
    }
    if (transition === e.last) return false;                           // duplicate
    e.flips = (e.flips || 0) + 1;
    if (e.flips >= 2) { e.mutedUntil = now + GEOFENCE_FLAP_WINDOW_MS; return false; }
    e.last = transition; e.at = now;
    return true;
  };
  try {
    const rec = (await kv.getJSON('geofflap:' + deviceId)) || {};
    const ok = apply(rec);
    await kv.setJSON('geofflap:' + deviceId, rec, 24 * 60 * 60);
    return ok;
  } catch (e) {
    const rec = _geofFlapFallback.get(deviceId) || {};
    const ok = apply(rec);
    _geofFlapFallback.set(deviceId, rec);
    return ok;
  }
}

return { geofenceAcceptTransition };

};
