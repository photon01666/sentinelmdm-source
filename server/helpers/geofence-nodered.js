// helpers/geofence-nodered.js - forward geofence transitions to Node-RED TTS, with
// per-device cooldown to avoid repeated announcements.
//
// A HELPER module, not a route module: it registers nothing.
//
//   notifyGeofenceNodeRed   export   POST a geofence event to Node-RED (coalesced)
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// All 6 deps are non-hoisted bindings: GEOFENCE_TTS_COOLDOWN_MS (L408),
// GEOFENCE_TTS_DEVICE_IDS (L412), NODERED_ALERT_KEY (L390), NODERED_GEOFENCE_URL (L407),
// _geofTtsFallback (L409), kv (L21).  The last non-hoisted dep to initialise is
// GEOFENCE_TTS_DEVICE_IDS at L412 — so the call must sit at or after L413; the earliest
// consumer of the export is L5487, so at or before L5486.  L413 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ GEOFENCE_TTS_COOLDOWN_MS, GEOFENCE_TTS_DEVICE_IDS, NODERED_ALERT_KEY, NODERED_GEOFENCE_URL, _geofTtsFallback, kv }) => {
async function notifyGeofenceNodeRed(deviceId, data, label) {
  if (!NODERED_ALERT_KEY) return;
  if (!GEOFENCE_TTS_DEVICE_IDS.includes(String(deviceId))) return;
  const fenceId = String(data.geofenceId || data.name || 'unknown');
  const transition = String(data.transition || 'unknown');
  const key = fenceId + ':' + transition;
  const now = Date.now();
  try {
    const rec = (await kv.getJSON('geofencetts:' + deviceId)) || {};
    if (rec[key] && (now - rec[key]) < GEOFENCE_TTS_COOLDOWN_MS) return;
    rec[key] = now;
    await kv.setJSON('geofencetts:' + deviceId, rec, 24 * 60 * 60);
  } catch {
    const rec = _geofTtsFallback.get(deviceId) || {};
    if (rec[key] && (now - rec[key]) < GEOFENCE_TTS_COOLDOWN_MS) return;
    rec[key] = now;
    _geofTtsFallback.set(deviceId, rec);
  }
  fetch(NODERED_GEOFENCE_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Sentinel-Key': NODERED_ALERT_KEY },
    body: JSON.stringify({ deviceId, deviceName: label || deviceId, geofenceId: data.geofenceId, name: data.name, transition, time: new Date().toLocaleString() }),
    signal: AbortSignal.timeout(5000),
  }).catch(() => {});
}

  return {
    notifyGeofenceNodeRed,
  };
};