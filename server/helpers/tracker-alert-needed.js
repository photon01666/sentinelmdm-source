// helpers/tracker-alert-needed.js — close-range tracker alert policy.
//
// A HELPER module, not a route module: it registers nothing. Consumer: the
// sockets/connection wiring (L4684 — moved below the block by the D1b sanctioned
// wiring-line relocation), which calls it from the tracker scan handler at
// runtime.
//
//   trackerAlertNeeded   export   true when an out-of-band alert should be sent
//
// IN-PLACE splice at the block position (X = L4275, comment absorbed from L4262).
// Resolution (A): the earliest eager consumer (sockets wiring) now sits BELOW
// the wiring line after the D1b wiring-line relocation; all deps are ready at
// the block top.
//
// Stable deps by value: TRACKER_ALERT_REARM_MS (L4257), TRACKER_DEDUP_TTL_SEC
// (L4258), TRACKER_MAX_ALERTS_PER_HOUR (L4259), _trackerNotifFallback (Map
// L4260 — mutated by reference, never reassigned), kv (L21).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ TRACKER_ALERT_REARM_MS, TRACKER_DEDUP_TTL_SEC, TRACKER_MAX_ALERTS_PER_HOUR, _trackerNotifFallback, kv }) => {

// Returns true when an out-of-band alert should be sent for this set of (non-safelisted)
// CLOSE-RANGE trackers. The dedup identity prefers the tag's STABLE trackerId (Apple Find My
// public key / Samsung privacy ID / Google FMDN EID) over the advertised MAC — those tags
// rotate their address (RPA), so MAC-only dedup would re-alert the same tag on every rotation
// (this is exactly what produced the spam in dense areas: a fresh random MAC every 15s cycle).
// Alert policy (all must hold):
//   1. RSSI ≥ TRACKER_ALERT_MIN_RSSI — ambient -80/-100 dBm noise never alerts (panel only);
//   2. PERSISTENCE — the same identity must be seen on ≥2 scan cycles (≈30s) — filters
//      one-off passers-by in transit/crowds;
//   3. PER-IDENTITY — at most one alert per encounter (re-alert only after ≥24h absence);
//   4. PER-DEVICE SOFT CAP — max TRACKER_MAX_ALERTS_PER_HOUR per device (rolling hour), so a
//      mall full of new tags can't flood the alert channels.
// Record shape per identity: { a: lastAlertTs, s: lastSeenTs, n: consecutive sightings }.
async function trackerAlertNeeded(deviceId, trackers) {
  const now = Date.now();
  const ids = trackers.map(t => String(t.trackerId || t.address || '').toUpperCase()).filter(Boolean);
  if (!ids.length) return false;
  const apply = (record) => {
    const alertable = [];
    for (const id of ids) {
      const rec = record[id];
      const gap = rec ? now - (rec.s || 0) : Infinity;
      if (!rec || gap >= TRACKER_ALERT_REARM_MS) {
        // Fresh encounter (or ≥24h since last sighting): first confirmation sighting only.
        record[id] = { a: 0, s: now, n: 1 };
        continue;
      }
      const n = (rec.n || 1) + 1;
      // Confirmed (≥2 sightings) AND not yet alerted in this encounter.
      if (n >= 2 && !rec.a) alertable.push(id);
      record[id] = { a: rec.a || 0, s: now, n };
    }
    if (!alertable.length) return [];
    // Per-device rolling-hour cap.
    let hour = record.__h;
    if (!hour || (now - hour.t) > 60 * 60 * 1000) hour = { c: 0, t: now };
    if (hour.c >= TRACKER_MAX_ALERTS_PER_HOUR) {
      record.__h = hour;
      return [];
    }
    hour.c += alertable.length;
    record.__h = hour;
    for (const id of alertable) record[id] = { ...record[id], a: now };
    return alertable;
  };
  try {
    const record = (await kv.getJSON('trackeralert:' + deviceId)) || {};
    const alertable = apply(record);
    if (!alertable.length) return false;
    await kv.setJSON('trackeralert:' + deviceId, record, TRACKER_DEDUP_TTL_SEC);
    return true;
  } catch (e) {
    // Redis hiccup — same semantics on the per-process map.
    let record = _trackerNotifFallback.get(deviceId) || {};
    const alertable = apply(record);
    if (!alertable.length) return false;
    _trackerNotifFallback.set(deviceId, record);
    return true;
  }
}

return { trackerAlertNeeded };

};
