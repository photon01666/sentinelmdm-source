// helpers/persist-auto-anchor.js — upsert learned anchor with throttling.
//
// A HELPER module, not a route module: it registers nothing.
//
//   persistAutoAnchor   export   upsert a learned anchor with rewrite throttling
//
// RELOCATE: wiring line must sit at/after L5486 and at/before L5596 — placed at L5596.
// 4 deps: AUTO_CALIB_REWRITE_MIN_MOVE_M (binding L5467), db (binding L625),
// isValidRssi (destructure L5485), log (destructure L400).
//
// relative requires: none

module.exports = ({ AUTO_CALIB_REWRITE_MIN_MOVE_M, db, isValidRssi, log }) => {
// Upsert a learned anchor (never overwrites a MANUAL one). Rewrites are throttled to
// avoid churn: only when the centroid moved ≥ AUTO_CALIB_REWRITE_MIN_MOVE_M.
// The UNIQUE(user_id, address) index + conflict fallback close the race where two
// concurrent heartbeats both SELECT-miss and double-INSERT the same anchor.
async function persistAutoAnchor(ownerId, addr, rec, lat, lng) {
  if (!isValidRssi(rec.bestRssi)) return;   // never persist sentinel/poisoned refs
  const row = (await db.prepare("SELECT id, origin, lat, lng FROM proximity_anchors WHERE user_id=? AND address=?").get(ownerId, addr));
  const now = Date.now();
  if (row) {
    if (row.origin === 'manual') return;   // operator's manual placement always wins
    const dy = (lat - row.lat) * 111320, dx = (lng - row.lng) * 111320 * Math.cos(lat * Math.PI / 180);
    if (Math.sqrt(dx * dx + dy * dy) < AUTO_CALIB_REWRITE_MIN_MOVE_M && row.origin === 'auto') return;
    (await db.prepare(
      "UPDATE proximity_anchors SET name=?, lat=?, lng=?, ref_rssi=?, origin='auto', created_at=? WHERE id=?"
    ).run(String(rec.name || addr).slice(0, 80), lat, lng, rec.bestRssi, now, row.id));
  } else {
    try {
      (await db.prepare(
        'INSERT INTO proximity_anchors (user_id,kind,address,name,lat,lng,ref_rssi,created_at,origin) VALUES (?,?,?,?,?,?,?,?,?)'
      ).run(ownerId, rec.kind || 'bt', addr, String(rec.name || addr).slice(0, 80), lat, lng, rec.bestRssi, now, 'auto'));
    } catch (e) {
      if (!/unique|duplicate/i.test(e.message || '')) throw e;
      const again = (await db.prepare("SELECT id, origin, lat, lng FROM proximity_anchors WHERE user_id=? AND address=?").get(ownerId, addr));
      if (again && again.origin !== 'manual') {
        (await db.prepare(
          "UPDATE proximity_anchors SET name=?, lat=?, lng=?, ref_rssi=?, origin='auto', created_at=? WHERE id=?"
        ).run(String(rec.name || addr).slice(0, 80), lat, lng, rec.bestRssi, now, again.id));
      }
    }
  }
  log('info', 'Auto-calibrated anchor', { address: addr, name: String(rec.name || addr).slice(0, 40), lat: Math.round(lat * 1e5) / 1e5, lng: Math.round(lng * 1e5) / 1e5, refRssi: rec.bestRssi });
}

  return {
    persistAutoAnchor,
  };
};