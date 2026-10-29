// helpers/tower-votes.js — fleet-learned cell-tower positions (GPS votes).
//
// A HELPER module, not a route module: it registers nothing. Consumers:
//   * the backfill-tower-votes wiring (addTowerVote) and the sockets/connection
//     wiring (voteTowerPositions) — both BELOW the wiring line (D1b wiring-line
//     relocations placed the backfill + sockets wirings below cellKey);
//   * persistLearnedTower is private (called by addTowerVote).
//
//   addTowerVote          export   one GPS-weighted vote for a tower's position
//   persistLearnedTower   private  centroid persistence (ring-gated)
//   voteTowerPositions    export   live-path entry: collect + persist votes
//
// Wiring RELOCATED to X = L4469 (D1b R1): the require must sit at/after cellKey's
// declaration (L4468) and before the backfill wiring (L4470). Deps:
//   * TOWCALIB_* (L4358-L4360), OSM_SNAP_MAX_M (L4362), nearestOsmMast /
//     servingCellsFromSnapshot (cell-geometry wiring L4365), AUTO_CALIB_MAX_GPS_ACC_M
//     (L3669), decryptText (L133), kv (L21), log (L250), stmts (L1703) — all above.
//   * cellKey (L4468) — passed BY VALUE (the wiring sits below its declaration;
//     calls are not rewritten by canon, so the body keeps `cellKey(s)` bare).
//   * db travels as the LIVE getter `getDb: () => db` (reads rewritten to
//     `getDb().…`).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ AUTO_CALIB_MAX_GPS_ACC_M, OSM_SNAP_MAX_M, TOWCALIB_MIN_SAMPLES, TOWCALIB_REWRITE_MIN_MOVE_M, TOWCALIB_SAMPLE_CAP, cellKey, decryptText, getDb, kv, log, nearestOsmMast, servingCellsFromSnapshot, stmts }) => {

// One GPS-weighted vote for a tower's position. Shared by the live path and backfill.
// Votes are SIGNAL-weighted at persist time (strong readings vote near the tower;
// cell-edge readings barely count), and readiness requires a RING, not a line:
// the weighted vote covariance must spread on BOTH axes (minor axis ≥ 250 m, axis
// ratio ≤ 3:1) — a commute drive-by while camped on one cell has a 6 km major axis
// and a ~0 minor axis, and its midpoint is road, not tower. Never persist that.
async function addTowerVote(s, lat, lng, w, rssi) {
  const key = 'cellcalib2:' + cellKey(s);
  const rec = (await kv.getJSON(key)) || { n: 0, samples: [] };
  rec.n = (rec.n || 0) + 1;
  rec.samples = (rec.samples || []).concat([{ lat, lng, w, rssi: Number.isFinite(rssi) ? rssi : -100 }]);
  if (rec.samples.length > TOWCALIB_SAMPLE_CAP) rec.samples.splice(0, rec.samples.length - TOWCALIB_SAMPLE_CAP);
  await kv.setJSON(key, rec, 60 * 24 * 60 * 60); // 60d TTL
  if ((rec.samples || []).length < TOWCALIB_MIN_SAMPLES) return;
  const sigW = r => Math.min(32, Math.pow(10, (r + 85) / 30)); // ≈1 @-85 … 32 @-60+
  const W = rec.samples.reduce((sum, p) => sum + p.w * sigW(p.rssi), 0);
  if (W <= 0) return;
  const cLat = rec.samples.reduce((sum, p) => sum + p.lat * p.w * sigW(p.rssi), 0) / W;
  const cLng = rec.samples.reduce((sum, p) => sum + p.lng * p.w * sigW(p.rssi), 0) / W;
  // Weighted 2x2 covariance in meters (equirectangular around the centroid).
  let sxx = 0, syy = 0, sxy = 0;
  const cosLat = Math.cos(cLat * Math.PI / 180);
  for (const p of rec.samples) {
    const x = (p.lng - cLng) * 111320 * cosLat, y = (p.lat - cLat) * 111320;
    const pw = p.w * sigW(p.rssi) / W;
    sxx += pw * x * x; syy += pw * y * y; sxy += pw * x * y;
  }
  const tr = sxx + syy, det = Math.max(0, sxx * syy - sxy * sxy);
  const disc = Math.sqrt(Math.max(0, (tr / 2) * (tr / 2) - det));
  const l1 = tr / 2 + disc, l2 = Math.max(0, tr / 2 - disc);
  const minorM = Math.sqrt(l2), majorM = Math.sqrt(Math.max(l1, 0));
  if (minorM < 250) return;                    // line, not a ring — drive-by, reject
  if (l1 > 9 * Math.max(l2, 1)) return;        // axis ratio worse than 3:1 — reject
  await persistLearnedTower(s, rec.samples.length, cLat, cLng, majorM);
}

async function persistLearnedTower(s, n, lat, lng, spread) {
  // Snap to mapped steel when close: the mast IS the tower; the centroid is an estimate.
  let fLat = lat, fLng = lng, snapped = 0, snapMast = null;
  const mast = await nearestOsmMast(lat, lng, OSM_SNAP_MAX_M);
  if (mast) { fLat = mast.lat; fLng = mast.lng; snapped = 1; snapMast = mast.osmid; }
  const now = Date.now();
  try {
    const row = (await getDb().prepare('SELECT learned_lat, learned_lng, learned_samples FROM cell_towers WHERE mcc=? AND mnc=? AND tac=? AND cid=?').get(s.mcc, s.mnc, s.tac, s.cid));
    if (!row) {
      // Tower unknown to OCID too: learn it from scratch (position learned, source marked).
      await getDb().prepare(
        'INSERT INTO cell_towers (mcc,mnc,tac,cid,lat,lng,ref_dbm,samples,spread_m,source,updated_at,learned_lat,learned_lng,learned_samples,learned_spread,learned_at,learned_snapped) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ' +
        'ON CONFLICT(mcc,mnc,tac,cid) DO UPDATE SET learned_lat=?,learned_lng=?,learned_samples=?,learned_spread=?,learned_at=?,learned_snapped=?'
      ).run(s.mcc, s.mnc, s.tac, s.cid, fLat, fLng, -90, 0, 0, 'learned', now, fLat, fLng, n, Math.round(spread), now, snapped,
        fLat, fLng, n, Math.round(spread), now, snapped);
    } else {
      if (row.learned_lat != null) {
        const dy = (fLat - row.learned_lat) * 111320, dx = (fLng - row.learned_lng) * 111320 * Math.cos(fLat * Math.PI / 180);
        if (Math.sqrt(dx * dx + dy * dy) < TOWCALIB_REWRITE_MIN_MOVE_M) return;
      }
      await getDb().prepare(
        'UPDATE cell_towers SET learned_lat=?,learned_lng=?,learned_samples=?,learned_spread=?,learned_at=?,learned_snapped=?,updated_at=? WHERE mcc=? AND mnc=? AND tac=? AND cid=?'
      ).run(fLat, fLng, n, Math.round(spread), now, snapped, now, s.mcc, s.mnc, s.tac, s.cid);
    }
    log('info', 'Learned tower position', { key: cellKey(s), lat: Math.round(fLat * 1e5) / 1e5, lng: Math.round(fLng * 1e5) / 1e5, samples: n, snapped: snapMast || undefined });
  } catch (e) { log('warn', 'persistLearnedTower failed', { key: cellKey(s), error: e.message }); }
}

// Live path: every accurate GPS fix votes for the currently-camped tower(s).
// Fire-and-forget from the location handler, next to autoCalibrateAnchors.
async function voteTowerPositions(deviceId, lat, lng, gpsAccM) {
  let nd = null;
  try {
    const netRow = (await stmts.latestNetwork.get(deviceId));
    if (!netRow?.data) return;
    nd = JSON.parse(decryptText(netRow.data));
  } catch { return; }
  const serving = servingCellsFromSnapshot(nd);
  if (!serving.length) return;
  const gpsW = Math.max(0.2, 1 - gpsAccM / (AUTO_CALIB_MAX_GPS_ACC_M * 2));
  for (const s of serving) {
    try { await addTowerVote(s, lat, lng, gpsW, s.rssi); }
    catch (e) { log('warn', 'tower vote failed', { key: cellKey(s), error: e.message }); }
  }
}

return { addTowerVote, voteTowerPositions };

};
