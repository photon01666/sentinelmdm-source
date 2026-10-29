// helpers/cell-fix.js - coarse position fix from currently-visible cell towers.
//
// A HELPER module, not a route module: it registers nothing. It exists to serve
// routes/wifi-aps-anchors-and-positioning.js, which receives it as a ctx dep.
//
//   computeCellFix   export   triangulate a coarse position from towers the device can see
//                             RIGHT NOW. Deliberately ignores history: folding stale towers
//                             into a fix would paint a phantom trail on the map.
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 8 of the 11 deps are `function` declarations and hoist (carrierName, cellDistM,
// cellTowerHistory, latestCells, loadKnownTowers, nearestOsmMast, towerPosition, and
// the ones declared above). The lowest non-hoisted binding is cellKey (L7505), so the call
// must sit at or after L7506; the earliest consumer of the export is L7823, so at or before
// L7822. L7741 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ CELL_TOWER_CONFIDENT_SPREAD_M, CELL_TOWER_COVERAGE_RADIUS_M, OSM_NEAR_MAX_M, carrierName, cellDistM, cellKey, cellTowerHistory, latestCells, loadKnownTowers, nearestOsmMast, towerPosition }) => {
// Triangulate a coarse position using CURRENTLY visible towers with known positions.
// History is display-only (map footprint): folding stale towers into the live fix
// drags the estimate back along the travel path and understates the error — the
// "small circle sitting on the tower" failure. A single tower can only ever yield
// a coarse "within range" circle — without a second bearing, direction is unknowable.
// Returns { fix, cells, nSeen, history }.
async function computeCellFix(deviceId) {
  const { cells: currentCells, nSeen } = await latestCells(deviceId);
  const known = await loadKnownTowers(currentCells);
  const pts = [];
  const cellOut = currentCells.map(c => {
    const k = cellKey(c);
    const t = known.get(k);
    const pos = t ? towerPosition(t) : null;
    const out = { ...c, key: k, known: !!t, source: t?.source || null, carrier: carrierName(c.mcc, c.mnc), lat: null, lng: null, distM: null, spreadM: t ? (t.spread_m ?? null) : null, rangeM: t ? (t.range_m ?? null) : null, posSource: pos ? pos.posSource : null, learnedSamples: pos ? pos.learnedSamples : 0, disagreeM: pos ? pos.disagreeM : 0 };
    if (t && pos) {
      const d = cellDistM(c.rssi);
      out.lat = pos.lat; out.lng = pos.lng; out.distM = Math.round(d);
      pts.push({ lat: pos.lat, lng: pos.lng, d, w: 1 / (d * d), registered: c.registered, spread: t.spread_m ?? 0, source: t.source, rangeM: t.range_m ?? null, posSource: pos.posSource, disagreeM: pos.disagreeM, key: k });
    }
    return out;
  });
  // A fix is only credible when at least two CURRENTLY visible towers are
  // geographically resolved. A single resolved tower still yields a coarse
  // "somewhere near this tower" fix; unresolved towers never anchor a fix.
  // OCID towers carry REAL positions, ripe learned positions are fleet-measured, and
  // operator placements are ground truth — all always resolved regardless of vote spread.
  const confident = pts.filter(p => p.posSource === 'learned' || p.posSource === 'manual' || p.source === 'ocid' || p.spread >= CELL_TOWER_CONFIDENT_SPREAD_M);
  let usable;
  let coarse = false;
  if (confident.length >= 2) usable = confident;
  else if (pts.length >= 1) { usable = pts; coarse = true; }
  else usable = [];
  const history = await cellTowerHistory(deviceId);
  if (!usable.length) {
    // Nothing visible right now with a known position — fall back to the most
    // recently seen historical tower as a stale coarse area (better than nothing
    // when the modem reports no identity, e.g. IWLAN/VoWiFi camping).
    if (!history.length) return { fix: null, cells: cellOut, nSeen, history };
    const h = history[0];
    const acc = Math.min(5000, Math.max(1000, h.rangeM || CELL_TOWER_COVERAGE_RADIUS_M));
    const fix = { lat: h.lat, lng: h.lng, accuracyM: Math.round(acc), source: 'cell', coarse: true, stale: true };
    return { fix, cells: cellOut, nSeen, history };
  }
  const W = usable.reduce((s, p) => s + p.w, 0);
  const lat = usable.reduce((s, p) => s + p.lat * p.w, 0) / W;
  const lng = usable.reduce((s, p) => s + p.lng * p.w, 0) / W;
  const meanD = usable.reduce((s, p) => s + p.d, 0) / usable.length;
  const maxDisagree = Math.max(0, ...usable.map(p => p.disagreeM || 0));
  let acc;
  if (coarse) {
    // Single tower: no bearing — the device is somewhere within range. The circle
    // must cover the tower's coverage, the RSSI distance estimate, AND any
    // OCID↔learned disagreement about where the tower even is.
    const t = usable[0];
    acc = Math.min(5000, Math.max(500, t.rangeM || 0, t.d, maxDisagree + 300));
  } else {
    // Multi-tower: the error must span the tower spread plus the ranging error.
    // (A centroid between towers 3 km apart with a ±300 m circle is a lie.)
    const spreadR = Math.max(...usable.map(p => {
      const dx = (p.lat - lat) * 111320, dy = (p.lng - lng) * 111320 * Math.cos(lat * Math.PI / 180);
      return Math.sqrt(dx * dx + dy * dy);
    }));
    acc = Math.min(5000, Math.max(300, spreadR + meanD * 0.5, maxDisagree + 300));
  }
  const posSource = usable.every(p => p.posSource === 'manual') ? 'manual'
    : usable.every(p => p.posSource === 'learned') ? 'learned'
    : (usable.some(p => p.posSource === 'learned' || p.posSource === 'manual') ? 'mixed' : 'ocid');
  // Nearest mapped structure to the fix — grounds the estimate in real steel and
  // flags OCID positions sitting far from anything physical.
  const mast = await nearestOsmMast(lat, lng, OSM_NEAR_MAX_M);
  const connected = cellOut.find(c => c.registered && c.known);
  const fix = { lat: Math.round(lat * 1e6) / 1e6, lng: Math.round(lng * 1e6) / 1e6, accuracyM: Math.round(acc), source: 'cell', coarse, posSource, maxDisagreeM: maxDisagree, mast: mast || null, towerKey: connected ? connected.key : (usable[0] && usable[0].key) };
  return { fix, cells: cellOut, nSeen, history };
}

  return {
    computeCellFix,
  };
};
