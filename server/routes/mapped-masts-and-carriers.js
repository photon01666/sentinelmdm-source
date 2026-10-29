module.exports = ({ app, OSM_TILE_TTL_MS, _osmFetchInflight, carrierName, db, fetchOsmTiles, osmCellsForBbox, requireAuth, requireUnlocked, towerPosition }) => {
// ── Mapped tower structures (OSM steel) ────────────────────────────────────────
// GET /api/masts?bbox=minlat,minlng,maxlat,maxlng&limit=400 — physical structures for
// the map layer. Public data (no user scoping); bbox span clamped, rows capped.
app.get('/api/masts', requireUnlocked, requireAuth, async (req, res) => {
  try {
    const parts = String(req.query.bbox || '').split(',').map(Number);
    if (parts.length !== 4 || parts.some(v => !Number.isFinite(v)))
      return res.status(400).json({ error: 'bbox=minlat,minlng,maxlat,maxlng required' });
    let [a, b, c, d] = parts;
    const minlat = Math.max(-90, Math.min(a, c)), maxlat = Math.min(90, Math.max(a, c));
    const minlng = Math.max(-180, Math.min(b, d)), maxlng = Math.min(180, Math.max(b, d));
    if (maxlat - minlat > 3 || maxlng - minlng > 3)
      return res.status(400).json({ error: 'bbox too large (max 3° span)' });
    const limit = Math.min(1000, Math.max(1, parseInt(req.query.limit, 10) || 400));
    const rows = (await db.prepare(
      'SELECT osmid, kind, lat, lng, tags FROM osm_masts WHERE lat BETWEEN ? AND ? AND lng BETWEEN ? AND ? LIMIT ?'
    ).all(minlat, maxlat, minlng, maxlng, limit));
    // Global coverage: fetch missing/stale tiles in the background; this response
    // carries what's cached plus pending:true so the client retries shortly.
    let pending = false;
    try {
      const cells = osmCellsForBbox(minlat, minlng, maxlat, maxlng);
      const have = new Map();
      try {
        for (const r of (await db.prepare('SELECT cell, fetched_at FROM osm_tiles').all())) have.set(r.cell, Number(r.fetched_at));
      } catch {}
      const now = Date.now();
      const missing = cells.filter(c => !_osmFetchInflight.has(c) && (!have.has(c) || now - have.get(c) > OSM_TILE_TTL_MS)).slice(0, 6);
      if (missing.length) { pending = true; fetchOsmTiles(missing).catch(() => {}); }
    } catch {}
    res.json({ masts: rows, count: rows.length, pending });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Carriers on a mast ─────────────────────────────────────────────────────────
// GET /api/masts/carriers?osmid=node/123 — every carrier using one mapped structure.
// Evidence tiers per carrier group: operator-placed or fleet-learned cells AT the mast
// (≤25 m) are confirmed tenants; anything merely nearby (≤300 m, any source) is
// reported as nearby with its distance — never asserted. (Query param, not a route
// param, because osmids contain slashes.)
app.get('/api/masts/carriers', requireUnlocked, requireAuth, async (req, res) => {
  try {
    const osmid = String(req.query.osmid || '');
    if (!osmid) return res.status(400).json({ error: 'osmid required' });
    const mast = (await db.prepare('SELECT osmid, kind, lat, lng, tags FROM osm_masts WHERE osmid=?').get(osmid));
    if (!mast) return res.status(404).json({ error: 'mast not found' });
    const R = 300, dLat = R / 111320, dLng = R / (111320 * Math.cos(mast.lat * Math.PI / 180));
    const rows = (await db.prepare(
      'SELECT mcc, mnc, tac, cid, lat, lng, source, learned_lat, learned_lng, learned_samples, manual_lat, manual_lng FROM cell_towers ' +
      'WHERE (lat BETWEEN ? AND ? AND lng BETWEEN ? AND ?) OR (learned_lat BETWEEN ? AND ? AND learned_lng BETWEEN ? AND ?)'
    ).all(mast.lat - dLat, mast.lat + dLat, mast.lng - dLng, mast.lng + dLng, mast.lat - dLat, mast.lat + dLat, mast.lng - dLng, mast.lng + dLng));
    const distTo = (la, ln) => {
      const dx = (la - mast.lat) * 111320, dy = (ln - mast.lng) * 111320 * Math.cos(mast.lat * Math.PI / 180);
      return Math.sqrt(dx * dx + dy * dy);
    };
    const groups = new Map(); // 'mcc-mnc' -> { carrier, mcc, mnc, cells, bestTier, minDistM }
    const tierRank = { confirmed: 0, likely: 1, nearby: 2 };
    for (const t of rows) {
      const eff = towerPosition(t);
      if (!eff) continue;
      const d = distTo(eff.lat, eff.lng);
      if (d > R) continue;
      let tier;
      if (d <= 25) tier = (eff.posSource === 'manual' || eff.posSource === 'learned') ? 'confirmed' : 'likely';
      else tier = 'nearby';
      const k = `${t.mcc}-${t.mnc}`;
      const g = groups.get(k) || { carrier: carrierName(t.mcc, t.mnc), mcc: t.mcc, mnc: t.mnc, cells: 0, bestTier: 'nearby', minDistM: Infinity };
      g.cells++;
      if (tierRank[tier] < tierRank[g.bestTier]) g.bestTier = tier;
      if (d < g.minDistM) g.minDistM = Math.round(d);
      groups.set(k, g);
    }
    const carriers = [...groups.values()].sort((a, b) => tierRank[a.bestTier] - tierRank[b.bestTier] || a.minDistM - b.minDistM);
    res.json({ mast: { osmid: mast.osmid, kind: mast.kind, lat: mast.lat, lng: mast.lng, tags: mast.tags }, carriers });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
};
