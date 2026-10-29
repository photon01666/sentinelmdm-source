// helpers/cell-history.js - cell-tower history for a device: scan recent network
// snapshots, map towers to known positions, and return a time-sorted history list.
//
// A HELPER module, not a route module: it registers nothing.
//
//   cellTowerHistory   export   build per-device tower history from network_events
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 3 of the 7 deps are hoisted `function` declarations (carrierName L7055,
// loadKnownTowers L7152, towerPosition L7268); 4 are non-hoisted bindings
// (_cellHistoryCache L7102, cellKey L7049, db L723, decryptText L167).
// The last non-hoisted dep to initialise is `_cellHistoryCache` at L7102 — so the
// call must sit at or after L7103; the earliest consumer of the export is L7285,
// so at or before L7284.  L7103 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ _cellHistoryCache, carrierName, cellKey, db, decryptText, loadKnownTowers, towerPosition }) => {
async function cellTowerHistory(deviceId) {
  const cached = _cellHistoryCache.get(deviceId);
  if (cached && Date.now() - cached.ts < 60_000) return cached.history;
  try {
    const rows = (await db.prepare('SELECT data, timestamp FROM network_events WHERE device_id=? ORDER BY timestamp DESC LIMIT 300').all(deviceId));
    const seen = new Map(); // tower key -> lastSeen
    for (const row of rows) {
      try {
        const nd = JSON.parse(decryptText(row.data));
        const list = (nd.cellular && Array.isArray(nd.cellular.cells)) ? nd.cellular.cells : (nd.cells || []);
        for (const c of list) {
          if (c == null || c.mcc == null || c.cid == null) continue;
          const hmcc = Number(c.mcc), hmnc = Number(c.mnc || 0), htac = Number(c.tac || 0), hcid = Number(c.cid);
          if (!(hmcc >= 0 && hmcc <= 999) || !(hmnc >= 0 && hmnc <= 999)) continue;
          if (htac >= 2147483647 || hcid === 2147483647 || hcid >= 9223372036854775000) continue;
          const k = `${hmcc}-${hmnc}-${htac}-${hcid}`;
          if (!seen.has(k)) seen.set(k, row.timestamp);
        }
      } catch {}
    }
    if (!seen.size) { _cellHistoryCache.set(deviceId, { ts: Date.now(), history: [] }); return []; }
    const cells = [...seen.keys()].map(k => {
      const [mcc, mnc, tac, cid] = k.split('-').map(Number);
      return { mcc, mnc, tac, cid, rssi: -100, registered: false };
    });
    const known = await loadKnownTowers(cells);
    const history = cells
      .map(c => {
        const k = cellKey(c);
        const t = known.get(k);
        const pos = t ? towerPosition(t) : null;
        return { key: k, mcc: c.mcc, mnc: c.mnc, tac: c.tac, cid: c.cid, carrier: carrierName(c.mcc, c.mnc), lat: pos ? pos.lat : null, lng: pos ? pos.lng : null, source: t ? t.source : null, posSource: pos ? pos.posSource : null, rangeM: t ? (t.range_m ?? null) : null, lastSeen: seen.get(k) };
      })
      .filter(h => h.lat != null)
      .sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
    _cellHistoryCache.set(deviceId, { ts: Date.now(), history });
    return history;
  } catch { return []; }
}

  return {
    cellTowerHistory,
  };
};