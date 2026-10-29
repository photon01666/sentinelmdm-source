// helpers/cell-geometry.js - cell-identity validation, serving-cell extraction from
// network snapshots, and nearest-OSM-mast lookup (distance to closest mapped tower).
//
// A HELPER module, not a route module: it registers nothing.
//
//   validCellIdentity       export   validate mcc/mnc/tac/cid ranges
//   servingCellsFromSnapshot export  extract registered serving cells from a device snapshot
//   nearestOsmMast          export   nearest OSM comms structure within maxM of a lat/lng
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 of the 1 deps is a `const` binding (db L723); no `function` declarations among
// the deps.  The lowest and only non-hoisted binding is `db` at L723 — so the call must
// sit at or after L724; the earliest consumer of the exports is L6974, so at or before
// L6973.  L6896 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ db }) => {
function validCellIdentity(mcc, mnc, tac, cid) {
  if (!(mcc >= 0 && mcc <= 999) || !(mnc >= 0 && mnc <= 999)) return false;
  if (tac >= 2147483647 || cid === 2147483647 || cid >= 9223372036854775000) return false;
  return true;
}

// Identifiable SERVING cells in a network snapshot (neighbours are signal-only — their
// position relative to the device is unknown, so only the camped cell votes).
function servingCellsFromSnapshot(nd) {
  const out = [];
  try {
    const list = (nd.cellular && Array.isArray(nd.cellular.cells)) ? nd.cellular.cells : (nd.cells || []);
    for (const c of list) {
      if (c == null || !c.registered || c.mcc == null || c.cid == null) continue;
      const mcc = Number(c.mcc), mnc = Number(c.mnc || 0), tac = Number(c.tac || 0), cid = Number(c.cid);
      if (!validCellIdentity(mcc, mnc, tac, cid)) continue;
      out.push({ mcc, mnc, tac, cid, rssi: Number.isFinite(c.rssi_dbm) ? c.rssi_dbm : -100 });
    }
  } catch {}
  return out;
}

// Nearest mapped comms structure (OSM steel) to a point, within maxM. Used to snap
// learned centroids and to flag OCID positions sitting far from any real structure.
async function nearestOsmMast(lat, lng, maxM) {
  try {
    const dLat = maxM / 111320, dLng = maxM / (111320 * Math.cos(lat * Math.PI / 180));
    const rows = (await db.prepare('SELECT osmid, kind, lat, lng, tags FROM osm_masts WHERE lat BETWEEN ? AND ? AND lng BETWEEN ? AND ?').all(lat - dLat, lat + dLat, lng - dLng, lng + dLng));
    let best = null, bestD = Infinity;
    for (const r of rows) {
      const dx = (r.lat - lat) * 111320, dy = (r.lng - lng) * 111320 * Math.cos(lat * Math.PI / 180);
      const d = Math.sqrt(dx * dx + dy * dy);
      if (d < bestD) { bestD = d; best = r; }
    }
    if (best && bestD <= maxM) return { osmid: best.osmid, kind: best.kind, lat: best.lat, lng: best.lng, distM: Math.round(bestD) };
  } catch {}
  return null;
}

  return {
    nearestOsmMast,
    servingCellsFromSnapshot,
    validCellIdentity,
  };
};