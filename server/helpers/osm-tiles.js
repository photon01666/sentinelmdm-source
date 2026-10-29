// helpers/osm-tiles.js - OpenStreetMap tile fetching / cell-to-OSM helpers.
//
// A HELPER module, not a route module: it registers nothing.
//
//   osmTileCell        PRIVATE  only called inside this block
//   osmCellsForBbox    export   tile-cell keys covering a lat/lng bbox
//   fetchOsmTiles      export   Overpass-fetch uncached cells -> osm_masts / osm_tiles rows
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 4 of the 5 deps are non-hoisted `const`/`let` bindings (OSM_MIRRORS L1792,
// OSM_TILE_DEG L1790, _osmFetchInflight L1793, db L723); only `log` (L447) is a
// `function` declaration and hoists. The lowest non-hoisted binding is
// _osmFetchInflight at L1793 — so the call must sit at or after L1794; the earliest
// consumer of the exports is L7476, so at or before L7475. L1794 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ OSM_MIRRORS, OSM_TILE_DEG, _osmFetchInflight, db, log }) => {
function osmTileCell(lat, lng) {
  return (Math.floor(lat / OSM_TILE_DEG) * OSM_TILE_DEG) + ':' + (Math.floor(lng / OSM_TILE_DEG) * OSM_TILE_DEG);
}
function osmCellsForBbox(minlat, minlng, maxlat, maxlng) {
  const cells = new Set();
  for (let la = Math.floor(minlat / OSM_TILE_DEG) * OSM_TILE_DEG; la <= maxlat; la += OSM_TILE_DEG)
    for (let ln = Math.floor(minlng / OSM_TILE_DEG) * OSM_TILE_DEG; ln <= maxlng; ln += OSM_TILE_DEG)
      cells.add(la + ':' + ln);
  return [...cells];
}
async function fetchOsmTiles(cells) {
  const todo = cells.filter(c => !_osmFetchInflight.has(c)).slice(0, 6);
  if (!todo.length) return;
  for (const c of todo) _osmFetchInflight.add(c);
  try {
    for (const cell of todo) {
      try {
        const [clat, clng] = cell.split(':').map(Number);
        const bbox = `${clat},${clng},${clat + OSM_TILE_DEG},${clng + OSM_TILE_DEG}`;
        const q = `[out:json][timeout:60];(node["man_made"="mast"](${bbox});node["man_made"="communications_tower"](${bbox});node["man_made"="tower"]["tower:type"="communication"](${bbox}););out center tags;`;
        let data = null;
        for (const m of OSM_MIRRORS) {
          try {
            const res = await fetch(m, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json', 'User-Agent': 'SentinelMDM/1.0 (private fleet mapper)' }, body: 'data=' + encodeURIComponent(q), signal: AbortSignal.timeout(70000) });
            if (!res.ok) continue;
            const j = await res.json();
            if (j && Array.isArray(j.elements)) { data = j; break; }
          } catch {}
        }
        if (!data) continue; // don't mark: retry on a later pan
        let n = 0;
        const now = Date.now();
        for (const e of data.elements) {
          const la = (e.lat != null) ? e.lat : (e.center && e.center.lat);
          const ln = (e.lon != null) ? e.lon : (e.center && e.center.lon);
          if (la == null || ln == null) continue;
          const tags = e.tags || {};
          const kind = tags.man_made === 'tower' ? 'tower' : (tags.man_made || 'mast');
          const keep = {};
          for (const k of ['man_made', 'tower:type', 'tower:construction', 'height', 'operator', 'communication:mobile_phone', 'name']) if (tags[k] != null) keep[k] = tags[k];
          await db.prepare(
            'INSERT INTO osm_masts (osmid,kind,lat,lng,tags,updated_at) VALUES (?,?,?,?,?,?) ' +
            'ON CONFLICT(osmid) DO UPDATE SET kind=?,lat=?,lng=?,tags=?,updated_at=?'
          ).run(e.type + '/' + e.id, kind, la, ln, JSON.stringify(keep), now, kind, la, ln, JSON.stringify(keep), now).catch(() => {});
          n++;
        }
        await db.prepare('INSERT INTO osm_tiles (cell,fetched_at) VALUES (?,?) ON CONFLICT(cell) DO UPDATE SET fetched_at=?').run(cell, now, now).catch(() => {});
        log('info', 'OSM tile fetched', { cell, structures: n });
      } finally { _osmFetchInflight.delete(cell); }
    }
  } catch (e) { log('warn', 'OSM tile fetch failed', { error: e.message }); }
}

  return {
    fetchOsmTiles,
    osmCellsForBbox,
  };
};
