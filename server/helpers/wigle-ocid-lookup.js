// helpers/wigle-ocid-lookup.js — external WiFi-AP (WiGLE) + cell-tower (OpenCellID) lookups.
//
// A HELPER module, not a route module: it registers nothing.
//
//   wigleMiss          private  negative-result cache write (WiGLE)
//   wigleAuthHeader    export   Basic auth from WIGLE_API_KEY (or apiName:apiToken)
//   lookupWigleAP      export   BSSID -> { lat, lng, ssid } (cached row or live query)
//   ocidMiss           private  negative-result cache write (OCID)
//   lookupOcidTower    export   one-off OCID tower lookup (upserts cell_towers)
//
// IN-PLACE splice at the block position (X = L4880). Resolution (A): the only
// consumer above the block is a runtime call inside loadKnownTowers's body
// (L4866 — executes at request time, long after this wiring line); the rf-fix /
// wifi-aps route wirings consume the exports from BELOW the block.
//
// Stable deps by value: OCID_MISS_TTL_MS (L4855), OCID_TRANSIENT_TTL_MS (L4856),
// _ocidMissCache (Map L4854 — shared with loadKnownTowers; mutated by reference,
// never reassigned), _wigleMissCache (Map L4879 — sole user is this module;
// never reassigned), log (L249). db travels as the LIVE getter `getDb: () => db`
// (LIVE_READS pair; reads are rewritten to `getDb().prepare`).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ OCID_MISS_TTL_MS, OCID_TRANSIENT_TTL_MS, _ocidMissCache, _wigleMissCache, getDb, log }) => {

function wigleMiss(bssid, transient) {
  _wigleMissCache.set(bssid, Date.now() + (transient ? OCID_TRANSIENT_TTL_MS : OCID_MISS_TTL_MS));
  if (_wigleMissCache.size > 5000) {
    const now = Date.now();
    for (const [kk, ts] of _wigleMissCache) if (ts <= now) _wigleMissCache.delete(kk);
  }
}
function wigleAuthHeader() {
  const k = (process.env.WIGLE_API_KEY || '').trim();
  if (!k) return null;
  const enc = k.includes(':') ? Buffer.from(k).toString('base64') : k;
  return 'Basic ' + enc;
}
// Resolve one BSSID → { lat, lng, ssid } (cached row or live query). Null on miss.
async function lookupWigleAP(bssid) {
  const b = String(bssid || '').toUpperCase();
  if (!b) return null;
  try {
    const hit = (await getDb().prepare('SELECT lat, lng, ssid FROM wifi_aps WHERE bssid=?').get(b));
    if (hit) return { lat: hit.lat, lng: hit.lng, ssid: hit.name || hit.ssid };
  } catch {}
  const auth = wigleAuthHeader();
  if (!auth || (_wigleMissCache.get(b) || 0) > Date.now()) return null;
  try {
    const url = `https://api.wigle.net/api/v2/network/search?netid=${encodeURIComponent(b)}&resultsPerPage=5`;
    const res = await fetch(url, { headers: { Authorization: auth, Accept: 'application/json' }, signal: AbortSignal.timeout(5000) });
    if (!res.ok) { wigleMiss(b, true); return null; }
    const j = await res.json();
    const best = j && j.success !== false && Array.isArray(j.results) && j.results.length
      ? j.results.slice().sort((x, y) => (y.totalWlObs || y.totalObs || 0) - (x.totalWlObs || x.totalObs || 0))[0]
      : null;
    if (!best || !Number.isFinite(best.trilat) || !Number.isFinite(best.trilong)) { wigleMiss(b, false); return null; }
    const now = Date.now();
    (await getDb().prepare(
      'INSERT INTO wifi_aps (bssid,ssid,lat,lng,accuracy_m,source,updated_at) VALUES (?,?,?,?,?,?,?) ' +
      'ON CONFLICT(bssid) DO UPDATE SET ssid=?, lat=?, lng=?, updated_at=?'
    ).run(b, String(best.ssid || '').slice(0, 80) || null, best.trilat, best.trilong, 100, 'wigle', now,
      String(best.ssid || '').slice(0, 80) || null, best.trilat, best.trilong, now).catch(() => {}));
    _wigleMissCache.delete(b);
    log('info', 'WiGLE AP resolved', { bssid: b, ssid: String(best.ssid || '').slice(0, 32) });
    return { lat: best.trilat, lng: best.trilong, ssid: best.ssid || null };
  } catch { wigleMiss(b, true); return null; }
}
// One-off OpenCellID lookup for a tower we've never seen — returns the cell_towers row
// (upserted, source='ocid') or null. Free tier is rate-limited, so misses are cached:
// definitive "not in OCID" for 24h, transient failures (429/timeout) for 5 min.
function ocidMiss(k, transient) {
  _ocidMissCache.set(k, Date.now() + (transient ? OCID_TRANSIENT_TTL_MS : OCID_MISS_TTL_MS));
  if (_ocidMissCache.size > 5000) {
    const now = Date.now();
    for (const [kk, ts] of _ocidMissCache) if (ts <= now) _ocidMissCache.delete(kk);
  }
}
async function lookupOcidTower(mcc, mnc, tac, cid) {
  const k = `${mcc}-${mnc}-${tac}-${cid}`;
  try {
    const url = `https://opencellid.org/cell/get?key=${encodeURIComponent(process.env.OCID_API_KEY)}&mcc=${mcc}&mnc=${mnc}&lac=${tac}&cellid=${cid}&format=json`;
    const res = await fetch(url, { signal: AbortSignal.timeout(4000) });
    if (!res.ok) { ocidMiss(k, true); return null; }
    const j = await res.json();
    if (j == null || j.lat == null || j.lon == null || !Number.isFinite(j.lat) || !Number.isFinite(j.lon)) {
      // Definitive miss (API answered, tower unknown) — EXCEPT explicit rate limiting.
      if (j && /limit|quota|throttl|recaptcha/i.test(String(j.message || '') + String(j.status || ''))) ocidMiss(k, true);
      else ocidMiss(k, false);
      return null;
    }
    const now = Date.now();
    const refDbm = Number.isFinite(j.averageSignalStrength) && j.averageSignalStrength < 0 ? Math.round(j.averageSignalStrength) : -90;
    const rangeM = Number.isFinite(j.range) && j.range > 0 ? Math.round(j.range) : null;
    await getDb().prepare(
      'INSERT INTO cell_towers (mcc,mnc,tac,cid,lat,lng,ref_dbm,samples,spread_m,source,updated_at,range_m) VALUES (?,?,?,?,?,?,?,?,?,?,?,?) ' +
      'ON CONFLICT(mcc,mnc,tac,cid) DO UPDATE SET lat=?, lng=?, ref_dbm=?, source=?, updated_at=?, range_m=?'
    ).run(mcc, mnc, tac, cid, j.lat, j.lon, refDbm, Number(j.samples) || 1, 0, 'ocid', now, rangeM,
      j.lat, j.lon, refDbm, 'ocid', now, rangeM);
    _ocidMissCache.delete(k);
    log('info', 'OCID tower resolved', { key: k, lat: j.lat, lng: j.lon, range: rangeM });
    return (await getDb().prepare('SELECT * FROM cell_towers WHERE mcc=? AND mnc=? AND tac=? AND cid=?').get(mcc, mnc, tac, cid));
  } catch { ocidMiss(k, true); return null; }
}

return { lookupOcidTower, lookupWigleAP, wigleAuthHeader };

};
