// helpers/geo-backfill.js — best-effort geo enrichment for web analytics.
//
// A HELPER module, not a route module: it registers nothing.
//
//   resolveGeoAndBackfill   export   look up IP via ip-api.com and backfill session rows
//
// CRITICAL privacy invariant: `ip` is used only as the cache key + URL param — it must
// NEVER be passed into any db.prepare(...) call, preserving web_analytics' existing
// "no raw IP retained" privacy property (only the resolved country/city strings are stored).
//
// 5 ctx deps: GEO_LOOKUP_ENABLED (binding L2066), GEO_RATE_BUDGET_PER_MIN (binding L2067),
// _geoCache (binding L2068), db (binding L699), kv (destructure L21).
// The require call must sit at or after L2069; the earliest consumer of the export is L3275,
// so at or before L3274.
//
// relative requires: none

module.exports = ({ GEO_LOOKUP_ENABLED, GEO_RATE_BUDGET_PER_MIN, _geoCache, db, kv }) => {

async function resolveGeoAndBackfill(ip, sessionHash) {
  if (!ip || !sessionHash || !GEO_LOOKUP_ENABLED) return;
  let geo = _geoCache.get(ip);
  if (!geo) {
    const n = await kv.incrWindow('geo:ipapi:calls', 60).catch(() => 0); // cross-replica budget
    if (n > GEO_RATE_BUDGET_PER_MIN) return; // over budget this minute — degrade silently
    try {
      const opts = (typeof AbortSignal !== 'undefined' && AbortSignal.timeout)
        ? { signal: AbortSignal.timeout(3000) } : {};
      const r = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,country,city`, opts);
      const j = /** @type {any} */ (await r.json());
      if (j?.status !== 'success') return;
      geo = { country: (j.country || '').slice(0, 100) || null, city: (j.city || '').slice(0, 100) || null };
      if (_geoCache.size > 20000) _geoCache.clear();
      _geoCache.set(ip, geo);
    } catch { return; } // network/timeout/parse error — swallow entirely
  }
  if (!geo.country && !geo.city) return;
  try {
    // No LIMIT 1 (unlike the `duration` UPDATE) — geo is session-constant, so backfill EVERY
    // still-unresolved row for this session, not just the most recent one.
    await db.prepare(`UPDATE web_analytics SET country=?, city=?
      WHERE session_hash=? AND country IS NULL AND timestamp > ?`)
      .run(geo.country, geo.city, sessionHash, Date.now() - 3_600_000);
  } catch {}
}

  return {
    resolveGeoAndBackfill,
  };
};