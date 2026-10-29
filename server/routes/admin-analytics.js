// routes/admin-analytics.js — marketing-site web-analytics dashboard + purge (admin only).
// Extracted from server.js. Deps injected; classifyBotUA is a server.js helper (hoisted).

module.exports = function registerAdminAnalyticsRoutes({ app, db, requireAdmin, classifyBotUA, isPg }) {
  // Analytics stats (admin only)
  app.get('/api/admin/analytics', requireAdmin, async (req, res) => {
    try {
      const days = Math.min(Math.max(parseInt(/** @type {any} */ (req.query.days)) || 30, 1), 365);
      const cutoff = Date.now() - days * 86_400_000;
      const todayStart = new Date(); todayStart.setUTCHours(0, 0, 0, 0);
      const total_views  = (await db.prepare('SELECT COUNT(*) AS c FROM web_analytics WHERE timestamp > ?').get(cutoff))?.c || 0;
      const unique_today = (await db.prepare('SELECT COUNT(DISTINCT session_hash) AS c FROM web_analytics WHERE timestamp > ?')
                             .get(todayStart.getTime()))?.c || 0;
      const avg_duration = (await db.prepare('SELECT AVG(duration_seconds) AS a FROM web_analytics WHERE timestamp > ? AND duration_seconds > 0')
                             .get(cutoff))?.a || 0;
      // date(ts,'unixepoch') is SQLite-only — Postgres needs to_timestamp/to_char. Group by UTC day on both.
      const dayExpr = isPg
        ? "to_char(to_timestamp(timestamp/1000) AT TIME ZONE 'UTC', 'YYYY-MM-DD')"
        : "date(timestamp/1000,'unixepoch')";
      const daily  = (await db.prepare(`SELECT ${dayExpr} AS day, COUNT(*) AS views
                                 FROM web_analytics WHERE timestamp > ?
                                 GROUP BY day ORDER BY day`).all(cutoff));
      const recent = (await db.prepare('SELECT * FROM web_analytics ORDER BY timestamp DESC LIMIT 100').all());

      // ── Quick-win aggregates (all range-aware via `cutoff`) ──────────────────
      const top_pages = (await db.prepare(
        `SELECT path, COUNT(*) AS views FROM web_analytics WHERE timestamp > ?
         GROUP BY path ORDER BY views DESC LIMIT 10`).all(cutoff));
      const os_breakdown = (await db.prepare(
        `SELECT COALESCE(os,'Unknown') AS os, COUNT(*) AS views FROM web_analytics
         WHERE timestamp > ? GROUP BY os ORDER BY views DESC`).all(cutoff));
      const browser_breakdown = (await db.prepare(
        `SELECT COALESCE(browser,'Unknown') AS browser, COUNT(*) AS views FROM web_analytics
         WHERE timestamp > ? GROUP BY browser ORDER BY views DESC`).all(cutoff));
      const device_breakdown = (await db.prepare(
        `SELECT COALESCE(device_type,'desktop') AS device_type, COUNT(*) AS views FROM web_analytics
         WHERE timestamp > ? GROUP BY device_type ORDER BY views DESC`).all(cutoff));
      const bounceRow = (await db.prepare(
        `SELECT SUM(CASE WHEN cnt=1 THEN 1 ELSE 0 END) AS single_page, COUNT(*) AS total_sessions
         FROM (SELECT session_hash, COUNT(*) AS cnt FROM web_analytics WHERE timestamp > ? GROUP BY session_hash) t`
      ).get(cutoff));
      const bounce_rate = bounceRow?.total_sessions ? Math.round(bounceRow.single_page / bounceRow.total_sessions * 100) : 0;
      // Trend vs. the immediately preceding window of equal length.
      const prevCutoffStart = cutoff - days * 86_400_000;
      const prev_total_views = (await db.prepare(
        `SELECT COUNT(*) AS c FROM web_analytics WHERE timestamp > ? AND timestamp <= ?`
      ).get(prevCutoffStart, cutoff))?.c || 0;
      const trend_pct = prev_total_views > 0 ? Math.round((total_views - prev_total_views) / prev_total_views * 100) : null;
      // "Active now" — fixed 5-minute window, intentionally independent of the `days` selector.
      const active_now = (await db.prepare(
        `SELECT COUNT(DISTINCT session_hash) AS c FROM web_analytics WHERE timestamp > ?`
      ).get(Date.now() - 5 * 60 * 1000))?.c || 0;

      // Traffic-source breakdown — `referrer`/`utm_*` are only ever set on a session's entry
      // pageview (see POST /api/analytics/pageview), so these are inherently per-SESSION, not
      // per-pageview, counts.
      const top_referrers = (await db.prepare(
        `SELECT referrer, COUNT(*) AS c FROM web_analytics
         WHERE timestamp > ? AND referrer IS NOT NULL GROUP BY referrer ORDER BY c DESC LIMIT 10`).all(cutoff));
      const top_campaigns = (await db.prepare(
        `SELECT utm_source, utm_medium, utm_campaign, COUNT(*) AS c FROM web_analytics
         WHERE timestamp > ? AND utm_source IS NOT NULL
         GROUP BY utm_source, utm_medium, utm_campaign ORDER BY c DESC LIMIT 10`).all(cutoff));

      // Geo breakdown — backfilled best-effort by resolveGeoAndBackfill() after each pageview.
      const top_countries = (await db.prepare(
        `SELECT country, COUNT(*) AS c FROM web_analytics
         WHERE timestamp > ? AND country IS NOT NULL GROUP BY country ORDER BY c DESC LIMIT 10`).all(cutoff));
      const top_cities = (await db.prepare(
        `SELECT city, country, COUNT(*) AS c FROM web_analytics
         WHERE timestamp > ? AND city IS NOT NULL GROUP BY city, country ORDER BY c DESC LIMIT 10`).all(cutoff));

      // Bot traffic (marketing-site URL scanners) — separate counter + recent list.
      const bot_total  = (await db.prepare('SELECT COUNT(*) AS c FROM bot_traffic WHERE timestamp > ?').get(cutoff))?.c || 0;
      const bot_unique = (await db.prepare('SELECT COUNT(DISTINCT ip) AS c FROM bot_traffic WHERE timestamp > ?').get(cutoff))?.c || 0;
      // Crawler (legit search-engine bot) vs scanner (everything else), classified over the FULL
      // cutoff window (not just the 100-row recent slice) — a scanner can generate far more hits.
      const bot_ua_counts = (await db.prepare(
        `SELECT ua, COUNT(*) AS c FROM bot_traffic WHERE timestamp > ? GROUP BY ua`).all(cutoff));
      let bot_crawler_total = 0, bot_scanner_total = 0;
      for (const row of bot_ua_counts) {
        if (classifyBotUA(row.ua) === 'crawler') bot_crawler_total += row.c; else bot_scanner_total += row.c;
      }
      const bot_recent = (await db.prepare('SELECT * FROM bot_traffic ORDER BY timestamp DESC LIMIT 100').all())
        .map(r => ({ ...r, kind: classifyBotUA(r.ua) }));

      res.json({ total_views, unique_today, avg_duration: Math.round(avg_duration), trend_pct, active_now, bounce_rate,
                 daily, recent, top_pages, os_breakdown, browser_breakdown, device_breakdown,
                 top_referrers, top_campaigns, top_countries, top_cities,
                 bot_total, bot_unique, bot_crawler_total, bot_scanner_total, bot_recent });
    } catch (e) { res.status(500).json({ error: 'Analytics query failed' }); }
  });

  // Purge all analytics data (admin only, destructive)
  app.delete('/api/admin/analytics/purge', requireAdmin, async (req, res) => {
    try {
      const a = (await db.prepare('DELETE FROM web_analytics').run());
      const b = (await db.prepare('DELETE FROM bot_traffic').run());
      res.json({ ok: true, deleted: (a?.changes || 0) + (b?.changes || 0) });
    } catch (e) { res.status(500).json({ error: 'Purge failed' }); }
  });
};
