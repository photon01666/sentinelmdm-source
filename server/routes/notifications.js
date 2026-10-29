// routes/notifications.js — Admin notif-config, per-user notif-prefs, user alert center.
// Extracted from server.js L9636-9765. 9 routes + alertScopeUserId helper.
module.exports = ({ app, AI_REPORT_CATEGORIES, SIGNAL_HYBRID_GROUP, SIGNAL_SENDER, USER_ALERT_CATEGORIES,
  db, isDiscordWebhookUrl, log, notifyAdmin, requireAdmin, requireAuth }) => {

// ── Admin: notification provider configuration ────────────────────────────
app.get('/api/admin/notif-config', requireAdmin, async (_req, res) => {
  const get = async key => (await db.prepare("SELECT value FROM settings WHERE key=?").get(key))?.value || '';
  res.json({
    signal_configured: !!SIGNAL_SENDER,
    signal_hybrid_group_configured: !!SIGNAL_HYBRID_GROUP,
    discord_webhook: (await get('notif_discord_webhook')),
  });
});

app.post('/api/admin/notif-config', requireAdmin, async (req, res) => {
  const { discord_webhook } = req.body || {};
  const upsert = db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value");
  if (discord_webhook !== undefined) {
    const v = (discord_webhook || '').trim();
    if (v && !isDiscordWebhookUrl(v)) return res.status(400).json({ error: 'Invalid Discord webhook URL' });
    (await upsert.run('notif_discord_webhook', v));
  }
  log('info', 'Admin notification config updated', { by: req.session?.username });
  res.json({ ok: true });
});

// Test notification — sends a test message to all configured admin channels
app.post('/api/admin/notif-test', requireAdmin, async (req, res) => {
  const user = req.session?.username || 'admin';
  const ts   = new Date().toLocaleString();
  await notifyAdmin(`🔔 Test Notification\nSent by: ${user}\nTime: ${ts}\nAll configured admin channels are working.`);
  res.json({ ok: true });
});

// ── Per-user notification preferences ────────────────────────────────────────
app.get('/api/users/me/notif-prefs', requireAuth, async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.json({});
  const user = (await db.prepare('SELECT notif_prefs FROM users WHERE id=?').get(uid));
  try { res.json(JSON.parse(user?.notif_prefs || '{}')); } catch { res.json({}); }
});

app.patch('/api/users/me/notif-prefs', requireAuth, async (req, res) => {
  const uid = req.session.userId;
  if (!uid) return res.status(403).json({ error: 'Not a user account' });
  const user = (await db.prepare('SELECT notif_prefs FROM users WHERE id=?').get(uid));
  if (!user) return res.status(404).json({ error: 'User not found' });
  const current = (() => { try { return JSON.parse(user.notif_prefs || '{}'); } catch { return {}; } })();
  const { discord_webhook, email_alerts, push_alerts, events, ai_reports } = req.body || {};
  if (discord_webhook !== undefined) {
    const v = (discord_webhook || '').trim();
    if (v && !isDiscordWebhookUrl(v)) return res.status(400).json({ error: 'Invalid Discord webhook URL' });
    current.discord_webhook = v;
  }
  if (email_alerts    !== undefined) current.email_alerts = !!email_alerts;
  if (push_alerts     !== undefined) current.push_alerts = !!push_alerts;
  if (events && typeof events === 'object') {
    current.events = current.events || {};
    for (const k of USER_ALERT_CATEGORIES) if (events[k] !== undefined) current.events[k] = !!events[k];
  }
  if (ai_reports && typeof ai_reports === 'object') {
    current.ai_reports = current.ai_reports || {};
    for (const k of AI_REPORT_CATEGORIES) if (ai_reports[k] !== undefined) current.ai_reports[k] = !!ai_reports[k];
  }
  (await db.prepare('UPDATE users SET notif_prefs=? WHERE id=?').run(JSON.stringify(current), uid));
  res.json({ ok: true });
});

// ── User alert center ("All Alerts" panel) ───────────────────────────────────
function alertScopeUserId(req) {
  return (req.session.account_type === 'business_sub' && req.session.parent_owner_id)
    ? req.session.parent_owner_id
    : req.session.userId;
}

app.get('/api/users/me/alerts', requireAuth, async (req, res) => {
  const uid = alertScopeUserId(req);
  if (!uid) return res.status(403).json({ error: 'Not a user account' });
  const rows = (await db.prepare(
    `SELECT id, device_id, category, message, audit_result, proposed_fix, created_at, archived_at FROM user_alerts
     WHERE user_id=? ORDER BY created_at DESC LIMIT 500`
  ).all(String(uid)));
  // False-positive alerts: rows in alert_auto_audits with false_positive=1, joined back to
  // user_alerts so the WebUI can display them in their own tab.
  let falsePositives = [];
  try {
    falsePositives = (await db.prepare(
      `SELECT ua.id, ua.device_id, ua.category, ua.message, ua.audit_result, ua.created_at, aa.suppression_signature
       FROM user_alerts ua
       INNER JOIN alert_auto_audits aa ON aa.alert_id = ua.id
       WHERE ua.user_id=? AND aa.false_positive=1
       ORDER BY ua.created_at DESC LIMIT 200`
    ).all(String(uid)));
  } catch (_) { /* table may not exist yet */ }
  const activeCount = rows.filter(r => !r.archived_at).length;
  res.json({ alerts: rows, activeCount, falsePositives });
});

app.post('/api/users/me/alerts/clear-history', requireAuth, async (req, res) => {
  const uid = alertScopeUserId(req);
  if (!uid) return res.status(403).json({ error: 'Not a user account' });
  const info = (await db.prepare('DELETE FROM user_alerts WHERE user_id=? AND archived_at IS NOT NULL').run(String(uid)));
  res.json({ ok: true, removed: info.changes });
});

app.post('/api/users/me/alerts/:id/archive', requireAuth, async (req, res) => {
  const uid = alertScopeUserId(req);
  const id = Number(req.params.id);
  if (!uid) return res.status(403).json({ error: 'Not a user account' });
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid alert id' });
  const info = (await db.prepare('UPDATE user_alerts SET archived_at=? WHERE id=? AND user_id=? AND archived_at IS NULL')
    .run(Date.now(), id, String(uid)));
  res.json({ ok: info.changes > 0 });
});

app.post('/api/users/me/alerts/:id/delete', requireAuth, async (req, res) => {
  const uid = alertScopeUserId(req);
  const id = Number(req.params.id);
  if (!uid) return res.status(403).json({ error: 'Not a user account' });
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid alert id' });
  const info = (await db.prepare('DELETE FROM user_alerts WHERE id=? AND user_id=?').run(id, String(uid)));
  res.json({ ok: info.changes > 0 });
});

// POST /api/users/me/alerts/batch-delete — permanently delete multiple alerts by ID
app.post('/api/users/me/alerts/batch-delete', requireAuth, async (req, res) => {
  const uid = alertScopeUserId(req);
  if (!uid) return res.status(403).json({ error: 'Not a user account' });
  const ids = (req.body.ids || []).map(Number).filter(n => Number.isInteger(n) && n > 0);
  if (!ids.length) return res.status(400).json({ error: 'No valid IDs provided' });
  const placeholders = ids.map(() => '?').join(',');
  const info = (await db.prepare(`DELETE FROM user_alerts WHERE id IN (${placeholders}) AND user_id=?`).run(...ids, String(uid)));
  res.json({ ok: true, removed: info.changes });
});

// POST /api/users/me/alerts/clear-day — permanently delete all alerts created on a given UTC day
// Body: { date: "2026-08-24" } — UTC calendar date
app.post('/api/users/me/alerts/clear-day', requireAuth, async (req, res) => {
  const uid = alertScopeUserId(req);
  if (!uid) return res.status(403).json({ error: 'Not a user account' });
  const dateStr = String(req.body.date || '');
  if (!/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) return res.status(400).json({ error: 'Invalid date — expected YYYY-MM-DD (UTC)' });
  const dayStart = new Date(dateStr + 'T00:00:00Z').getTime();
  const dayEnd   = new Date(dateStr + 'T23:59:59.999Z').getTime();
  const info = (await db.prepare('DELETE FROM user_alerts WHERE user_id=? AND created_at>=? AND created_at<=?').run(String(uid), dayStart, dayEnd));
  res.json({ ok: true, removed: info.changes, date: dateStr });
});

};
