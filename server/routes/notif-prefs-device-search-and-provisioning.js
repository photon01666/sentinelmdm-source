// routes/notif-prefs-device-search-and-provisioning.js — per-user notification prefs GET/PATCH
// (/api/users/:id/notif-prefs), notif-test, admin global device search, admin device provisioning.
// Extracted from server.js L6115-6248. 5 routes.
module.exports = ({ app, USER_ALERT_CATEGORIES, db, decryptText, deviceStatus, encryptText, io,
  isDiscordWebhookUrl, kv, log, notifyUser, randomUUID, redisEnabled, requireAdmin, requireAuth,
  stmts }) => {

// Admin can GET/PATCH any user's prefs. A public user can also GET/PATCH their own.
app.get('/api/users/:id/notif-prefs', requireAuth, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  // Admin can access any user; public users can only access their own
  if (req.session.role !== 'admin' && req.session.userId !== targetId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const user = (await db.prepare('SELECT notif_prefs FROM users WHERE id=?').get(targetId));
  if (!user) return res.status(404).json({ error: 'User not found' });
  try {
    res.json(JSON.parse(user.notif_prefs || '{}'));
  } catch {
    res.json({});
  }
});

app.patch('/api/users/:id/notif-prefs', requireAuth, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (req.session.role !== 'admin' && req.session.userId !== targetId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const user = (await db.prepare('SELECT id, notif_prefs FROM users WHERE id=?').get(targetId));
  if (!user) return res.status(404).json({ error: 'User not found' });

  const current = (() => { try { return JSON.parse(user.notif_prefs || '{}'); } catch { return {}; } })();
  const { discord_webhook, email_alerts, events } = req.body || {};
  if (discord_webhook !== undefined) {
    const v = (discord_webhook || '').trim();
    if (v && !isDiscordWebhookUrl(v)) return res.status(400).json({ error: 'Invalid Discord webhook URL' });
    current.discord_webhook = v;
  }
  if (email_alerts    !== undefined) current.email_alerts = !!email_alerts;
  if (events && typeof events === 'object') {
    current.events = current.events || {};
    for (const k of USER_ALERT_CATEGORIES) if (events[k] !== undefined) current.events[k] = !!events[k];
  }

  (await db.prepare('UPDATE users SET notif_prefs=? WHERE id=?')
    .run(JSON.stringify(current), targetId));
  res.json({ ok: true });
});

// Test user notification — sends a test message to the user's configured channels
app.post('/api/users/:id/notif-test', requireAuth, async (req, res) => {
  const targetId = parseInt(req.params.id, 10);
  if (req.session.role !== 'admin' && req.session.userId !== targetId) {
    return res.status(403).json({ error: 'Forbidden' });
  }
  const user = (await db.prepare('SELECT username FROM users WHERE id=?').get(targetId));
  if (!user) return res.status(404).json({ error: 'User not found' });
  const ts = new Date().toLocaleString();
  await notifyUser(targetId, `🔔 Test Notification\nUser: ${user.username}\nTime: ${ts}\nYour notification channel is configured correctly.`);
  res.json({ ok: true });
});

// ── Global device search (admin only — searches across all devices/users) ──
app.get('/api/devices/search', requireAdmin, async (req, res) => {
  const q      = (/** @type {string} */ (req.query.q || '')).trim().toLowerCase();
  const status = req.query.status; // 'online'|'offline'|undefined=all
  const userId = req.query.user_id ? parseInt(/** @type {any} */ (req.query.user_id)) : null;

  // Demo devices are synthetic sample data private to their owner — never surfaced to admin,
  // even via a targeted user_id search (mirrors GET /api/devices).
  let sql = `SELECT d.*, t.ip_address, t.model_plain, d.owner_user_id AS dev_owner
             FROM devices d LEFT JOIN device_telemetry t ON d.id=t.device_id WHERE COALESCE(d.is_demo,0)=0`;
  const params = [];
  if (status === 'online')  { sql += ' AND d.online=1'; }
  if (status === 'offline') { sql += ' AND d.online=0'; }
  if (userId !== null) {
    // Admin users "own" the unassigned admin-fleet (owner_user_id NULL) — include those when an
    // admin is selected so the admin can filter to their fleet. Non-admins → exact owner match.
    const selRole = (await db.prepare('SELECT role FROM users WHERE id=?').get(userId))?.role;
    if (selRole === 'admin') {
      sql += ' AND (d.owner_user_id=? OR t.owner_user_id=? OR d.owner_user_id IS NULL)';
    } else {
      sql += ' AND (d.owner_user_id=? OR t.owner_user_id=?)';
    }
    params.push(userId, userId);
  }

  let rows = (await db.prepare(sql + ' ORDER BY d.last_seen DESC LIMIT 300').all(...params));

  // Decrypt name/model and apply text filter (post-decrypt, since columns are encrypted)
  rows = await Promise.all(rows.map(async r => ({
    ...r,
    name:            decryptText(r.name),
    model:           decryptText(r.model),
    android_version: decryptText(r.android_version),
    last_lat: r.last_lat ? (parseFloat(decryptText(String(r.last_lat))) || null) : null,
    last_lng: r.last_lng ? (parseFloat(decryptText(String(r.last_lng))) || null) : null,
    status: (redisEnabled ? (await kv.getJSON('devstate:' + r.id))?.status : null) ?? deviceStatus.get(r.id) ?? null,
  })));

  if (q) {
    rows = rows.filter(r =>
      (r.name        || '').toLowerCase().includes(q) ||
      (r.model       || '').toLowerCase().includes(q) ||
      (r.model_plain || '').toLowerCase().includes(q) ||
      (r.ip_address  || '').includes(q) ||
      (r.id          || '').toLowerCase().includes(q)
    );
  }
  res.json(rows);
});

// ── Admin device provisioning ──────────────────────────────────────────────
app.post('/api/admin/provision-device', requireAdmin, async (req, res) => {
  const { userId, deviceName, deviceModel } = req.body;
  if (!userId) return res.status(400).json({ error: 'userId required' });
  const user = (await db.prepare('SELECT * FROM users WHERE id=?').get(userId));
  if (!user)             return res.status(404).json({ error: 'User not found' });
  if (user.status !== 'active') return res.status(400).json({ error: 'User account is not active' });

  const deviceId = randomUUID();
  const name     = (deviceName || `${user.username}'s Device`).slice(0, 64);
  const model    = (deviceModel || '').slice(0, 64);

  (await db.prepare(`INSERT INTO devices (id,name,model,android_version,battery,last_seen,online,platform,owner_user_id)
    VALUES (?,?,?,?,NULL,?,0,'android',?)`)
    .run(deviceId, encryptText(name), encryptText(model), encryptText(''), Date.now(), userId));

  // Also grant the user full device-scoped permissions on this device
  const userRow = (await stmts.getUserById.get(userId));
  const perms   = JSON.parse(decryptText(userRow.permissions) || '{}');
  perms[deviceId] = {
    location: true, photos: true, audio: true, screenshots: true, stream: true,
    network: true, files: true, calls: true, sms: true, apps: true, commands: true,
  };
  (await stmts.updateUserPerms.run(encryptText(JSON.stringify(perms)), userId));

  io.emit('devices_updated');
  log('info', 'Device provisioned for user', { deviceId, userId, username: user.username });
  res.json({ ok: true, deviceId, name });
});
};
