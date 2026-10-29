module.exports = ({ app, connectedSockets, db, decryptText, emitToDevice, encryptBuffer, express, isDeviceOnline, kv, log, maybeRespondWithZkPayloads, r2Del, r2Put, randomUUID, redisEnabled, requireAdmin, requireAuth, requireDeviceAccess, requireUnlocked }) => {
// ── OS (GrapheneOS) update status ─────────────────────────────────────────
// Surfaces, for ADMINS only, whether a newer official GrapheneOS stable release
// exists than the source tag the published OTA was built from. The device Updater
// is repointed to our R2 and will NOT auto-pull from GrapheneOS, so this is the
// signal that a security rebuild + republish is due.
const OS_DEVICE = 'raven';
let _osUpstreamCache = { ts: 0, build: null, date: null }; // 1h TTL
async function fetchChannelBuild(url) {
  try {
    const opts = (typeof AbortSignal !== 'undefined' && AbortSignal.timeout)
      ? { signal: AbortSignal.timeout(8000) } : {};
    const r = await fetch(url, opts);
    if (!r.ok) return null;
    const parts = (await r.text()).trim().split(/\s+/);
    if (parts.length < 2) return null;
    return { build: parts[0], date: Number(parts[1]) || null };
  } catch { return null; }
}
async function getUpstreamLatest() {
  if (_osUpstreamCache.build && Date.now() - _osUpstreamCache.ts < 60 * 60 * 1000)
    return _osUpstreamCache;
  const up = await fetchChannelBuild(`https://releases.grapheneos.org/${OS_DEVICE}-stable`);
  if (up) _osUpstreamCache = { ts: Date.now(), build: up.build, date: up.date };
  return _osUpstreamCache;
}
const getSetting = async (k, d = null) => (await db.prepare('SELECT value FROM settings WHERE key=?').get(k))?.value ?? d;

app.get('/api/os-status', requireUnlocked, requireAdmin, async (req, res) => {
  const sourceTag = (await getSetting('os_source_tag'));
  const spl       = (await getSetting('os_spl'));
  const otaUrl    = (await getSetting('os_ota_url', process.env.OTA_PUBLIC_URL || '/')).replace(/\/?$/, '/');
  if (req.query.recheck === '1') _osUpstreamCache = { ts: 0, build: null, date: null };
  const [published, upstream] = await Promise.all([
    fetchChannelBuild(`${otaUrl}${OS_DEVICE}-stable`),
    getUpstreamLatest(),
  ]);
  const upstreamBuild = upstream?.build || null;
  const updateAvailable = !!(upstreamBuild && sourceTag && Number(upstreamBuild) > Number(sourceTag));
  const publishedBuild = published?.build || null;
  // Per-device OS build / SPL (reported by agent 2.6.3.0+). 'current' = on the published OTA build.
  const onlineSet = redisEnabled ? new Set(await kv.smembers('online_devices')) : new Set(connectedSockets.keys());
  const devices = (await db.prepare("SELECT id, name, os_build, security_patch, online FROM devices WHERE platform='android' OR platform IS NULL ORDER BY name").all())
    .map(d => ({
      name:          decryptText(d.name),
      osBuild:       d.os_build || null,
      securityPatch: d.security_patch || null,
      online:        onlineSet ? onlineSet.has(d.id) : d.online === 1,
      current:       !!(publishedBuild && d.os_build && d.os_build === publishedBuild),
    }));
  res.json({
    device: OS_DEVICE,
    sourceTag, spl,
    published: published ? { build: published.build, date: published.date } : null,
    upstream:  upstreamBuild ? { build: upstreamBuild, date: upstream.date } : null,
    updateAvailable,
    upstreamReachable: !!upstreamBuild,
    devices,
  });
});

app.post('/api/os-status', requireUnlocked, requireAdmin, async (req, res) => {
  const { sourceTag, spl, otaUrl } = req.body || {};
  if (sourceTag !== undefined)
    (await db.prepare("INSERT INTO settings (key,value) VALUES ('os_source_tag',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(String(sourceTag).replace(/[^0-9]/g, '').slice(0, 12)));
  if (spl !== undefined)
    (await db.prepare("INSERT INTO settings (key,value) VALUES ('os_spl',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(String(spl).replace(/[^0-9-]/g, '').slice(0, 16)));
  if (otaUrl !== undefined)
    (await db.prepare("INSERT INTO settings (key,value) VALUES ('os_ota_url',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(String(otaUrl).slice(0, 200)));
  log('info', 'OS source tag/SPL updated', { sourceTag, spl });
  res.json({ ok: true });
});

// ── Sideload APK to device ────────────────────────────────────────────────
// Upload APK, store in R2, issue one-time token, emit install_apk command to device.
app.post('/api/devices/:id/push-file', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  const { path: destPath, name: rawName, base64 } = req.body || {};
  if (!base64 || typeof base64 !== 'string') return res.status(400).json({ error: 'No file data received' });
  if (!(await isDeviceOnline(req.params.id))) return res.status(503).json({ error: 'Device offline' });
  if (!destPath) return res.status(400).json({ error: 'Missing path' });
  const fileName = String(rawName || 'file').replace(/[^a-zA-Z0-9._\- ()]/g, '_');
  const byteLen = Math.round(base64.length * 0.75);
  emitToDevice(req.params.id, 'command', { command: 'push_file', path: destPath, name: fileName, base64 });
  log('info', 'File push initiated', { deviceId: req.params.id, dest: destPath, size: byteLen });
  res.json({ ok: true });
});

app.post('/api/devices/:id/install-apk', requireUnlocked, requireAuth,
  express.raw({ type: 'application/octet-stream', limit: '150mb' }),
  async (req, res) => {
    if (!Buffer.isBuffer(req.body) || !req.body.length)
      return res.status(400).json({ error: 'No APK data received' });
    if (!(await isDeviceOnline(req.params.id))) return res.status(503).json({ error: 'Device offline' });
    const { requirePerm } = (() => {
      const session = req.session;
      const isAdmin = session?.role === 'admin';
      const perms = session?.permissions?.[req.params.id] || {};
      const canRun = isAdmin || perms.commands;
      return { requirePerm: canRun };
    })();
    if (!requirePerm) return res.status(403).json({ error: 'Permission denied' });
    const ts = Date.now();
    const safeName = String(req.headers['x-filename'] || 'app.apk').replace(/[^a-zA-Z0-9._-]/g, '_');
    const r2Key = `apks/${req.params.id}_${ts}_${safeName}`;
    try {
      await r2Put(r2Key, encryptBuffer(req.body));
      const token = randomUUID();
      kv.setJSON('installapk:' + token, { r2Key }, 600).catch(() => {});  // 10-min TTL (shared across replicas)
      // Best-effort R2 cleanup after the token's lifetime (consumed or not, the object is
      // no longer needed). Replica-local; the 30-day DB cleanup catches any miss.
      setTimeout(() => { r2Del(r2Key).catch(() => {}); }, 10 * 60 * 1000).unref();
      emitToDevice(req.params.id, 'command', { command: 'install_apk', token });
      log('info', 'APK sideload initiated', { deviceId: req.params.id, file: safeName, size: req.body.length });
      res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
  }
);

// ── New feature API endpoints ─────────────────────────────────────────────

app.get('/api/devices/:id/notifications', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'notification_event'))) return;
  const rows = (await db.prepare('SELECT id,pkg,title,text,timestamp FROM notifications WHERE device_id=? ORDER BY timestamp DESC LIMIT 500')
    .all(req.params.id));
  res.json(rows.map(r => ({ ...r, title: decryptText(r.title), text: decryptText(r.text) })));
});
app.delete('/api/devices/:id/notifications', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  (await db.prepare('DELETE FROM notifications WHERE device_id=?').run(req.params.id));
  res.json({ ok: true });
});

app.get('/api/devices/:id/clipboard', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'clipboard_event'))) return;
  const rows = (await db.prepare('SELECT id,content,timestamp FROM clipboard_events WHERE device_id=? ORDER BY timestamp DESC LIMIT 200')
    .all(req.params.id));
  res.json(rows.map(r => ({ ...r, content: decryptText(r.content) })));
});
app.delete('/api/devices/:id/clipboard', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  (await db.prepare('DELETE FROM clipboard_events WHERE device_id=?').run(req.params.id));
  res.json({ ok: true });
});

app.get('/api/devices/:id/contacts', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'contacts_data'))) return;
  const row = (await db.prepare('SELECT data,timestamp FROM contacts WHERE device_id=? ORDER BY timestamp DESC LIMIT 1').get(req.params.id));
  if (!row) return res.json({ contacts: [], timestamp: null });
  try { res.json({ contacts: JSON.parse(decryptText(row.data)), timestamp: row.timestamp }); }
  catch { res.json({ contacts: [], timestamp: row.timestamp }); }
});

app.get('/api/devices/:id/calendar', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'calendar_data'))) return;
  const row = (await db.prepare('SELECT data,timestamp FROM calendar_events WHERE device_id=? ORDER BY timestamp DESC LIMIT 1').get(req.params.id));
  if (!row) return res.json({ events: [], timestamp: null });
  try { res.json({ events: JSON.parse(decryptText(row.data)), timestamp: row.timestamp }); }
  catch { res.json({ events: [], timestamp: row.timestamp }); }
});


app.get('/api/devices/:id/usage-stats', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'usage_stats_data'))) return;
  const row = (await db.prepare('SELECT data,timestamp FROM usage_stats WHERE device_id=? ORDER BY timestamp DESC LIMIT 1').get(req.params.id));
  if (!row) return res.json({ stats: [], timestamp: null });
  try { res.json({ stats: JSON.parse(row.data), timestamp: row.timestamp }); }
  catch { res.json({ stats: [], timestamp: row.timestamp }); }
});
};
