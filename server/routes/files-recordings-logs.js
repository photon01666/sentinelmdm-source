module.exports = ({ app, ALL_ROWS, checkStorageQuota, db, decryptBuffer, decryptText, deviceOwnerInfo, encryptBuffer, fs, io, kv, log, maybeRespondWithZkPayloads, path, r2Del, r2Get, r2Put, randomUUID, requireAdmin, requireAuth, requireDeviceAccess, requirePerm, requireUnlocked, stmts, streamsDir, uploadsDir }) => {
// ── File manager API ───────────────────────────────────────────────────────
app.get('/api/devices/:id/file-listing', requireDeviceAccess, requirePerm('files'), async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'file_list'))) return;
  res.json(await kv.getJSON('filelist:' + req.params.id));
});

app.get('/api/devices/:id/files', requireDeviceAccess, requirePerm('files'), async (req, res) => {
  res.json((await stmts.listFiles.all(req.params.id)).map(f => ({ ...f, remote_path: decryptText(f.remote_path) })));
});

// Files by item ID — look up device from the file record to check permission
app.get('/api/files/:id/raw', async (req, res) => {
  const row = (await stmts.getFile.get(+req.params.id));
  if (!row) return res.status(404).json({ error: 'Not found' });
  const { ownerUserId } = (await deviceOwnerInfo(row.device_id));
  const isOwner = req.session.account_type === 'public' && req.session.userId === ownerUserId;
  if (req.session.role !== 'admin' && !isOwner) {
    if (req.session.account_type === 'business_sub' && req.session.parent_owner_id !== ownerUserId)
      return res.status(403).json({ error: 'Permission denied: files' });
    const dp = (req.session.permissions || {})[row.device_id] || {};
    if (!dp.files && !dp.commands) return res.status(403).json({ error: 'Permission denied: files' });
  }
  try {
    // Try R2 first; fall back to local disk for files written before R2 migration
    let encBuf = await r2Get(`uploads/${row.filename}`);
    if (!encBuf) {
      const fPath = path.join(uploadsDir, row.filename);
      if (!fs.existsSync(fPath)) return res.status(404).json({ error: 'File not found' });
      encBuf = fs.readFileSync(fPath);
    }
    res.setHeader('Content-Disposition', `attachment; filename="${path.basename(decryptText(row.remote_path))}"`);
    res.send(decryptBuffer(encBuf));
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/files/:id', async (req, res) => {
  const row = (await stmts.getFile.get(+req.params.id));
  if (row) {
    const { ownerUserId } = (await deviceOwnerInfo(row.device_id));
    const isOwner = req.session.account_type === 'public' && req.session.userId === ownerUserId;
    if (req.session.role !== 'admin' && !isOwner) {
      if (req.session.account_type === 'business_sub' && req.session.parent_owner_id !== ownerUserId)
        return res.status(403).json({ error: 'Permission denied: files' });
      const dp = (req.session.permissions || {})[row.device_id] || {};
      if (!dp.files && !dp.commands) return res.status(403).json({ error: 'Permission denied: files' });
    }
    await r2Del(`uploads/${row.filename}`);
    (await stmts.deleteFile.run(req.params.id));
  }
  res.json({ ok: true });
});

// ── Stream recordings ──────────────────────────────────────────────────────
// Save a recording uploaded by the browser after stream stops.
// For ZK-owned devices: the browser ZK-encrypts the assembled blob before upload.
// Server stores the opaque ciphertext; only the owner's browser can decrypt.
app.post('/api/devices/:id/recordings', requireAuth, requireDeviceAccess, async (req, res) => {
  const { type, data, duration, zk, dek_wrapped } = req.body;
  if (!type || !data || !['audio', 'video', 'screen'].includes(type)) return res.status(400).json({ error: 'Invalid type or data' });
  try {
    const id  = randomUUID();
    const ext = type === 'audio' ? 'wav' : 'webm';
    const filename = `${id}.${ext}`;
    const rawBuf   = Buffer.from(data, 'base64');
    // Storage quota: block new recordings when the account is over 1 GB.
    const ownerUserId = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(req.params.id))?.owner_user_id;
    if (ownerUserId) {
      const quota = await checkStorageQuota(ownerUserId, rawBuf.length);
      if (!quota.ok) {
        io.to(`monitor:${req.params.id}`).emit('storage_quota_exceeded', { deviceId: req.params.id, used: quota.used, quota: quota.quota, needed: rawBuf.length });
        log('warn', 'Recording blocked — storage quota exceeded', { deviceId: req.params.id, ownerUserId, used: quota.used, needed: rawBuf.length });
        return res.status(413).json({ error: 'Storage quota exceeded', used: quota.used, quota: quota.quota });
      }
    }
    if (zk) {
      // ZK-encrypted recording: store the opaque ciphertext as-is (browser encrypted it).
      // dek_wrapped contains the ECDH-wrapped DEK — only owner can unwrap.
      await r2Put(`streams/${filename}`, rawBuf);
      (await db.prepare(`INSERT INTO stream_recordings (id, device_id, type, filename, size, duration, captured_at, zk_encrypted, dek_wrapped)
                  VALUES (?,?,?,?,?,?,?,?,?)`)
        .run(id, req.params.id, type, filename, rawBuf.length, Math.round(duration) || 0, Date.now(), 1,
             dek_wrapped ? (typeof dek_wrapped === 'string' ? dek_wrapped : JSON.stringify(dek_wrapped)) : null));
    } else {
      await r2Put(`streams/${filename}`, encryptBuffer(rawBuf));
      (await db.prepare(`INSERT INTO stream_recordings (id, device_id, type, filename, size, duration, captured_at, zk_encrypted, dek_wrapped)
                  VALUES (?,?,?,?,?,?,?,?,?)`)
        .run(id, req.params.id, type, filename, rawBuf.length, Math.round(duration) || 0, Date.now(), 0, null));
    }
    res.json({ id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// List recordings for a device.
app.get('/api/devices/:id/recordings', requireAuth, requireDeviceAccess, async (req, res) => {
  const type = req.query.type;
  const rows = type
    ? (await db.prepare(`SELECT id, type, size, duration, captured_at, zk_encrypted FROM stream_recordings WHERE device_id=? AND type=? ORDER BY captured_at DESC LIMIT 50`).all(req.params.id, type))
    : (await db.prepare(`SELECT id, type, size, duration, captured_at, zk_encrypted FROM stream_recordings WHERE device_id=? ORDER BY captured_at DESC LIMIT 50`).all(req.params.id));
  res.json(rows);
});

// Download a recording.
// ZK recordings: return JSON {zk:true, payload, dek_wrapped} — browser decrypts.
// Plaintext recordings: server-decrypt and return raw bytes (legacy behavior).
app.get('/api/recordings/:recId/download', requireAuth, async (req, res) => {
  const row = (await db.prepare(`SELECT * FROM stream_recordings WHERE id=?`).get(req.params.recId));
  if (!row) return res.status(404).json({ error: 'Not found' });
  // Public users access devices they own via the ownership model (no permissions-map entries),
  // mirroring /api/media/:id and /api/files/:id/raw. Without this, the owner's own ZK recording
  // download 403s and the browser hangs on "Decrypting recording…".
  const { ownerUserId } = (await deviceOwnerInfo(row.device_id));
  const isOwner = req.session.account_type === 'public' && req.session.userId === ownerUserId;
  if (req.session.role !== 'admin' && !isOwner) {
    if (req.session.account_type === 'business_sub' && req.session.parent_owner_id !== ownerUserId)
      return res.status(403).json({ error: 'Permission denied' });
    const dp = (req.session.permissions || {})[row.device_id] || {};
    if (!dp.stream && !dp.commands) return res.status(403).json({ error: 'Permission denied' });
  }
  try {
    let buf = await r2Get(`streams/${row.filename}`);
    if (!buf) {
      const fPath = path.join(streamsDir, row.filename);
      if (!fs.existsSync(fPath)) return res.status(404).json({ error: 'Recording not found' });
      buf = fs.readFileSync(fPath);
    }
    if (row.zk_encrypted) {
      // ZK recording: return encrypted blob + dek_wrapped so browser can decrypt
      const dw = row.dek_wrapped ? JSON.parse(row.dek_wrapped) : null;
      res.json({ zk: true, payload: buf.toString('base64'), dek_wrapped: dw });
    } else {
      const ext  = row.type === 'audio' ? 'wav' : 'webm';
      const mime = row.type === 'audio' ? 'audio/wav' : 'video/webm';
      const ts   = new Date(row.captured_at).toISOString().replace(/[:.]/g, '-').slice(0, 19);
      res.setHeader('Content-Type', mime);
      res.setHeader('Content-Disposition', `attachment; filename="${row.type}-${row.device_id.slice(0,8)}-${ts}.${ext}"`);
      res.send(decryptBuffer(buf));
    }
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Delete a recording
app.delete('/api/recordings/:recId', requireAuth, async (req, res) => {
  const row = (await db.prepare(`SELECT * FROM stream_recordings WHERE id=?`).get(req.params.recId));
  if (!row) return res.json({ ok: true });
  const { ownerUserId } = (await deviceOwnerInfo(row.device_id));
  const isOwner = req.session.account_type === 'public' && req.session.userId === ownerUserId;
  if (req.session.role !== 'admin' && !isOwner) {
    if (req.session.account_type === 'business_sub' && req.session.parent_owner_id !== ownerUserId)
      return res.status(403).json({ error: 'Permission denied' });
    const dp = (req.session.permissions || {})[row.device_id] || {};
    if (!dp.stream && !dp.commands) return res.status(403).json({ error: 'Permission denied' });
  }
  await r2Del(`streams/${row.filename}`);
  (await db.prepare(`DELETE FROM stream_recordings WHERE id=?`).run(req.params.recId));
  res.json({ ok: true });
});

// ── Device logs (network + security) ──────────────────────────────────────
app.get('/api/devices/:id/network-logs', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'network_logs'))) return;
  const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
  const type   = /** @type {any} */ (req.query.type);
  const before = parseInt(/** @type {any} */ (req.query.before), 10) || 0;  // cursor: only rows older than this ts
  // ?limit=all lifts the page cap so the Download / Copy All / Ask-AI exports pull the
  // FULL retained history (not just the paginated tab window). The tab passes a numeric limit.
  const limit  = (req.query.limit === 'all') ? ALL_ROWS : Math.min(parseInt(/** @type {any} */ (req.query.limit), 10) || 3000, 5000);
  const conds  = ['device_id=?', 'timestamp>=?'];
  const args   = [req.params.id, cutoff];
  if (type)       { conds.push('type=?');      args.push(type); }
  if (before > 0) { conds.push('timestamp<?'); args.push(before); }
  args.push(limit);
  const rows = (await db.prepare(
    `SELECT id,type,data,timestamp FROM device_network_logs WHERE ${conds.join(' AND ')} ORDER BY timestamp DESC LIMIT ?`
  ).all(...args));
  res.json(rows.map(r => {
    try { return { id: r.id, timestamp: r.timestamp, ...JSON.parse(decryptText(r.data)) }; }
    catch { return { id: r.id, type: r.type, timestamp: r.timestamp }; }
  }));
});

app.get('/api/devices/:id/security-logs', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'security_logs'))) return;
  const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
  const before = parseInt(/** @type {any} */ (req.query.before), 10) || 0;  // cursor: only rows older than this ts
  // ?limit=all lifts the cap for the full-history Download / Copy All / Ask-AI exports.
  const limit  = (req.query.limit === 'all') ? ALL_ROWS : Math.min(parseInt(/** @type {any} */ (req.query.limit), 10) || 1500, 3000);
  const conds  = ['device_id=?', 'timestamp>=?'];
  const args   = [req.params.id, cutoff];
  if (before > 0) { conds.push('timestamp<?'); args.push(before); }
  args.push(limit);
  const rows = (await db.prepare(
    `SELECT id,tag,name,data,timestamp FROM device_security_logs WHERE ${conds.join(' AND ')} ORDER BY timestamp DESC LIMIT ?`
  ).all(...args));
  res.json(rows.map(r => ({
    id: r.id, tag: r.tag, name: r.name || '', timestamp: r.timestamp, data: decryptText(r.data)
  })));
});

app.delete('/api/devices/:id/network-logs', requireUnlocked, requireAdmin, async (req, res) => {
  (await db.prepare('DELETE FROM device_network_logs WHERE device_id=?').run(req.params.id));
  res.json({ ok: true });
});

app.delete('/api/devices/:id/security-logs', requireUnlocked, requireAdmin, async (req, res) => {
  (await db.prepare('DELETE FROM device_security_logs WHERE device_id=?').run(req.params.id));
  res.json({ ok: true });
});
};
