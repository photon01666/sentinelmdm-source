// routes/applocker-blocked-files.js — AppLocker blocked-file captures: list, download, delete, admin force-upload.
// Extracted from server.js L6348-6407. 4 routes.
// NOTE: the adjacent uploadBlockedFile() helper + APPLOCKER_AUTO_UPLOAD_MAX_BYTES deliberately STAY in
// server.js — uploadBlockedFile is also called by the IS_WORKER auto-upload poller (server.js ~L16091) —
// and uploadBlockedFile is injected via ctx.
module.exports = ({ app, db, decryptBuffer, decryptText, log, r2Del, r2Get, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked, sha256hex, uploadBlockedFile }) => {
// List captured blocked-file rows for this device — the WebUI cross-references this against the
// live "Check Blocked & Ran" event list (srpActivity()) to decide whether to show a Download
// button (status='uploaded'), a "Force Upload" button (status='skipped_size', admin only), or
// nothing yet (auto-upload poller hasn't run for this path — every 5 min, see the IS_WORKER loop).
app.get('/api/devices/:id/remote-assist/applocker/blocked-files', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const rows = (await db.prepare(
    'SELECT id,path,file_name,size_bytes,status,error,blocked_at,uploaded_at,r2_key FROM applocker_blocked_files WHERE device_id=? ORDER BY blocked_at DESC'
  ).all(req.params.id));
  res.json(rows.map(r => ({
    id: r.id, path: decryptText(r.path), fileName: decryptText(r.file_name), sizeBytes: r.size_bytes,
    status: r.status, error: r.error, blockedAt: r.blocked_at, uploadedAt: r.uploaded_at, hasFile: !!r.r2_key,
  })));
});

app.get('/api/devices/:id/remote-assist/applocker/blocked-files/:fileId/download', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const row = (await db.prepare('SELECT device_id,file_name,r2_key FROM applocker_blocked_files WHERE id=? AND device_id=?').get(req.params.fileId, req.params.id));
  if (!row || !row.r2_key) return res.status(404).json({ error: 'Not uploaded' });
  try {
    const enc = (await r2Get(row.r2_key));
    if (!enc) return res.status(404).json({ error: 'File not found in storage' });
    const buf = decryptBuffer(enc);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${decryptText(row.file_name).replace(/[^a-zA-Z0-9._-]/g, '_')}"`);
    res.setHeader('Content-Length', buf.length);
    res.send(buf);
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Manual early delete -- same access as everything else on this device (owner or admin), no
// separate admin-only gate (unlike force-upload, which pulls a NEW capture; this only removes one
// already sitting here). Ahead of the automatic 7-day TTL trim above, so a reviewed/no-longer-
// needed capture doesn't have to wait out the week.
app.delete('/api/devices/:id/remote-assist/applocker/blocked-files/:fileId', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const row = (await db.prepare('SELECT r2_key FROM applocker_blocked_files WHERE id=? AND device_id=?').get(req.params.fileId, req.params.id));
  if (!row) return res.status(404).json({ error: 'Not found' });
  if (row.r2_key) await r2Del(row.r2_key).catch(() => {});
  (await db.prepare('DELETE FROM applocker_blocked_files WHERE id=? AND device_id=?').run(req.params.fileId, req.params.id));
  log('info', 'AppLocker blocked-file deleted', { deviceId: req.params.id, fileId: req.params.fileId });
  res.json({ ok: true });
});

// Admin-only override past APPLOCKER_AUTO_UPLOAD_MAX_BYTES — matches the ask: auto-upload caps at
// 500MB, but an admin can still force a larger blocked binary up from the WebUI. Accepts a path
// straight from the live "Check Blocked & Ran" list (works whether or not the poller has ever
// touched this path yet) — replaces any existing row for that exact path so a retry doesn't pile
// up duplicate rows.
app.post('/api/devices/:id/remote-assist/applocker/blocked-files/force-upload', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  if (req.session?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  const path = String(req.body?.path || '').trim();
  const blockedAt = Number(req.body?.blockedAt) || Date.now();
  if (!path) return res.status(400).json({ error: 'path is required' });
  try {
    (await db.prepare('DELETE FROM applocker_blocked_files WHERE device_id=? AND path_hash=?').run(req.params.id, sha256hex(path.toLowerCase())));
    const result = (await uploadBlockedFile(req.params.id, path, blockedAt, { force: true }));
    res.json(result);
  } catch (e) {
    log('error', 'AppLocker force-upload failed', { deviceId: req.params.id, path, error: e.message });
    res.status(502).json({ error: e.message });
  }
});
};
