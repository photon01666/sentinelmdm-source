// routes/device-media-zk.js — Device locations/status/media/network data, owner storage
// quota + media wipe, ZK payload/key management, and ZK stream chunks/sessions.
// Extracted from server.js L4604-4977. 17 routes.
module.exports = ({ app, STORAGE_QUOTA_BYTES, calculateStorageBytes, db, decryptText, deviceOwnerInfo, io,
  log, maybeRespondWithZkPayloads, r2Del, requireAuth, requireDeviceAccess, requirePerm, stmts, updateDeviceOwner }) => {

app.get('/api/devices/:id/locations', requireDeviceAccess, requirePerm('location'), async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'location'))) return;
  const rows = (await stmts.locationHistory.all(req.params.id));
  res.json(rows.map(r => {
    try {
      const loc = JSON.parse(decryptText(r.data));
      return { id: r.id, device_id: r.device_id, timestamp: r.timestamp, ...loc };
    } catch { return r; }
  }));
});

app.delete('/api/devices/:id/locations', requireDeviceAccess, requirePerm('location'), async (req, res) => {
  (await stmts.delDevLocs.run(req.params.id));
  (await db.prepare('UPDATE devices SET last_lat=NULL,last_lng=NULL WHERE id=?').run(req.params.id));
  io.emit('devices_updated');
  log('info', 'Location history cleared', { deviceId: req.params.id });
  res.json({ ok: true });
});

app.get('/api/devices/:id/status-events', requireDeviceAccess, async (req, res) => {
  const rows = (await stmts.listStatusEvents.all(req.params.id));
  res.json(rows.map(r => {
    try { return { ...r, data: JSON.parse(decryptText(r.data)) }; }
    catch { return r; }
  }));
});

const MEDIA_TYPE_PERM = { photo: 'photos', audio: 'audio', screencapture: 'screenshots', unlock_photo: 'photos' };

// Fixed CBR bitrate the agent records at (AudioHelper.kt `setAudioEncodingBitRate(64_000)`) — lets
// us estimate an audio clip's duration from its decoded byte size without parsing the M4A/AAC
// container (no ffmpeg/media-probe dependency in this server image).
const AUDIO_CLIP_BITRATE_BPS = 64_000;

app.get('/api/devices/:id/media', requireDeviceAccess, async (req, res) => {
  // For ZK-owned devices, filter by the requested type so unlock_photo, photo, screencapture
  // etc. go to the correct UI section. Without filtering, all types are mixed together and
  // unlock photos appear in the Photos grid while Unlock Attempts shows "none".
  // 'audio_segment' = chunked record_audio uploads on ZK devices (one row per ~60s segment, see
  // [[audio-chunked-recording-segments]] / the audio_segment socket handler) — always queried
  // alongside 'audio' (legacy single-shot clips) so the WebUI can group segments by session.
  const zkMediaTypes = ['photo', 'audio', 'audio_segment', 'screencapture', 'unlock_photo', 'screen_frame'];
  const type = /** @type {any} */ (req.query.type);
  const zkTypes = type === 'audio' ? ['audio', 'audio_segment']
    : (type && zkMediaTypes.includes(type)) ? [type] : zkMediaTypes;
  if ((await maybeRespondWithZkPayloads(req, res, ...zkTypes))) return;
  if (req.session.role !== 'admin') {
    const dp = (req.session.permissions || {})[req.params.id] || {};
    const perm = MEDIA_TYPE_PERM[type];
    if (perm && !dp[perm] && !dp.commands)
      return res.status(403).json({ error: `Permission denied: ${perm}` });
  }
  if (type === 'unlock_photo') return res.json((await stmts.mediaListUnlock.all(req.params.id)));
  // Audio clips: derive size_bytes/duration_sec for display (the `media` table has no size/
  // duration columns — see AUDIO_CLIP_BITRATE_BPS). Requires decrypting `data` to measure the
  // base64 length, so this uses its own query and strips `data` back out before responding —
  // the list must never carry full clip payloads (that's what GET /api/media/:id is for).
  if (type === 'audio') {
    const rows = (await stmts.mediaListAudio.all(req.params.id));
    return res.json(rows.map(({ data, ...row }) => {
      let size_bytes = null, duration_sec = null;
      try {
        const b64 = decryptText(data);
        size_bytes = Math.floor(b64.length * 3 / 4);
        duration_sec = Math.round(size_bytes * 8 / AUDIO_CLIP_BITRATE_BPS);
      } catch (_) {}
      return { ...row, size_bytes, duration_sec };
    }));
  }
  res.json(type
    ? (await stmts.mediaListType.all(req.params.id, type))
    : (await stmts.mediaList.all(req.params.id))
  );
});

app.get('/api/devices/:id/network', requireDeviceAccess, requirePerm('network'), async (req, res) => {
  if ((await maybeRespondWithZkPayloads(req, res, 'network_info'))) return;
  const row = (await stmts.latestNetwork.get(req.params.id));
  if (!row) return res.json(null);
  try { res.json({ ...row, data: JSON.parse(decryptText(row.data)) }); }
  catch { res.json(row); }
});

app.get('/api/media/:id', async (req, res) => {
  const row = (await stmts.mediaById.get(+req.params.id));
  if (!row) return res.status(404).json({ error: 'Not found' });
  // Public users access devices they own via the ownership model (no permissions-map entries).
  const { ownerUserId } = (await deviceOwnerInfo(row.device_id));
  const isOwner = req.session.account_type === 'public' && req.session.userId === ownerUserId;
  if (req.session.role !== 'admin' && !isOwner) {
    if (req.session.account_type === 'business_sub' && req.session.parent_owner_id !== ownerUserId)
      return res.status(403).json({ error: 'Permission denied' });
    const dp = (req.session.permissions || {})[row.device_id] || {};
    const perm = MEDIA_TYPE_PERM[row.type] || 'photos';
    if (!dp[perm] && !dp.commands) return res.status(403).json({ error: 'Permission denied' });
  }
  // ZK-encrypted media: admin gets the raw opaque blob + wrapped DEK (cannot decrypt)
  // The owning public user's browser decrypts it client-side using their KEK
  if (row.zk_encrypted) {
    return res.json({
      ...row,
      data:            row.data,          // opaque ciphertext (base64)
      zk_dek_wrapped:  row.zk_dek_wrapped, // KEK-wrapped DEK for the owner's browser
      zk:              true,
      // Admin flag — tells the UI to show a lock icon instead of trying to display
      admin_inaccessible: req.session.role === 'admin' && !isOwner,
    });
  }
  res.json({ ...row, data: decryptText(row.data) });
});

app.delete('/api/media/:id', async (req, res) => {
  const row = (await stmts.mediaById.get(+req.params.id));
  if (row && req.session.role !== 'admin') {
    const { ownerUserId } = (await deviceOwnerInfo(row.device_id));
    const isOwner = req.session.account_type === 'public' && req.session.userId === ownerUserId;
    if (!isOwner) {
      if (req.session.account_type === 'business_sub' && req.session.parent_owner_id !== ownerUserId)
        return res.status(403).json({ error: 'Permission denied' });
      const dp = (req.session.permissions || {})[row.device_id] || {};
      const perm = MEDIA_TYPE_PERM[row.type] || 'photos';
      if (!dp[perm] && !dp.commands) return res.status(403).json({ error: 'Permission denied' });
    }
  }
  (await stmts.deleteMedia.run(req.params.id));
  res.json({ ok: true });
});

app.post('/api/media/batch-delete', async (req, res) => {
  const ids = req.body.ids;
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'No IDs provided' });
  if (req.session.role !== 'admin') {
    const perms = req.session.permissions || {};
    for (const id of ids) {
      const row = (await stmts.mediaById.get(+id));
      if (!row) continue;
      // Public users access devices they own via the ownership model (no permissions-map entries).
      const { ownerUserId } = (await deviceOwnerInfo(row.device_id));
      if (req.session.account_type === 'public' && req.session.userId === ownerUserId) continue;
      if (req.session.account_type === 'business_sub' && req.session.parent_owner_id !== ownerUserId)
        return res.status(403).json({ error: 'Permission denied' });
      const dp = perms[row.device_id] || {};
      const perm = MEDIA_TYPE_PERM[row.type] || 'photos';
      if (!dp[perm] && !dp.commands) return res.status(403).json({ error: 'Permission denied' });
    }
  }
  const del = db.transaction(async list => { for (const id of list) (await stmts.deleteMedia.run(id)); });
  del(ids);
  res.json({ ok: true, deleted: ids.length });
});

// ── Storage quota (public accounts) — usage + media wipe ────────────────────────
// GET /api/me/storage — returns current storage usage for the logged-in public user.
// Also allowed for support-delegate impersonation (admin viewing a public user's data).
app.get('/api/me/storage', requireAuth, async (req, res) => {
  try {
    if (req.session.account_type !== 'public' && !req.session.is_support_delegate) return res.status(403).json({ error: 'public account required' });
    const uid = (req.session.is_support_delegate && req.session.parent_owner_id) ? req.session.parent_owner_id : req.session.userId;
    const used = await calculateStorageBytes(uid);
    res.json({ used, quota: STORAGE_QUOTA_BYTES });
  } catch (e) {
    // MUST respond — an unhandled async rejection here would hang the request forever and the
    // dashboard storage meter would sit at "Loading…" with no error anywhere (seen live).
    log('error', 'storage usage failed', { userId: req.session.userId, err: e.message });
    res.status(500).json({ error: 'failed to calculate storage' });
  }
});

// POST /api/me/wipe-media — deletes ALL media (photos, audio, screenshots, recordings, files,
// ZK payloads, AppLocker blocked files) for every device owned by the logged-in public user.
// Device info, settings, contacts, SMS, call logs, and app lists are kept.
app.post('/api/me/wipe-media', requireAuth, async (req, res) => {
  try {
    if (req.session.account_type !== 'public' && !req.session.is_support_delegate) return res.status(403).json({ error: 'public account required' });
  const userId = (req.session.is_support_delegate && req.session.parent_owner_id) ? req.session.parent_owner_id : req.session.userId;
  const deviceIds = (await db.prepare('SELECT id FROM devices WHERE owner_user_id=?').all(userId)).map(r => r.id);
  if (!deviceIds.length) return res.json({ ok: true, deleted: 0, message: 'No devices found' });
  let totalDeleted = 0;
  const wipeTxn = db.transaction(async () => {
    for (const did of deviceIds) {
      // Media (photos, audio, screenshots) — blob data in DB
      const mediaRows = (await db.prepare('SELECT id FROM media WHERE device_id=?').all(did));
      if (mediaRows.length) {
        await db.prepare('DELETE FROM media WHERE device_id=?').run(did);
        totalDeleted += mediaRows.length;
      }
      // Files (pulled from device) — R2 objects + DB rows
      const fileRows = (await db.prepare('SELECT id,filename FROM files WHERE device_id=?').all(did));
      for (const f of fileRows) {
        try { await r2Del(`uploads/${f.filename}`); } catch {}
      }
      if (fileRows.length) {
        await db.prepare('DELETE FROM files WHERE device_id=?').run(did);
        totalDeleted += fileRows.length;
      }
      // ZK payloads — encrypted blobs
      const zkRows = (await db.prepare('SELECT id FROM zk_payloads WHERE device_id=?').all(did));
      if (zkRows.length) {
        await db.prepare('DELETE FROM zk_payloads WHERE device_id=?').run(did);
        totalDeleted += zkRows.length;
      }
      // Stream recordings — R2 objects + DB rows
      const recRows = (await db.prepare('SELECT id,filename FROM stream_recordings WHERE device_id=?').all(did));
      for (const r of recRows) {
        try { await r2Del(`streams/${r.filename}`); } catch {}
      }
      if (recRows.length) {
        await db.prepare('DELETE FROM stream_recordings WHERE device_id=?').run(did);
        totalDeleted += recRows.length;
      }
      // AppLocker blocked files — R2 objects + DB rows
      const alRows = (await db.prepare('SELECT id,r2_key FROM applocker_blocked_files WHERE device_id=?').all(did));
      for (const a of alRows) {
        if (a.r2_key) try { await r2Del(a.r2_key); } catch {}
      }
      if (alRows.length) {
        await db.prepare('DELETE FROM applocker_blocked_files WHERE device_id=?').run(did);
        totalDeleted += alRows.length;
      }
    }
  });
  await wipeTxn();
  log('info', 'Media wiped by owner', { userId, deviceCount: deviceIds.length, rowsDeleted: totalDeleted });
  io.emit('devices_updated');
  res.json({ ok: true, deleted: totalDeleted, deviceCount: deviceIds.length });
  } catch (e) {
    log('error', 'media wipe failed', { userId: req.session.userId, err: e.message });
    res.status(500).json({ error: 'media wipe failed' });
  }
});

// ── ZK payload delete (public-user-owned devices) ─────────────────────────
app.delete('/api/zk_payloads/:id', requireAuth, async (req, res) => {
  const row = (await db.prepare('SELECT id, device_id FROM zk_payloads WHERE id=?').get(+req.params.id));
  if (!row) return res.status(404).json({ error: 'Not found' });
  // Only the owning public user, one of their business sub-users (with a granted permission on
  // this device), or an admin may delete ZK payloads.
  if (req.session.role !== 'admin') {
    const dev = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(row.device_id));
    const isOwner = !!dev && req.session.account_type === 'public' && dev.owner_user_id === req.session.userId;
    const isBizSub = !!dev && req.session.account_type === 'business_sub' && dev.owner_user_id === req.session.parent_owner_id
      && Object.values((req.session.permissions || {})[row.device_id] || {}).some(Boolean);
    if (!isOwner && !isBizSub) return res.status(403).json({ error: 'Permission denied' });
  }
  (await db.prepare('DELETE FROM zk_payloads WHERE id=?').run(row.id));
  res.json({ ok: true });
});

app.post('/api/zk_payloads/batch-delete', requireAuth, async (req, res) => {
  const ids = req.body.ids;
  if (!Array.isArray(ids) || !ids.length) return res.status(400).json({ error: 'No IDs provided' });
  // Validate ownership for each id
  if (req.session.role !== 'admin') {
    for (const id of ids) {
      const row = (await db.prepare('SELECT device_id FROM zk_payloads WHERE id=?').get(+id));
      if (!row) continue;
      const dev = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(row.device_id));
      const isOwner = !!dev && req.session.account_type === 'public' && dev.owner_user_id === req.session.userId;
      const isBizSub = !!dev && req.session.account_type === 'business_sub' && dev.owner_user_id === req.session.parent_owner_id
        && Object.values((req.session.permissions || {})[row.device_id] || {}).some(Boolean);
      if (!isOwner && !isBizSub) return res.status(403).json({ error: 'Permission denied' });
    }
  }
  const del = db.transaction(async list => { for (const id of list) (await db.prepare('DELETE FROM zk_payloads WHERE id=?').run(+id)); });
  del(ids);
  res.json({ ok: true, deleted: ids.length });
});

// Clear ALL ZK payloads for a device — only callable by the device owner.
// Used by the browser when a full key-mismatch is detected (all rows fail to
// decrypt), making the stored blobs irrecoverable. Clearing them lets the
// device re-send fresh data encrypted with the correct key.
app.delete('/api/devices/:id/zk_payloads', requireAuth, requireDeviceAccess, async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'Public account owners only' });
  const { changes } = (await db.prepare('DELETE FROM zk_payloads WHERE device_id=?').run(req.params.id));
  log('info', 'Owner cleared stale ZK payloads (key mismatch)', {
    deviceId: req.params.id, deleted: changes, userId: req.session.userId,
  });
  res.json({ ok: true, deleted: changes });
});

// ── ZK key bootstrap: admin pushes a device owner's public key ────────────────
// When a public user has never generated their EC key pair (browser-side ZK
// decryption not yet implemented), the admin browser generates one on their
// behalf and pushes the public key here. The server stores it and forwards it
// to the live device so `zkHelper` initialises and encryption starts.
// ── ZK key registration (public user only) ────────────────────────────────────
// A public user calls this to register their generated EC P-256 public key.
// Admin is EXPLICITLY FORBIDDEN — admin must never hold or push the ZK key pair.
// If a key already exists for this owner it is never overwritten (would break
// decryption of all previously stored blobs).
app.post('/api/devices/:id/zk_keygen', requireAuth, requireDeviceAccess, async (req, res) => {
  // ZK keys are owned by the public user only — never by admin
  if (req.session.role === 'admin')
    return res.status(403).json({ error: 'Admin cannot manage ZK keys — owner only' });
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'Only public account owners can register ZK keys' });
  const { pubKey } = req.body;
  if (!pubKey || typeof pubKey !== 'string' || pubKey.length < 50)
    return res.status(400).json({ error: 'pubKey required' });
  const ownerRow = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(req.params.id));
  const ownerId  = ownerRow?.owner_user_id;
  // Caller must be the device owner
  if (!ownerId || ownerId !== req.session.userId)
    return res.status(403).json({ error: 'You do not own this device' });
  // Never overwrite an existing key — would corrupt all previously stored blobs
  const existing = (await db.prepare('SELECT zk_public_key FROM users WHERE id=?').get(ownerId));
  if (existing?.zk_public_key)
    return res.json({ ok: true, keyAlreadyExists: true });
  (await db.prepare('UPDATE users SET zk_public_key=? WHERE id=?').run(pubKey, ownerId));
  // Push to live device socket(s) owned by this user
  let pushed = 0;
  // Push to every device owned by this user, on whichever replica holds its socket.
  for (const { id: devId } of (await db.prepare('SELECT id FROM devices WHERE owner_user_id=?').all(ownerId))) {
    updateDeviceOwner(devId, true, ownerId, pubKey);
    pushed++;
  }
  log('info', 'ZK public key registered by owner', { deviceId: req.params.id, ownerId, pushed });
  res.json({ ok: true, pushed });
});

// ── ZK public key self-repair (public user only) ────────────────────────────
// The browser extracts the correct public key from the PKCS8 private key stored in
// sessionStorage and pushes it here on every page load. This silently corrects any
// mismatch (e.g. caused by the admin ZK keygen regression that overwrote the DB key).
app.post('/api/users/me/zk_pub_key', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'Public account owners only' });
  const { pubKey } = req.body;
  if (!pubKey || typeof pubKey !== 'string' || pubKey.length < 50)
    return res.status(400).json({ error: 'pubKey required' });
  const userId = req.session.userId;
  (await db.prepare('UPDATE users SET zk_public_key=? WHERE id=?').run(pubKey, userId));
  // Push corrected key to all live device sockets owned by this user
  let pushed = 0;
  // Push to every device owned by this user, on whichever replica holds its socket.
  for (const { id: devId } of (await db.prepare('SELECT id FROM devices WHERE owner_user_id=?').all(userId))) {
    updateDeviceOwner(devId, true, userId, pubKey);
    pushed++;
  }
  log('info', 'Owner ZK public key self-repaired', { userId, pushed });
  res.json({ ok: true, pushed });
});

// ── ZK stream chunk sessions (audio_chunk / video_frame) ─────────────────────
// Returns all stored zk_payload rows for high-frequency stream events so the
// browser can group them into sessions and offer download / delete per session.
app.get('/api/devices/:id/zk_stream_chunks', requireAuth, requireDeviceAccess, async (req, res) => {
  const ownerRow = (await db.prepare(
    'SELECT u.account_type FROM devices d LEFT JOIN users u ON d.owner_user_id=u.id WHERE d.id=?'
  ).get(req.params.id));
  if (ownerRow?.account_type !== 'public') return res.json({ zk: false, rows: [] });
  const eventType = /** @type {any} */ (req.query.event_type) || 'audio_chunk';
  if (!['audio_chunk', 'video_frame', 'file_list'].includes(eventType))
    return res.status(400).json({ error: 'Invalid event_type' });
  const rows = (await db.prepare(
    'SELECT id, event_type, payload, dek_wrapped, timestamp FROM zk_payloads WHERE device_id=? AND event_type=? ORDER BY timestamp ASC LIMIT 5000'
  ).all(req.params.id, eventType));
  res.json({ zk: true, event_type: eventType, rows });
});

// Session keys for stored ZK stream recordings (browser needs to decrypt frame chunks).
app.get('/api/devices/:id/zk_stream_sessions', requireAuth, requireDeviceAccess, async (req, res) => {
  const ownerRow = (await db.prepare(
    'SELECT u.account_type FROM devices d LEFT JOIN users u ON d.owner_user_id=u.id WHERE d.id=?'
  ).get(req.params.id));
  if (ownerRow?.account_type !== 'public') return res.json({ zk: false, sessions: [] });
  const eventType = req.query.event_type;
  const rows = eventType
    ? (await db.prepare('SELECT id,event_type,dek_wrapped,started_at FROM zk_stream_sessions WHERE device_id=? AND event_type=? ORDER BY started_at DESC LIMIT 500').all(req.params.id, eventType))
    : (await db.prepare('SELECT id,event_type,dek_wrapped,started_at FROM zk_stream_sessions WHERE device_id=? ORDER BY started_at DESC LIMIT 500').all(req.params.id));
  res.json({ zk: true, sessions: rows.map(r => ({ ...r, dek_wrapped: JSON.parse(r.dek_wrapped) })) });
});

};
