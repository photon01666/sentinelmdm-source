// Auto-purge counter for bt_events (7-day rolling window). MOVED here from
// server.js: the only writer is the bt_event insert handler below, so it is
// exclusive to this block. It must stay `let` and module-scoped -- every
// connection shares one counter, exactly as before the move. Passing it
// through ctx instead would give the module a frozen 0 and disable the purge
// entirely (silently: `++0 % 100 === 0` never fires again).
let _btEventInsertCount = 0;

module.exports = ({ALL_ROWS, AUTO_CALIB_MAX_GPS_ACC_M, EventEmitter, HONEYPOT_FEED_URL,
                   LIVE_INPUT_COMMANDS, RA_AUTO_PROVISION_COOLDOWN_MS, RETAIN_UNLOCK_PHOTOS,
                   SCREENTEXT_SCHEDULE_KEY, SIGNAL_SENDER, TAILNET_UUID,
                   TRACKER_ALERT_MIN_RSSI, XRAY_REMOTEASSIST_UUID, XRAY_VPN_UUID,
                   ZK_EVENT_LABELS, _canSendUserNotif, appendToAudioMedia, applyBtSafelist,
                   autoCalibrateAnchors, buildS3DriveCommand, buildScreentextLogFromRows,
                   buildVariant, cancelOfflineGrace, checkStorageQuota, checkTrialLineageAbuse,
                   connectedSockets, crypto, db, decryptDevice, decryptText, deviceEmit,
                   deviceOwnerInfo, deviceStatus, emitRemoteAssistProvision, emitToDevice,
                   encryptBuffer, encryptText, encryptedDevices, enqueueLocation,
                   enqueueZkPayload, fileChunkBuffers, finalizeAudioSession,
                   geofenceAcceptTransition, geofenceAlertDue, getBtSafelist,
                   getS3DriveEnabled, getScreentextSchedule, getServerUnlocked,
                   honeypotSighting, io, kv, log, markOnline, mintApkToken, normalizeVpn,
                   notifyAdminExempt, notifyAdminForDevice, notifyGeofenceNodeRed, notifyPush,
                   notifyUser, opencodeApiKey, path, persistDevState, persistUserAlert, r2Put,
                   raAutoProvisionAttempts, randomUUID, redisEnabled, runScreentextAnalysis,
                   scheduleOfflineGrace, selectBuildForDevice, serverEncPrivKey,
                   setScreentextSchedule, signalAlert, signalData, socketReqCtx,
                   startOfTodayUtcTs, stmts, stopTheftModeAlerts, surveilStop,
                   syncDeviceDisplayNameToBastion, tailnetCommand, trackerAlertNeeded,
                   voteTowerPositions, vpnCommand }) => {
io.on('connection', socket => {
  let deviceId = null;

  // Browser/monitor sockets join the global 'monitors' room so global broadcasts
  // (enrollment / guest-chat / support / bug-report) fan out across
  // ALL replicas via the Redis adapter — not just sockets on this one.
  if (socket.isMonitor) socket.join('monitors');

  // ── DPI bypass metadata ───────────────────────────────────────────────────
  // Captured at handshake time; transport updated on WebSocket upgrade.
  const ua = socket.handshake.headers['user-agent'] || '';
  // Honeypot fleet cross-reference (inert unless HONEYPOT_FEED_URL is wired): is this connecting IP
  // one the honeypot flagged (attacker / C2)? If so, page admin once / 6h. Best-effort, never blocks.
  if (typeof HONEYPOT_FEED_URL === 'string' && HONEYPOT_FEED_URL) {
    const _cip = String(socket.handshake.headers['cf-connecting-ip']
      || String(socket.handshake.headers['x-forwarded-for'] || '').split(',')[0]
      || socket.handshake.address || '').trim();
    if (_cip) honeypotSighting(_cip, `socket connect ua=${ua.slice(0, 80)}`).catch(() => {});
  }
   const realityHeader = socket.handshake.headers['x-via-reality'] || '';
   // If the header is missing or just a generic "1" flag, derive the REALITY node from the
   // host's hostname. Inside a container, os.hostname() returns the container ID, so read the
   // host name mounted at /etc/host-hostname. The hostname ends with a two-letter node code.
   const _hostHn = (() => { try { return require('fs').readFileSync('/etc/host-hostname', 'utf8').trim(); } catch { return ''; } })();
   const _hn = _hostHn || require('os').hostname();
   const _nodeFromHost = /[A-Z]{2}$/.test(_hn) ? _hn.match(/[A-Z]{2}$/)[0] : null;
   const validNodes = ['CA', 'VA', 'OR'];
   const inferredNode = validNodes.includes(_nodeFromHost) ? _nodeFromHost : null;
   // IPv6-first (2026-09-23): the agent reports the ACTUAL dialed address — v4 or v6 — in the
   // header; realityV6 flags an IPv6 literal so the dashboard can label the card "IPv6" (app.js).
   const realityV6 = (realityHeader && realityHeader !== '1') && realityHeader.includes(':');
   socket.dpi = {
     transport:   socket.conn.transport.name,
     relay:       !!socket.handshake.headers['x-via-relay'],
     // REALITY is declared by the agent's X-Via-Reality header alone. When it is absent the
     // connection is relay/direct and MUST NOT show the REALITY badge — the inferred host node
     // below is only the swarm replica that answered (the CF relay forwards to the VIP), which
     // previously mislabeled relay connections as "REALITY · <node>".
     reality:     !!realityHeader,
     realityNode: (realityHeader && realityHeader !== '1') ? realityHeader
                : (realityHeader ? inferredNode : null),
     realityV6:   realityV6,
     chrome_ua:   ua.includes('Chrome/'),
   };
  socket.conn.on('upgrade', transport => {
    socket.dpi.transport = transport.name;
    persistDevState(deviceId, socket);
    if (deviceId && getServerUnlocked()) io.emit('devices_updated');
  });

  log('info', 'Socket connected', {
    socketId: socket.id,
    transport: socket.conn.transport.name,
    role: socket.isDevice ? 'device' : 'monitor',
  });

  // ── Support chat rooms ──────────────────────────────────────────────────────
  // Browser sessions join support rooms so messages push live (no polling).
  // Admins join `support:admins`; a public user joins their own `support:user:<id>`.
  {
    const sess = socket.request.session;
    if (sess?.authenticated) {
      if (sess.role === 'admin') socket.join('support:admins');
      else if (sess.account_type === 'public' && sess.userId)
        socket.join(`support:user:${sess.userId}`);
    }
  }

  // ── App-layer encryption handshake ────────────────────────────────────────
  // Device sends ephemeral EC P-256 public key; server performs ECDH with its static
  // private key, derives AES-128 session key, then acks. All subsequent events from
  // this device arrive as encrypted `e` events. Old devices skip this and register plain.
  socket.on('enc_hello', data => {
    if (!socket.isDevice) return;
    if (!serverEncPrivKey || !data?.ephemeralPubKey) {
      socket.emit('enc_hello_ack', {}); // ack so device doesn't hang
      return;
    }
    try {
      const devicePub = crypto.createPublicKey({
        key: Buffer.from(data.ephemeralPubKey, 'base64'),
        format: 'der',
        type: 'spki',
      });
      const sharedSecret = crypto.diffieHellman({ privateKey: serverEncPrivKey, publicKey: devicePub });
      // HKDF-SHA256: 32-byte zero salt, "SentinelMDM-v1" info → 16-byte AES-128 key
      socket.encKey = /** @type {any} */ (crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(32), Buffer.from('SentinelMDM-v1'), 16));
      socket.emit('enc_hello_ack', {});
      log('info', 'Enc session established', { socketId: socket.id });
    } catch (e) {
      log('error', 'enc_hello failed', { socketId: socket.id, error: e.message });
      socket.emit('enc_hello_ack', {}); // still ack to prevent device hanging
    }
  });

  // Encrypted wrapper: decrypt and re-dispatch as a regular socket event so all
  // existing socket.on() handlers work transparently for both plaintext and encrypted devices.
  socket.on('e', data => {
    if (!socket.encKey) { log('warn', 'Encrypted event from unkeyed socket', { socketId: socket.id }); return; }
    try {
      const combined = Buffer.from(data.d, 'base64');
      if (combined.length < 29) return;
      const iv  = combined.slice(0, 12);
      const tag = combined.slice(combined.length - 16);
      const ct  = combined.slice(12, combined.length - 16);
      const decipher = crypto.createDecipheriv('aes-128-gcm', socket.encKey, iv);
      decipher.setAuthTag(tag);
      const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
      const msg = JSON.parse(plain.toString('utf8'));
      // Invoke existing socket.on handlers via EventEmitter (socket.emit would go outward)
      EventEmitter.prototype.emit.call(socket, msg.ev, msg.d);
    } catch (e) {
      log('warn', 'AES-GCM decrypt failed', { socketId: socket.id, error: e.message });
    }
  });

  socket.on('register', async data => {
    if (!socket.isDevice || !getServerUnlocked()) return;
    // SECURITY (cross-device impersonation, finding #1): the registered identity MUST be the
    // signature-authenticated device from the handshake. A socket that proved possession of
    // device A's key may NOT register as device B — doing so would hijack B's command channel
    // (emitToDevice routes on connectedSockets) and let it inject telemetry under B's id.
    if (socket.authDeviceId && data?.deviceId && data.deviceId !== socket.authDeviceId) {
      log('warn', 'register deviceId mismatch — impersonation blocked',
        { authedDevice: socket.authDeviceId, claimed: data.deviceId, ip: socket.handshake.address });
      (await signalAlert('🚨 Device Impersonation Blocked',
        `Socket authenticated as device ${socket.authDeviceId} attempted to register as ${data.deviceId}.`,
        socketReqCtx(socket), socket.authDeviceId));
      return;
    }
    deviceId = socket.authDeviceId || data.deviceId || randomUUID();
    const prevSocket = connectedSockets.get(deviceId);
    connectedSockets.set(deviceId, socket);
    // Stamp the device identity on socket.data so the cross-replica stale-presence sweep
    // (io.fetchSockets() via the redis adapter propagates socket.data to every replica) can
    // distinguish a genuinely-connected device from a stale 'online_devices' Redis entry left
    // behind by an abruptly-killed replica whose disconnect handler never ran.
    socket.data.deviceId = deviceId;
    // Supersede the old socket: disconnect it so the displaced process's client-side watchdog
    // detects the drop and reconnects (used by AI Live Chat's temporary interactive socket
    // superseding the SYSTEM unattended socket, which then reconnects after the chat closes).
    if (prevSocket && prevSocket !== socket) {
      try { prevSocket.disconnect(true); } catch (_) {}
    }
    markOnline(deviceId);
    cancelOfflineGrace(deviceId);   // a reconnect within the grace cancels a pending offline-mark + alert
    // Tell peer replicas this device is now owned by THIS replica so their stale
    // connectedSockets entry is cleared before their old socket's disconnect fires
    // and wrongly calls markOffline (race: peer sadd → our srem race on reconnect).
    if (redisEnabled) io.serverSideEmit('device-registered', { deviceId });
    if (socket.encKey) encryptedDevices.add(deviceId); else encryptedDevices.delete(deviceId);
    persistDevState(deviceId, socket);   // publish DPI/transport + encrypted to Redis for cross-replica cards
    const devName = data.name || data.deviceName || data.deviceId;
    const platform = data.platform ||
      ((data.androidVersion || data.model || '').toLowerCase().startsWith('windows') ? 'windows' : 'android');
    // Coerce battery to an int (the column is INTEGER) — accept a number or a {level} object, else
    // null. Without this, a device sending battery as an object/string aborts register on Postgres
    // (invalid integer) → unhandled rejection → replica crash.
    const battInt = Number.isFinite(data.battery) ? data.battery
      : (Number.isFinite(data.battery?.level) ? data.battery.level : null);
    (await stmts.upsertDevice.run({ id: deviceId, name: encryptText(devName), model: encryptText(data.model || ''),
      androidVersion: encryptText(data.androidVersion || ''),
      osBuild: data.osBuild || null, securityPatch: data.securityPatch || null,
      battery: battInt,
      ts: Date.now(), platform, appVersion: data.appVersion || null }));
    // APK signing-cert fingerprint → drives variant-aware OTA dispatch (raven/stallion/tegu/stock).
    if (data.signerSha256) {
      try { (await db.prepare('UPDATE devices SET apk_signer=? WHERE id=?')
              .run(String(data.signerSha256).toLowerCase(), deviceId)); } catch (_) {}
    }
    // SentinelRemoteAssist per-device Hop-1 public key (Hop1Identity.cs, ≥ agent version with
    // Config.AccountLinkedBuild support) — replaces the old shared per-account key. Stored on every
    // register so it's already on file by the time provisionSession() needs it, no separate push
    // round-trip required. Only ever sent by remote_assist/windows devices; harmless no-op field on
    // every other platform.
    if (data.hop1PublicKey && typeof data.hop1PublicKey === 'string' && data.hop1PublicKey.startsWith('ssh-')) {
      try { (await db.prepare('UPDATE devices SET hop1_public_key=? WHERE id=?')
              .run(data.hop1PublicKey.trim(), deviceId)); } catch (_) {}
    }
    // Detect if this device is owned by a public user (needed for ZK media routing + user notifs)
    {
      const ownerRow = (await db.prepare(`
        SELECT u.id AS uid, u.account_type, u.trial_enabled AS trialenabled, u.trial_started_at AS trialstartedat,
               d.locked_identity_email AS lineage, d.lineage_kind AS kind, d.owner_user_id AS owner, d.agent_kind AS agentkind FROM devices d
        LEFT JOIN users u ON d.owner_user_id = u.id
        WHERE d.id=?
      `).get(deviceId));
      // ZK-PRIVACY (admin can NEVER see data) applies to: a public-user owner, OR a PUBLIC-kind lineage
      // lock (incl. a wiped/orphaned public device → stays private). An ADMIN-kind lineage lock is
      // anti-theft only — the device stays admin-VISIBLE (non-ZK). This decouples the lock from privacy.
      socket.deviceLineageLocked = !!ownerRow?.lineage;
      const adminKind = ownerRow?.kind === 'admin';
      socket.ownerIsPublicUser = (ownerRow?.account_type === 'public') || (socket.deviceLineageLocked && !adminKind);
      socket.ownerUserId = (ownerRow?.account_type === 'public') ? ownerRow.uid : null;
      socket.isRemoteAssist = ownerRow?.agentkind === 'remote_assist';
      // Re-assert orphan state on every (re)connect for ANY lineage-locked device (public OR admin)
      // that has NO current owner (its owner account was wiped/removed). The fire-once `device_locked`
      // emit at wipe time is missed if the device was offline then, so re-send it here so the agent goes
      // dormant + un-hides for a same-email reclaim (enterOrphanLock is idempotent). Uses the real
      // owner_user_id column, not the public-only ownerUserId.
      if (socket.deviceLineageLocked && !ownerRow?.owner) {
        setTimeout(() => { try { deviceEmit(socket, 'device_locked', { reason: 'orphaned' }); } catch (_) {} }, 3000);
      }
      // 30-day trial countdown starts the first time a trial account's device connects.
      if (socket.ownerUserId && ownerRow?.trialenabled && !ownerRow?.trialstartedat) {
        try {
          // Anti-reset: if this EXACT physical device (hardware-serial-derived id — survives a
          // factory wipe, see checkTrialLineageAbuse below) already started a trial under ANY
          // account, inherit that trial's ORIGINAL start instead of granting a fresh 30 days —
          // otherwise "wipe the device → sign into a brand-new email" resets the countdown
          // indefinitely. Mirrors the same-email account_continuity restore in wipeUserAccount(),
          // just keyed by hardware instead of email. A legitimately resold/gifted device still
          // works — the new owner just gets whatever time is left on the original clock (possibly
          // already expired) rather than 0 or a fresh 30.
          const prior = (await db.prepare('SELECT MIN(created_at) AS t FROM trial_starts WHERE device_id=?').get(deviceId));
          const startedAt = prior?.t ? Number(prior.t) : Date.now();
          const upd = (await db.prepare("UPDATE users SET trial_started_at=? WHERE id=? AND trial_enabled=1 AND trial_started_at IS NULL")
            .run(startedAt, socket.ownerUserId));
          if (upd.changes) {
            log('info', 'Trial countdown started (first device connect)', { userId: socket.ownerUserId, deviceId, inheritedStart: !!prior?.t });
            // Also flags email/hwId lineage matches (still alert-only for those two — hwId is
            // self-reported so it's not safe to enforce on, and email reuse is already blocked
            // separately by the same-email continuity restore at registration).
            checkTrialLineageAbuse(socket.ownerUserId, deviceId, socket.hwId).catch(() => {});
          }
        } catch {}
      }
    }
    // Update plaintext telemetry for global search.
    // ZK-owned (public-user) devices: NEVER persist user-telemetry in clear — battery and the
    // observed IP are ZK-private and arrive only via the encrypted device_status path.
    const zkOwned  = socket.ownerIsPublicUser === true;
    // Seed with cf-connecting-ip (real client on the plain-CF path) — NOT the raw socket peer,
    // which is the REALITY relay / Swarm overlay. The device's self-reported public IP overwrites
    // this on the first device_status. ZK devices: no plaintext IP at all.
    const clientIp = zkOwned ? null
      : (socket.handshake.headers['cf-connecting-ip'] || null);
    const ownerId = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(deviceId))?.owner_user_id || null;
    if (zkOwned) { try { (await db.prepare('UPDATE devices SET battery=NULL WHERE id=?').run(deviceId)); } catch {} }
    try {
      (await db.prepare(`INSERT INTO device_telemetry (device_id,owner_user_id,ip_address,model_plain,android_version_plain,online,battery,updated_at)
        VALUES (?,?,?,?,?,1,?,?)
        ON CONFLICT(device_id) DO UPDATE SET
          owner_user_id=excluded.owner_user_id, ip_address=excluded.ip_address,
          model_plain=excluded.model_plain, android_version_plain=excluded.android_version_plain,
          online=1, battery=excluded.battery, updated_at=excluded.updated_at`).run(
        deviceId, ownerId, clientIp,
        data.model || '', data.androidVersion || '',
        zkOwned ? null : (data.battery ?? null), Date.now()
      ));
    } catch (e) { log('warn', 'Telemetry update failed', { error: e.message }); }

    // Include owner's ZK public key so the device can activate envelope encryption
    const ownerPubRow = (await db.prepare(
      'SELECT u.zk_public_key FROM devices d JOIN users u ON d.owner_user_id=u.id WHERE d.id=? AND u.account_type=?'
    ).get(deviceId, 'public'));
    const registeredPayload = { deviceId };
    if (ownerPubRow?.zk_public_key) registeredPayload.zkPubKey = ownerPubRow.zk_public_key;
    deviceEmit(socket, 'registered', registeredPayload);
    // Rescue mode: device connected via one-time bypass — clear its stored key and
    // tell it to re-enroll with a fresh public key so normal auth resumes.
    if (socket.isRescue) {
      (await db.prepare('UPDATE devices SET public_key=NULL WHERE id=?').run(deviceId));
      deviceEmit(socket, 're_enroll', { deviceId });
      log('info', 'Rescue: device re-enrolled, key cleared — awaiting fresh public key', { deviceId });
    }
    // Device connected with enrollment-mode auth but key was already approved — tell it to
    // switch to key-based auth on next connect so it stops re-entering the enrollment path.
    if (socket.justEnrolled) {
      deviceEmit(socket, 'key_enrolled', { deviceId });
      socket.justEnrolled = false;
      log('info', 'key_enrolled sent to device after approval connect', { deviceId });
    }
    // Device is registering = it's awake; clear deep_sleep flag
    (await db.prepare('UPDATE devices SET deep_sleep=0 WHERE id=?').run(deviceId));
    const devRow = (await db.prepare('SELECT theft_mode, pending_update FROM devices WHERE id=?').get(deviceId));
    if (devRow?.theft_mode === 1) deviceEmit(socket, 'command', { command: 'start_theft_mode' });
    // Re-push WiFi auto-join config so the enable/disable + allow/deny survives reconnects.
    {
      const wajRow = (await db.prepare("SELECT value FROM settings WHERE key=?").get('wifi_autojoin:' + deviceId));
      if (wajRow) { try { deviceEmit(socket, 'command', { command: 'set_wifi_autojoin', ...normalizeWifiAutoJoin(JSON.parse(wajRow.value)) }); } catch (_) {} }
    }
    // Re-push airline WiFi credentials so auto-login survives reconnects.
    {
      const awRow = (await db.prepare("SELECT value FROM settings WHERE key=?").get('airline_wifi:' + deviceId));
      if (awRow) { try { deviceEmit(socket, 'command', { command: 'set_airline_wifi', ...JSON.parse(awRow.value) }); } catch (_) {} }
    }
    // Re-push unlock-capture config (what/when to capture on unlock attempts) so it survives reconnects.
    {
      const ucRow = (await db.prepare("SELECT value FROM settings WHERE key=?").get('unlock_capture:' + deviceId));
      if (ucRow) { try { deviceEmit(socket, 'command', { command: 'set_unlock_capture', ...normalizeUnlockCapture(JSON.parse(ucRow.value)) }); } catch (_) {} }
    }
    // Re-push screentext schedule (every 6h + quiet hours) so it survives reconnects.
    {
      const stsRow = (await db.prepare("SELECT value FROM settings WHERE key=?").get(SCREENTEXT_SCHEDULE_KEY + deviceId));
      if (stsRow) {
        try {
          const stsCfg = JSON.parse(stsRow.value);
          deviceEmit(socket, 'command', { command: 'set_screentext_schedule', enabled: !!stsCfg.enabled, hour: stsCfg.hour || 20, minute: stsCfg.minute || 0, quietHoursStart: stsCfg.quietHoursStart ?? 23, quietHoursEnd: stsCfg.quietHoursEnd ?? 7 });
        } catch (_) {}
      }
    }
    // Re-push auto-VPN config (+ the secret egress UUID) so it survives reconnects/app restarts.
    {
      const vpnRow = (await db.prepare("SELECT value FROM settings WHERE key=?").get('vpn:' + deviceId));
      if (vpnRow && XRAY_VPN_UUID) { try { deviceEmit(socket, 'command', vpnCommand(normalizeVpn(JSON.parse(vpnRow.value)))); } catch (_) {} }
    }
    // Re-push S3 Drive config (+ the account Public password and this device's own Private
    // password/prefix) so it survives reconnects/app restarts — same reasoning as the VPN re-push
    // immediately above. No req/session exists in this handshake context, so read owner_user_id
    // directly instead of routing through resolveS3DriveOwnerUserId's req-based fallback — an
    // unowned/admin-fleet device simply has nothing to re-push here (nobody's account config
    // would apply to it without an explicit HTTP action from an admin).
    if (data.agentKind === 'remote_assist') {
      try {
        if ((await getS3DriveEnabled(deviceId))) {
          const s3dRow = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(deviceId));
          if (s3dRow?.owner_user_id) {
            deviceEmit(socket, 'command', (await buildS3DriveCommand(deviceId, s3dRow.owner_user_id, true, false)));
          }
        }
      } catch (_) {}
    }
    // Remote-assist auto-start on reconnect:
    //   Fires whenever this device has EVER had a Remote Assist key issued (a
    //   remote_assist_sessions row with ssh_public_key set) AND the tunnel is not ALREADY live —
    //   NOT behind a separate opt-in flag. The very first Connect/Regen Private Key click is
    //   already the explicit-consent event (that's what creates this row); every later
    //   reboot/reconnect just resumes that SAME already-authorized tunnel with the SAME key,
    //   never minting anything new — so there is nothing further to opt into.
    //   ⚠️ Used to ALSO require a separate `ra_auto:<deviceId>` setting, auto-flipped on only as a
    //   side-effect of clicking Connect/Reconnect in the dashboard. Any device whose Hop-1 session
    //   was ever established some other way (test tooling, a direct bastion API call,
    //   remote-update-session.sh) never got that flag set, so it never auto-reconnected at all —
    //   found 2026-07-17 on the QEMU test VM, which had 5+ prior sessions/keys on file but zero
    //   `ra_auto` row, so this whole block silently never ran for it, on any reboot, ever. Do not
    //   reintroduce a gate here that isn't reachable by every device that already has a key.
    //   Gate is a LIVE bastion status check, not the DB row's `status` column — that column is
    //   only ever written by the explicit /start and /reconnect routes, so an 'active' row from
    //   the last manual Connect survives forever across a Windows reboot (nothing marks it
    //   'ended' on disconnect/reboot). A cooldown (not the DB row, not the flag) is what prevents
    //   the infinite loop the original guard was protecting against: pushing the transport command
    //   reconfigures xray, which drops the control channel, triggering a reconnect within seconds
    //   — often before Hop-1 has finished coming up, so a naive live-check-and-retry would
    //   re-provision on that reconnect too and could cascade. See RA_AUTO_PROVISION_COOLDOWN_MS.
    if (data.agentKind === 'remote_assist' && XRAY_REMOTEASSIST_UUID) {
      const bastionClient = require('../bastionClient');
      if (bastionClient.configured()) {
        try {
          const { ownerUserId } = (await deviceOwnerInfo(deviceId));
          if (ownerUserId) {
            // A key_pending row means an explicit dashboard Connect is ACTIVELY in flight right
            // now (POST /ssh-key creates it key_pending before /start upgrades it to active) —
            // if the agent's socket happens to reconnect during that window (RunSetup kills +
            // restarts the tunnel to install the new key), we must not race it with a second,
            // independent auto-provision. The original assumption ("this one doesn't go stale:
            // key_pending rows only exist for the few seconds a real Connect is running") turned
            // out to be false — found live 2026-07-29: a Linux device's /start call failed with
            // 409 (hop1_public_key not yet on file) after /ssh-key had already created its
            // key_pending row, and nothing ever promotes or expires that row on a failed /start —
            // it silently gated out EVERY subsequent auto-provision attempt forever, indefinitely
            // stuck the device's Hop-1 tunnel. Bound the check to rows created in the last 2
            // minutes (generous — a real /ssh-key -> /start round trip completes in seconds).
            const pending = await db.prepare(
              "SELECT 1 FROM remote_assist_sessions WHERE device_id=? AND status='key_pending' AND created_at > ? ORDER BY created_at DESC LIMIT 1"
            ).get(deviceId, Date.now() - 120000);
            if (!pending) {
              const lastKey = await db.prepare(
                "SELECT ssh_public_key, id FROM remote_assist_sessions WHERE device_id=? AND ssh_public_key IS NOT NULL ORDER BY created_at DESC LIMIT 1"
              ).get(deviceId);
              if (lastKey?.ssh_public_key) {
                let liveConnected = false;
                try { liveConnected = !!(await bastionClient.sessionStatus(deviceId))?.connected; } catch (_) { /* treat as not-connected */ }
                if (!liveConnected) {
                  const lastAttempt = raAutoProvisionAttempts.get(deviceId) || 0;
                  if (Date.now() - lastAttempt < RA_AUTO_PROVISION_COOLDOWN_MS) {
                    log('info', 'Remote-assist auto-provision skipped (cooldown)', { deviceId });
                  } else if (!data.hop1PublicKey) {
                    // Old agent build (pre-per-device-Hop-1-key) reconnecting — nothing to
                    // provision against yet. Let it be; a fleet still on the old build simply
                    // won't auto-reconnect Remote Assist until it's updated, same as any device
                    // that has never had a Remote Assist key issued at all (the outer `if` above).
                    log('info', 'Remote-assist auto-provision skipped (no hop1PublicKey — old agent build)', { deviceId });
                  } else {
                    raAutoProvisionAttempts.set(deviceId, Date.now());
                    // data.hop1PublicKey, not a re-query — it was just written to devices moments
                    // ago earlier in this SAME register handler, and is the freshest value we have.
                    const provisioned = (await bastionClient.provisionSession(deviceId, ownerUserId, data.hop1PublicKey, data.platform));
                    syncDeviceDisplayNameToBastion(deviceId).catch(() => {}); // best-effort, never blocks reconnect
                    if (provisioned?.port) {
                      // Mirror /reconnect's DB bookkeeping so the dashboard/status reflects reality
                      // instead of only ever being written by explicit user actions.
                      await db.prepare("UPDATE remote_assist_sessions SET status='ended', ended_at=? WHERE device_id=? AND status='active' AND id<>?").run(Date.now(), deviceId, lastKey.id);
                      await db.prepare("UPDATE remote_assist_sessions SET status='active', bastion_label=?, bastion_port=? WHERE id=?").run(provisioned.label, provisioned.port || null, lastKey.id);
                      await emitRemoteAssistProvision(deviceId, data.platform, provisioned.port, socket);
                      log('info', `Remote-assist session auto-started on reconnect`, { deviceId, port: provisioned.port });
                      // DO NOT emit remote_assist_ssh_key here. Every push re-runs the agent's
                      // elevated setup, and doing that on EVERY tracker-side reconnect is both
                      // pointless churn and a way to disturb a working authorized_keys file.
                      // Keys already installed by an explicit Connect/Regen persist in
                      // administrators_authorized_keys across reconnects, so nothing needs
                      // re-pushing to keep an existing tunnel usable. Browser keys are ONLY
                      // pushed via POST /api/devices/:id/remote-assist/ssh-key (Connect/Regen).
                      //
                      // ⚠️ Two parts of this comment's ORIGINAL rationale are now obsolete —
                      // corrected 2026-08-03 so nobody re-derives a wrong conclusion from them:
                      //   • "the agent's baked-in sentinel-setup.ps1 already includes the
                      //     standing support key" — no longer true. Config.AdminHopTwoPublicKey has
                      //     been empty since the standing-admin-key removal; the bastion's
                      //     standing support key is PUSHED by /ssh-key (the 2.0.4 fix), which is why
                      //     it is present on a box that has ever been Connected/Regened.
                      //   • "a browser key may be lost across the scheduled-task boundary (see
                      //     PendingSshPublicKey known bug)" — fixed. Agent 2.0.6 accumulates
                      //     concurrent pushes instead of clobbering them, and 2.0.8 persists
                      //     pending keys to disk so they survive a process restart.
                    }
                  }
                }
                // liveConnected === true: do NOTHING — tunnel is already up, re-pushing would
                // cause the connect/disconnect loop the cooldown/this whole check exists to avoid.
              }
            }
          }
        } catch (e) { log('warn', 'Remote-assist on connect failed', { deviceId, error: e.message }); }
      }
    }
    // Re-push tailnet access config on reconnect (admin/sub fleet only — NEVER public/ZK users).
    if (!socket.ownerIsPublicUser && TAILNET_UUID) {
      const tailnetRow = (await db.prepare('SELECT tailnet_group_id FROM devices WHERE id=?').get(deviceId));
      if (tailnetRow?.tailnet_group_id) {
        try { deviceEmit(socket, 'command', await tailnetCommand(tailnetRow.tailnet_group_id)); } catch (_) {}
      }
    }
    if (devRow?.pending_update === 1) {
      // Use THIS device's variant (signer from the register payload, else model/os_build).
      const build = (await selectBuildForDevice({
        apk_signer: (data.signerSha256 || '').toLowerCase(),
        model:      data.model  || '',
        os_build:   data.osBuild || '',
      }));
      if (build) {
        deviceEmit(socket, 'command', { command: 'update_app', token: mintApkToken(build, 10 * 60 * 1000) });
        (await db.prepare('UPDATE devices SET pending_update=0 WHERE id=?').run(deviceId));
        log('info', 'Queued APK update dispatched to device', { deviceId, build: build.name, variant: buildVariant(build) });
      }
    }
    io.emit('devices_updated');
    log('info', prevSocket ? 'Device re-registered (reconnect)' : 'Device registered', {
      deviceId, name: devName, model: data.model, platform,
      android: data.androidVersion, battery: data.battery,
      totalOnline: connectedSockets.size
    });
  });

  socket.on('entering_deep_sleep', async () => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    (await db.prepare('UPDATE devices SET deep_sleep=1 WHERE id=?').run(deviceId));
    io.emit('devices_updated');
    log('info', 'Device entering deep sleep', { deviceId });
  });

  socket.on('location', data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    const locData = { lat: data.lat, lng: data.lng, accuracy: data.accuracy ?? 0 };
    if (data.speed   != null) locData.speed   = data.speed;
    if (data.bearing != null) locData.bearing = data.bearing;
    const ts = Date.now();
    // Buffered write (history INSERT + coalesced current-loc UPDATE) — see enqueueLocation.
    enqueueLocation(
      deviceId,
      encryptText(JSON.stringify(locData)),
      encryptText(String(data.lat)), encryptText(String(data.lng)),
      ts, data.battery ?? null
    );
    io.to(`monitor:${deviceId}`).emit('location_update', { deviceId, ...data, timestamp: ts });
    log('debug', 'Location update', { deviceId, lat: data.lat, lng: data.lng, accuracy: data.accuracy, battery: data.battery });
    // Auto-calibrate indoor anchors: when the GPS fix is accurate, every strong nearby
    // WiFi/BT reading is a vote for that device's location. Passive — no user action.
    // Same trigger votes the camped tower's POSITION (fleet-learned tower database).
    if (Number.isFinite(data.accuracy) && data.accuracy <= AUTO_CALIB_MAX_GPS_ACC_M) {
      autoCalibrateAnchors(deviceId, Number(data.lat), Number(data.lng), Number(data.accuracy)).catch(() => {});
      voteTowerPositions(deviceId, Number(data.lat), Number(data.lng), Number(data.accuracy)).catch(() => {});
    }
  });

  socket.on('photo', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    const isZk = !!(data.zk && socket.ownerIsPublicUser);
    const rawB64 = isZk ? (data.payload_base64 || data.base64 || '') : (data.base64 || '');
    if (!rawB64) { log('warn', 'Dropping empty photo — device-side capture failed', { deviceId, zk: isZk }); return; }
    // Storage quota: block new media when the account is over 1 GB.
    if (socket.ownerUserId) {
      const newBytes = Math.round(rawB64.length * 0.75);
      const quota = await checkStorageQuota(socket.ownerUserId, newBytes);
      if (!quota.ok) {
        socket.emit('storage_quota_exceeded', { used: quota.used, quota: quota.quota, needed: newBytes });
        io.to(`monitor:${deviceId}`).emit('storage_quota_exceeded', { deviceId, used: quota.used, quota: quota.quota, needed: newBytes });
        log('warn', 'Photo blocked — storage quota exceeded', { deviceId, ownerUserId: socket.ownerUserId, used: quota.used, needed: newBytes });
        return;
      }
    }
    const mediaData    = isZk ? rawB64 : encryptText(rawB64);
    const zkDekWrapped = isZk ? (data.zk_dek_wrapped || null) : null;
    const { id } = (await db.prepare(
      'INSERT INTO media (device_id,type,data,timestamp,zk_encrypted,zk_dek_wrapped) VALUES (?,?,?,?,?,?) RETURNING id'
    ).get(deviceId, 'photo', mediaData, Date.now(), isZk ? 1 : 0, zkDekWrapped));
    io.to(`monitor:${deviceId}`).emit('media_received', { deviceId, type: 'photo', id, timestamp: Date.now(), zk: isZk });
    log('info', 'Photo received', { deviceId, mediaId: id, zk: isZk, bytes: Math.round(rawB64.length * 0.75) });
    if (!isZk) {
      const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
      signalData('photo', dev ? `${dev.name}  •  ${dev.model}` : deviceId, data, deviceId);
    }
  });

  socket.on('network_info', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    (await stmts.insertNetwork.run(deviceId, encryptText(JSON.stringify(data)), Date.now()));
    io.to(`monitor:${deviceId}`).emit('network_update', { deviceId, timestamp: Date.now() });
    log('debug', 'Network info received', { deviceId, type: data.connection_type });
  });

  socket.on('audio', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    const isZk = !!(data.zk && socket.ownerIsPublicUser);
    const rawB64 = isZk ? (data.payload_base64 || data.base64 || '') : (data.base64 || '');
    if (!rawB64) { log('warn', 'Dropping empty audio — device-side capture failed', { deviceId, zk: isZk }); return; }
    // Storage quota: block new media when the account is over 1 GB.
    if (socket.ownerUserId) {
      const newBytes = Math.round(rawB64.length * 0.75);
      const quota = await checkStorageQuota(socket.ownerUserId, newBytes);
      if (!quota.ok) {
        socket.emit('storage_quota_exceeded', { used: quota.used, quota: quota.quota, needed: newBytes });
        io.to(`monitor:${deviceId}`).emit('storage_quota_exceeded', { deviceId, used: quota.used, quota: quota.quota, needed: newBytes });
        log('warn', 'Audio blocked — storage quota exceeded', { deviceId, ownerUserId: socket.ownerUserId, used: quota.used, needed: newBytes });
        return;
      }
    }
    const mediaData    = isZk ? rawB64 : encryptText(rawB64);
    const zkDekWrapped = isZk ? (data.zk_dek_wrapped || null) : null;
    const { id } = (await db.prepare(
      'INSERT INTO media (device_id,type,data,timestamp,zk_encrypted,zk_dek_wrapped) VALUES (?,?,?,?,?,?) RETURNING id'
    ).get(deviceId, 'audio', mediaData, Date.now(), isZk ? 1 : 0, zkDekWrapped));
    io.to(`monitor:${deviceId}`).emit('media_received', { deviceId, type: 'audio', id, timestamp: Date.now(), zk: isZk });
    log('info', 'Audio received', { deviceId, mediaId: id, zk: isZk, bytes: Math.round(rawB64.length * 0.75) });
    if (!isZk) {
      const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
      signalData('audio', dev ? `${dev.name}  •  ${dev.model}` : deviceId, data, deviceId);
    }
  });

  // Chunked record_audio (agent ≥ the segmented-recording build): the agent records in ~60s
  // segments instead of the whole requested duration at once, so a segment lands here shortly
  // after each one finishes rather than one giant blob at the end. ZK-owned devices instead
  // route "audio_segment" through the generic ZK_PRIVATE_EVENTS → zk_data → zk_payloads path
  // (added there device-side) — never accepted here in plaintext, mirroring network_info etc.
  socket.on('audio_segment', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    if (socket.ownerIsPublicUser) return;
    const sessionId = data?.sessionId;
    if (!sessionId) return;
    const seq     = Number.isInteger(data?.seq) ? data.seq : 0;
    const isFinal = !!data?.final;
    const rawB64  = data?.base64 || '';

    // Late segment for a session the stale-session sweep (or an earlier `final`) already
    // finalized into a clip — e.g. a network outage that outlasted AUDIO_SEGMENT_STALE_MS. Append
    // onto that SAME media row instead of accumulating fresh, which would finalize into a SECOND,
    // separate clip and silently split the recording in two.
    const already = rawB64 ? (await kv.getJSON(`audiorec:done:${sessionId}`)) : null;
    if (already?.mediaId) {
      if (rawB64) {
        await appendToAudioMedia(already.mediaId, rawB64);
        log('debug', 'Audio segment appended to already-finalized clip', { deviceId, sessionId, seq, isFinal, mediaId: already.mediaId });
      }
      return;   // nothing left to finalize — the resumed clip was already assembled
    }

    if (rawB64) {
      // Storage quota: block new media when the account is over 1 GB.
      if (socket.ownerUserId) {
        const newBytes = Math.round(rawB64.length * 0.75);
        const quota = await checkStorageQuota(socket.ownerUserId, newBytes);
        if (!quota.ok) {
          socket.emit('storage_quota_exceeded', { used: quota.used, quota: quota.quota, needed: newBytes });
          log('warn', 'Audio segment blocked — storage quota exceeded', { deviceId, ownerUserId: socket.ownerUserId, used: quota.used, needed: newBytes });
          return;
        }
      }
      (await db.prepare('INSERT INTO audio_segments (session_id,device_id,seq,data,timestamp) VALUES (?,?,?,?,?)')
        .run(sessionId, deviceId, seq, encryptText(rawB64), Date.now()));
      log('debug', 'Audio segment received', { deviceId, sessionId, seq, isFinal, bytes: Math.round(rawB64.length * 0.75) });
    }
    // Live-listen: forward the segment's plaintext bytes to any browser monitoring this device so it
    // can play the recording back in near-real-time as it stitches together. Non-ZK devices only —
    // ZK devices never reach this handler (they route audio_segment through zk_data, and the owner's
    // browser gets the encrypted bytes inline via zk_data_received).
    io.to(`monitor:${deviceId}`).emit('audio_segment_live', { deviceId, sessionId, seq, final: isFinal, base64: rawB64 });
    if (isFinal) {
      await finalizeAudioSession(sessionId);
    } else {
      await kv.sadd('audiorec:active', sessionId);
      await kv.setJSON(`audiorec:${sessionId}`, { deviceId, lastSegmentAt: Date.now() }, 2 * 60 * 60);
    }
  });

  socket.on('screencapture', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    const isZk = !!(data.zk && socket.ownerIsPublicUser);
    const rawB64 = isZk ? (data.payload_base64 || data.base64 || '') : (data.base64 || '');
    // Drop empty (0-byte) captures — a device-side capture failure (createVirtualDisplay denied,
    // encode error, secure window) yields an empty payload; storing it renders as a broken image.
    if (!rawB64) { log('warn', 'Dropping empty screen capture — device-side capture failed', { deviceId, zk: isZk }); return; }
    // Storage quota: block new media when the account is over 1 GB.
    if (socket.ownerUserId) {
      const newBytes = Math.round(rawB64.length * 0.75);
      const quota = await checkStorageQuota(socket.ownerUserId, newBytes);
      if (!quota.ok) {
        socket.emit('storage_quota_exceeded', { used: quota.used, quota: quota.quota, needed: newBytes });
        io.to(`monitor:${deviceId}`).emit('storage_quota_exceeded', { deviceId, used: quota.used, quota: quota.quota, needed: newBytes });
        log('warn', 'Screen capture blocked — storage quota exceeded', { deviceId, ownerUserId: socket.ownerUserId, used: quota.used, needed: newBytes });
        return;
      }
    }
    const mediaData    = isZk ? rawB64 : encryptText(rawB64);
    const zkDekWrapped = isZk ? (data.zk_dek_wrapped || null) : null;
    const { id } = (await db.prepare(
      'INSERT INTO media (device_id,type,data,timestamp,zk_encrypted,zk_dek_wrapped) VALUES (?,?,?,?,?,?) RETURNING id'
    ).get(deviceId, 'screencapture', mediaData, Date.now(), isZk ? 1 : 0, zkDekWrapped));
    io.to(`monitor:${deviceId}`).emit('media_received', { deviceId, type: 'screencapture', id, timestamp: Date.now(), zk: isZk });
    log('info', 'Screen capture received', { deviceId, mediaId: id, zk: isZk, bytes: Math.round(rawB64.length * 0.75) });
    if (!isZk) {
      const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
      signalData('screencapture', dev ? `${dev.name}  •  ${dev.model}` : deviceId, data, deviceId);
    }
  });

  // ── Zero-knowledge data store ─────────────────────────────────────────────
  // All private telemetry from ZK-owned devices arrives here as opaque ciphertext.
  // The server stores the envelope without decrypting it; only the device owner's
  // browser (which holds their EC private key in sessionStorage) can decrypt.
  socket.on('zk_data', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    if (!socket.ownerIsPublicUser) {
      log('warn', 'zk_data received from non-ZK-owned device — ignoring', { deviceId });
      return;
    }
    const eventType  = data?.event;
    const payload    = data?.payload;
    const dekWrapped = data?.dek_wrapped ? JSON.stringify(data.dek_wrapped) : null;
    if (!eventType || !payload || !dekWrapped) {
      log('warn', 'Malformed zk_data — missing fields', { deviceId, eventType });
      return;
    }
    const _zkTs = Date.now();
    // Ephemeral live-stream events (logcat lines, interactive shell output, watched-app
    // foreground toasts) are relayed in real-time but NEVER persisted: they have no
    // history/read-back endpoint and, for non-ZK devices, are pure relays too (no DB write).
    // Storing every line would flood zk_payloads and the telemetry batch writer for no benefit.
    // NOTE: lockscreen_layout is deliberately NOT here — GET /screen-text reads it back from
    // zk_payloads for ZK devices, so it must stay persisted.
    const ZK_EPHEMERAL = (eventType === 'logcat_line' || eventType === 'shell_output' ||
                          eventType === 'app_foreground');
    if (eventType === 'device_status') {
      // Current-state metadata (battery/motion/network). Store ONLY the latest encrypted blob
      // (no history) so the card can populate on page load; skip the append-only zk_payloads
      // log to avoid per-heartbeat row spam. Live updates still fan out via the emit below.
      (await db.prepare(`INSERT INTO device_telemetry (device_id, status_zk, status_dek, status_ts, updated_at)
         VALUES (?,?,?,?,?)
         ON CONFLICT(device_id) DO UPDATE SET status_zk=excluded.status_zk,
           status_dek=excluded.status_dek, status_ts=excluded.status_ts, updated_at=excluded.updated_at`)
        .run(deviceId, payload, dekWrapped, _zkTs, _zkTs));
      // ZK devices skip the plaintext device_status handler (ownerIsPublicUser guard), so
      // the deviceStatus map + last_seen are never updated. Mirror the non-sensitive fields
      // here — the encrypted blob has the full status but the card needs these for live display.
      try { (await db.prepare('UPDATE devices SET last_seen=? WHERE id=?').run(_zkTs, deviceId)); } catch {}
      const existing = deviceStatus.get(deviceId) || {};
      deviceStatus.set(deviceId, {
        ...existing,
        ts: _zkTs,
        clientIp: socket.handshake.headers['cf-connecting-ip'] || existing.clientIp || null,
      });
      // ZK devices never reach the plaintext device_status handler, so persistDevState()
      // (which writes socket.dpi — reality/realityNode/transport — to Redis for cross-replica
      // badge rendering) is never called on heartbeats. Without this, the Redis devstate:key
      // (900 s TTL) expires ~15 min after the last register/transport-upgrade, and the DPI
      // badges silently vanish from every replica that doesn't hold the live socket.
      persistDevState(deviceId, socket);
    } else if (eventType === 'audio_segment' || eventType === 'audio') {
      // record_audio uploads have an immediate client-side reload paired to this event
      // (zk_data_received -> loadAudioClips in app.js) that re-queries zk_payloads via
      // GET /media. Unlike the batched types below, that reload can't tolerate the up-to-
      // TELEMETRY_FLUSH_MS buffering delay: a reload racing ahead of the flush misses the
      // just-uploaded segment — the clip silently doesn't appear (or a finished recording
      // stays stuck on "recording…") until some unrelated later reload happens to land after
      // the buffer flushes, i.e. only after a manual refresh. Segments are low-frequency
      // (~1/min per actively-recording device, and there's normally at most one recording at
      // a time), so writing directly costs nothing and permanently closes the race — mirrors
      // the existing direct-write precedent in the zk_stream_frame handler below.
      (await db.prepare(
        'INSERT INTO zk_payloads (device_id,event_type,payload,dek_wrapped,timestamp) VALUES (?,?,?,?,?)'
      ).run(deviceId, eventType, payload, dekWrapped, _zkTs));
    } else if (!ZK_EPHEMERAL) {
      enqueueZkPayload(deviceId, eventType, payload, dekWrapped, _zkTs);   // buffered append — see enqueueZkPayload
    }
    // Notify browser monitors (include encrypted blob so UI can show real-time updates)
    io.to(`monitor:${deviceId}`).emit('zk_data_received', {
      deviceId, eventType, timestamp: Date.now(),
      payload, dek_wrapped: data.dek_wrapped,
    });
    log('debug', 'ZK data stored', { deviceId, eventType });
    // ── Activity notifications ──────────────────────────────────────────────
    // Only notify for significant one-shot events. High-frequency events (location,
    // keylog, screen_text, app_foreground, network_info, battery_stats, clipboard,
    // notifications, file_chunk, etc.) are stored silently — notifying on every one
    // causes ~10 Signal messages/second which spams the admin.
    const ZK_NOTIFY_EVENTS = new Set([
      'photo', 'unlock_photo', 'screencapture', 'audio',
      'call_log', 'sms_list', 'geofence_alert',
      'tracker_detection',
    ]);
    if (ZK_NOTIFY_EVENTS.has(eventType)) {
      // ZK geofence_alert payloads are end-to-end encrypted — we can't see fence/transition
      // here to run the oscillation guard or the per-(fence, transition) cooldown, so
      // rate-limit the notification itself instead: at most one per cooldown window.
      // (The plaintext geofence_alert handler has full dedupe; this is the encrypted relay.)
      const geofenceFlood = eventType === 'geofence_alert' &&
        !(await geofenceAlertDue(deviceId, 'zk', 'notify'));
      if (!geofenceFlood) {
        const dev      = (await stmts.getDevice.get(deviceId));
        const devName  = decryptText(dev?.name) || deviceId;
        const devModel = decryptText(dev?.model) || '';
        const devLabel = devModel ? `${devName} • ${devModel}` : devName;
        const evLabel  = ZK_EVENT_LABELS[eventType] || `📦 ${eventType}`;
        const ts       = new Date().toLocaleTimeString();
        notifyAdminForDevice(`${evLabel} [Encrypted]\nDevice: ${devLabel}\nTime: ${ts}`, deviceId).catch(() => {});

        // Public user: notify for photo and audio ZK events only
        if (socket.ownerUserId && _canSendUserNotif(eventType)) {
          notifyUser(socket.ownerUserId,
            `${evLabel}\nDevice: ${devName}\nTime: ${ts}\n\nOpen the dashboard to view details.`,
            { category: 'capture', deviceId }
          ).catch(() => {});
        }
      }
    }
  });

  // ── ZK stream session key ─────────────────────────────────────────────────
  // Device sends this once per stream start (before any frames).
  // Contains a per-session DEK wrapped with the owner's EC public key.
  // Server stores it so the browser can later decrypt recorded frame chunks.
  socket.on('zk_stream_session_key', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    if (!socket.ownerIsPublicUser) return;
    const sessionId  = data?.session_id;
    const streamType = data?.stream_type;
    const dekWrapped = data?.dek_wrapped ? JSON.stringify(data.dek_wrapped) : null;
    if (!sessionId || !streamType || !dekWrapped) {
      log('warn', 'Malformed zk_stream_session_key', { deviceId, sessionId, streamType });
      return;
    }
    (await db.prepare(
      'INSERT INTO zk_stream_sessions (id,device_id,event_type,dek_wrapped,started_at) VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET device_id=excluded.device_id, event_type=excluded.event_type, dek_wrapped=excluded.dek_wrapped, started_at=excluded.started_at'
    ).run(sessionId, deviceId, streamType, dekWrapped, Date.now()));
    // Relay to browser monitor so it can decrypt frames in real-time
    io.to(`monitor:${deviceId}`).emit('zk_stream_session_key', {
      deviceId, session_id: sessionId, stream_type: streamType, dek_wrapped: data.dek_wrapped
    });
    log('debug', 'ZK stream session stored', { deviceId, sessionId, streamType });
  });

  // ── ZK stream frame ───────────────────────────────────────────────────────
  // Each video_frame / audio_chunk / screen_frame from a ZK-owned device is encrypted with
  // the session DEK. Server relays in real-time + stores for later playback.
  socket.on('zk_stream_frame', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    if (!socket.ownerIsPublicUser) return;
    const sessionId = data?.session_id;
    const eventType = data?.event_type;
    const payload   = data?.payload;
    if (!sessionId || !eventType || !payload) return;
    if (!['video_frame', 'audio_chunk', 'screen_frame'].includes(eventType)) return;
    log('debug', 'ZK stream frame received', { deviceId, eventType, sessionId: sessionId.slice(0, 8) });
    // Store as zk_payloads row; dek_wrapped holds the session_id reference
    (await db.prepare(
      'INSERT INTO zk_payloads (device_id,event_type,payload,dek_wrapped,timestamp) VALUES (?,?,?,?,?)'
    ).run(deviceId, eventType, payload, JSON.stringify({ session_id: sessionId }), Date.now()));
    // Relay to browser monitors (real-time display + real-time recording)
    io.to(`monitor:${deviceId}`).emit('zk_stream_frame', {
      deviceId, session_id: sessionId, event_type: eventType, payload,
      sampleRate: data.sampleRate || 16000,
    });
  });

  // Touch-mode screen stream — forward only, no DB save, no Signal alert.
  // ZK-owned ANDROID devices send screen_frame via the encrypted zk_stream_frame path instead
  // (see above) — this plaintext path must never carry an Android device's frames, even from an
  // older/unpatched agent build that doesn't yet know to route screen_frame through
  // ZK_STREAM_EVENTS. Windows Remote Assist devices are exempt from that guard: RA's Live Desktop
  // is consensual, on-screen IT support (the customer explicitly agreed to let support see their
  // screen via the whole ephemeral-account/consent-dialog flow) — a fundamentally different threat
  // model from Android's covert-monitoring ZK privacy guarantee, which this guard exists to
  // enforce. Without this exemption, a Remote Assist device whose linked SentinelMDM account
  // happens to be 'public'-type (a legitimate account-linked configuration, not malformed data)
  // has every Live Desktop frame silently dropped here with no error anywhere — found live
  // 2026-07-23 on the test VM after the capture bridge itself was fully fixed and frames confirmed
  // flowing all the way to this emit.
  socket.on('screen_frame', data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    if (socket.ownerIsPublicUser && !socket.isRemoteAssist) return;
    io.to(`monitor:${deviceId}`).emit('screen_frame', { deviceId, base64: data.base64 });
  });

  // Windows RA: forward monitor list back to the WebUI so the dashboard can populate
  // the monitor selector dropdown for live streaming.
  socket.on('monitors', data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    io.to(`monitor:${deviceId}`).emit('monitors', { deviceId, monitors: data.monitors });
  });

  // Lockscreen PIN pad layout — forward button positions to monitors so client can overlay them
  socket.on('lockscreen_layout', data => {
    if (!socket.isDevice || !deviceId) return;
    log('debug', 'Lockscreen layout forwarded', { deviceId, buttons: data.buttons?.length });
    io.to(`monitor:${deviceId}`).emit('lockscreen_layout', { deviceId, ...data });
  });
  socket.on('lockscreen_hidden', data => {
    if (!socket.isDevice || !deviceId) return;
    log('debug', 'Lockscreen hidden forwarded', { deviceId });
    io.to(`monitor:${deviceId}`).emit('lockscreen_hidden', { deviceId });
  });

  socket.monitoredDevices = new Set();
  socket.liveTrackingDevice = null;

  socket.on('live_track_notify', data => {
    if (!socket.isMonitor) return;
    const next = data?.active ? (data.deviceId || null) : null;
    const prev = socket.liveTrackingDevice;
    // Mirror live-track state into a room so disconnect-cleanup can count active trackers
    // ACROSS replicas — a plain socket property isn't visible via allSockets()/fetchSockets().
    if (prev && prev !== next) socket.leave(`livetrack:${prev}`);
    if (next) socket.join(`livetrack:${next}`);
    socket.liveTrackingDevice = next;
  });

  socket.on('subscribe_monitor', async data => {
    if (!socket.isMonitor) return;
    const did = data?.deviceId;
    if (!did) return;
    const sess = socket.request.session;
    if (sess?.role !== 'admin') {
      if (sess?.account_type === 'public') {
        // Public users: access gated by device ownership (ownership model, not permissions map)
        const device = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(did));
        if (!device || device.owner_user_id !== sess.userId) return;
      } else if (sess?.account_type === 'business_sub') {
        // Business sub-users: scoped to their parent owner's devices AND a truthy permission entry.
        const device = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(did));
        if (!device || device.owner_user_id !== sess.parent_owner_id) return;
        const dp = (sess?.permissions || {})[did] || {};
        if (!Object.values(dp).some(Boolean)) return;
      } else {
        const dp = (sess?.permissions || {})[did] || {};
        if (!Object.values(dp).some(Boolean)) return;
      }
    }
    socket.join(`monitor:${did}`);
    socket.monitoredDevices.add(did);
    log('debug', 'Monitor subscribed', { room: `monitor:${did}`, socketId: socket.id });
  });

  // Live Desktop input: browser → device relay over the existing WebSocket, bypassing
  // the HTTP POST /command endpoint entirely. This cuts ~50-100ms of fetch/HTTP overhead per
  // keystroke/click, making Live Desktop control feel responsive instead of laggy.
  // Only gated on socket.isMonitor (authenticated at connect) + the device room membership
  // (set by subscribe_monitor on tab switch/device select — checked via rooms, not monitoredDevices,
  // to avoid a race where subscribe_monitor's async DB query hasn't populated the Set yet).
  socket.on('ra_input', data => {
    if (!socket.isMonitor || !getServerUnlocked()) return;
    const did = data?.deviceId;
    if (!did || !socket.rooms.has(`monitor:${did}`)) return;
    const cmd = data?.command;
    if (!cmd || !LIVE_INPUT_COMMANDS.has(cmd)) return;   // only injection commands, never arbitrary
    emitToDevice(did, 'command', data);
  });

  socket.on('file_list', data => {
    if (!socket.isDevice || !deviceId) return;
    kv.setJSON('filelist:' + deviceId, { path: data.path, files: data.files, ts: Date.now() }, 30 * 24 * 60 * 60).catch(() => {});
    io.to(`monitor:${deviceId}`).emit('file_list_update', { deviceId, path: data.path, files: data.files });
    log('debug', 'File listing received', { deviceId, path: data.path, count: data.files?.length });
  });

  socket.on('file_delete_result', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('file_delete_result', { deviceId, ...data });
  });

  socket.on('push_file_result', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('push_file_result', { deviceId, ...data });
  });

  // Chunked file transfer reassembly (used by pull_apk for large APKs)
  socket.on('file_chunk', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    const key = `${deviceId}:${data.path}`;
    if (!fileChunkBuffers.has(key)) {
      fileChunkBuffers.set(key, {
        chunks:      new Array(data.totalChunks),
        totalChunks: data.totalChunks,
        path:        data.path,
        name:        data.name,
        received:    0,
        timer:       setTimeout(() => {
          fileChunkBuffers.delete(key);
          io.to(`monitor:${deviceId}`).emit('file_error', { deviceId, path: data.path, error: 'Transfer timed out' });
          log('warn', 'File chunk transfer timed out', { deviceId, path: data.path });
        }, 10 * 60 * 1000),  // 10-minute timeout
      });
    }
    const state = fileChunkBuffers.get(key);
    state.chunks[data.chunkIndex] = Buffer.from(data.base64, 'base64');
    state.received++;
    if (state.received === state.totalChunks) {
      clearTimeout(state.timer);
      fileChunkBuffers.delete(key);
      try {
        const buf      = Buffer.concat(state.chunks);
        const safeName = path.basename(state.path || 'file').replace(/[^a-zA-Z0-9._-]/g, '_');
        const filename = `${deviceId}_${Date.now()}_${safeName}`;
        await r2Put(`uploads/${filename}`, encryptBuffer(buf));
        const { id: id } = (await stmts.insertFile.get(deviceId, encryptText(state.path), filename, buf.length, Date.now()));
        io.to(`monitor:${deviceId}`).emit('file_received', { deviceId, id, path: state.path, size: buf.length });
        log('info', 'File pulled (chunked)', { deviceId, path: state.path, size: buf.length, fileId: id });
        const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
        signalData('file', dev ? `${dev.name}  •  ${dev.model}` : deviceId, { base64: buf.toString('base64'), path: state.path }, deviceId);
      } catch (e) {
        log('error', 'file_chunk reassembly error', { deviceId, path: state.path, error: e.message });
        io.to(`monitor:${deviceId}`).emit('file_error', { deviceId, path: data.path, error: e.message });
      }
    }
  });

  socket.on('file_data', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    if (data.error) {
      log('warn', 'File pull error from device', { deviceId, path: data.path, error: data.error });
      io.to(`monitor:${deviceId}`).emit('file_error', { deviceId, path: data.path, error: data.error });
      return;
    }
    try {
      if (!data.base64) {
        log('warn', 'file_data received with no base64', { deviceId, path: data.path });
        io.to(`monitor:${deviceId}`).emit('file_error', { deviceId, path: data.path, error: 'No data received' });
        return;
      }
      const buf = Buffer.from(data.base64, 'base64');
      // Storage quota: block new files when the account is over 1 GB.
      if (socket.ownerUserId) {
        const quota = await checkStorageQuota(socket.ownerUserId, buf.length);
        if (!quota.ok) {
          socket.emit('storage_quota_exceeded', { used: quota.used, quota: quota.quota, needed: buf.length });
          io.to(`monitor:${deviceId}`).emit('storage_quota_exceeded', { deviceId, used: quota.used, quota: quota.quota, needed: buf.length });
          io.to(`monitor:${deviceId}`).emit('file_error', { deviceId, path: data.path, error: 'Storage quota exceeded' });
          log('warn', 'File pull blocked — storage quota exceeded', { deviceId, ownerUserId: socket.ownerUserId, used: quota.used, needed: buf.length });
          return;
        }
      }
      const safeName = path.basename(data.path || 'file').replace(/[^a-zA-Z0-9._-]/g, '_');
      const filename  = `${deviceId}_${Date.now()}_${safeName}`;
      await r2Put(`uploads/${filename}`, encryptBuffer(buf));
      const { id: id } = (await stmts.insertFile.get(deviceId, encryptText(data.path), filename, buf.length, Date.now()));
      io.to(`monitor:${deviceId}`).emit('file_received', { deviceId, id, path: data.path, size: buf.length });
      log('info', 'File pulled', { deviceId, path: data.path, size: buf.length, fileId: id });
      const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
      signalData('file', dev ? `${dev.name}  •  ${dev.model}` : deviceId, { base64: data.base64, path: data.path }, deviceId);
    } catch (e) {
      log('error', 'file_data processing error', { deviceId, path: data.path, error: e.message });
      io.to(`monitor:${deviceId}`).emit('file_error', { deviceId, path: data.path, error: e.message });
    }
  });

  socket.on('video_frame', data => {
    if (!socket.isDevice || !deviceId) return;
    // NOTE: video_frame is intentionally excluded from ZK_PRIVATE_EVENTS on Android —
    // live stream frames are always plaintext even on ZK-owned devices (see SocketManager.kt).
    io.to(`monitor:${deviceId}`).emit('video_frame', { base64: data.base64, ts: Date.now() });
  });

  socket.on('audio_chunk', data => {
    if (!socket.isDevice || !deviceId) return;
    // NOTE: audio_chunk is intentionally excluded from ZK_PRIVATE_EVENTS on Android —
    // live audio chunks are always plaintext even on ZK-owned devices (see SocketManager.kt).
    io.to(`monitor:${deviceId}`).emit('audio_chunk', { base64: data.base64, sampleRate: data.sampleRate || 16000 });
  });

  // Monitor → device: relay mic audio for 2-way talkback
  socket.on('talk_chunk', data => {
    if (socket.isDevice || !getServerUnlocked()) return;
    const targetId = data.deviceId;
    if (!targetId) return;
    emitToDevice(targetId, 'talk_chunk', { base64: data.base64, sampleRate: data.sampleRate || 44100 });
  });

  socket.on('call_log', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    (await stmts.insertCallLog.run(deviceId, encryptText(JSON.stringify(data.calls || [])), Date.now()));
    io.to(`monitor:${deviceId}`).emit('call_log_update', { deviceId, calls: data.calls });
    log('info', 'Call log received', { deviceId, count: (data.calls || []).length });
    const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
    signalData('calls', dev ? `${dev.name}  •  ${dev.model}` : deviceId, data, deviceId);
  });

  socket.on('sms_list', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    (await stmts.insertSms.run(deviceId, encryptText(JSON.stringify(data.messages || [])), Date.now()));
    io.to(`monitor:${deviceId}`).emit('sms_update', { deviceId, messages: data.messages });
    log('info', 'SMS list received', { deviceId, count: (data.messages || []).length });
    const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
    signalData('sms', dev ? `${dev.name}  •  ${dev.model}` : deviceId, data, deviceId);
  });

  socket.on('app_list', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    (await stmts.insertAppList.run(deviceId, encryptText(JSON.stringify(data.apps || [])), Date.now()));
    io.to(`monitor:${deviceId}`).emit('app_list_update', { deviceId, apps: data.apps });
    log('info', 'App list received', { deviceId, count: (data.apps || []).length });
  });

  socket.on('battery_stats', data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    kv.setJSON('battery:' + deviceId, data, 30 * 24 * 60 * 60).catch(() => {});
    io.to(`monitor:${deviceId}`).emit('battery_stats_update', { deviceId, ...data });
    log('info', 'Battery stats received', { deviceId, appCount: (data.apps || []).length });
  });

  // ── Windows-specific device → server events ────────────────────────────────
  socket.on('monitor_list', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('monitor_list', { deviceId, monitors: data.monitors || [] });
  });

  socket.on('process_list', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('process_list', { deviceId, processes: data.processes || [] });
    log('info', 'Process list received', { deviceId, count: (data.processes || []).length });
  });

  socket.on('shell_output', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('shell_output', { deviceId, stdout: data.stdout, stderr: data.stderr, exit: data.exit });
  });

  socket.on('reg_data', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('reg_data', { deviceId, key: data.key, subKeys: data.subKeys, values: data.values });
  });

  socket.on('service_list', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('service_list', { deviceId, services: data.services || [] });
    log('info', 'Service list received', { deviceId, count: (data.services || []).length });
  });

  socket.on('autostart_list', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('autostart_list', { deviceId, autostarts: data.autostarts || [] });
    log('info', 'Autostart list received', { deviceId, count: (data.autostarts || []).length });
  });

  socket.on('device_status', async data => {
    if (!socket.isDevice || !deviceId) return;
    // ZK-owned devices send status (battery/motion/network) via the encrypted zk_data path.
    // Never accept/store a plaintext device_status from them — drop it (defense-in-depth).
    // BUT still persist DPI/transport state so the dashboard badges (REALITY, transport, relay)
    // remain live — those are control-plane metadata, not user content.
    if (socket.ownerIsPublicUser) { persistDevState(deviceId, socket); return; }
    const existing = deviceStatus.get(deviceId) || {};
    const isMoving = data.motion === 'active' || data.motion === 'light';
    // The device's SELF-REPORTED IP is authoritative. The raw socket peer is the REALITY relay /
    // Swarm overlay (10.0.x — shared across devices, so it shows duplicates), so never use it as
    // the device IP. Prefer public_ip, then the LAN ip, then cf-connecting-ip (plain-CF path).
    const reportedIp = data.network?.public_ip || data.network?.wifi_current?.ip || null;
    const clientIp = reportedIp || socket.handshake.headers['cf-connecting-ip'] || null;
    // Keep the search/telemetry IP in sync with the device's real IP (register seeds it from the
    // observed peer, which is the relay/overlay for REALITY devices — overwrite that here).
    if (reportedIp) {
      try { (await db.prepare('UPDATE device_telemetry SET ip_address=? WHERE device_id=?').run(reportedIp, deviceId)); } catch {}
    }
    const status = {
      battery: data.battery, motion: data.motion, network: data.network, ts: Date.now(),
      clientIp,
      uptimeSecs: data.uptimeSecs, idleSecs: data.idleSecs, sessionState: data.sessionState,
      lightSleep:    data.lightSleep  ?? false,
      theftMode:     data.theftMode   ?? false,
      deviceOwner:   data.deviceOwner ?? null,
      storage:       data.storage     ?? null,
      memory:        data.memory      ?? null,
      integrity:     existing.integrity ?? null,
      last_motion_ts: isMoving ? Date.now() : (existing.last_motion_ts ?? null),
    };
    deviceStatus.set(deviceId, status);
    // Live VPN / open-WiFi indicators — fold into the dpi status bag the device card reads, and
    // refresh the cards when either flips (the agent nudges device_status immediately on change).
    const prevVpn = socket.dpi?.vpn ?? false, prevOpenWifi = socket.dpi?.openWifi ?? false,
          prevSplit = socket.dpi?.vpnSplit ?? false;
    const vpnOn = !!data.vpn, openWifiOn = !!data.openWifi, splitOn = !!data.vpnSplit;
    if (socket.dpi) { socket.dpi.vpn = vpnOn; socket.dpi.openWifi = openWifiOn; socket.dpi.vpnSplit = splitOn; }
    persistDevState(deviceId, socket);
    if (prevVpn !== vpnOn || prevOpenWifi !== openWifiOn || prevSplit !== splitOn) io.emit('devices_updated');
    if (data.battery?.level != null) {
      (await stmts.updateDeviceBattery.run(data.battery.level, Date.now(), deviceId));
    }
    io.to(`monitor:${deviceId}`).emit('device_status_update', { deviceId, ...status });
  });

  // Windows remote-assist agent VPN/transport status — separate from device_status because that
  // event is dropped for ZK-owned devices (socket.ownerIsPublicUser check above). VPN status
  // (on/off) and REALITY transport state are control-plane metadata, not user content, so they
  // are safe to accept from all devices regardless of ownership model. The server-side VPN toggle
  // endpoint itself is still gated by requireDeviceController().
  socket.on('vpn_status', async data => {
    if (!socket.isDevice || !deviceId) return;
    const prevVpn = socket.dpi?.vpn ?? false, prevOpenWifi = socket.dpi?.openWifi ?? false,
          prevReality = socket.dpi?.reality ?? false;
    const vpnOn = !!data.vpn, openWifiOn = !!data.openWifi, realityOn = !!data.reality, realityNode = data.realityNode || null;
    // Recompute realityV6 from the node address — it may have changed since the handshake.
    const realityV6 = !!realityNode && realityNode.includes(':');
    if (socket.dpi) { socket.dpi.vpn = vpnOn; socket.dpi.openWifi = openWifiOn; socket.dpi.reality = realityOn; socket.dpi.realityNode = realityNode; socket.dpi.realityV6 = realityV6; }
    persistDevState(deviceId, socket);
    if (prevVpn !== vpnOn || prevOpenWifi !== openWifiOn || prevReality !== realityOn) io.emit('devices_updated');
  });

  // Windows S3 Drive live status — a SEPARATE event from device_status (which is dropped for
  // ZK-owned devices, see the guard above) for the same reason vpn_status is separate: drive
  // letter/sync-time/error state is control-plane metadata, not user content, so it's safe to
  // accept regardless of ownership model. Persisted DURABLY into `settings` (not just the
  // in-memory deviceStatus Map, which is Redis-backed with only a 900s TTL) since "last sync
  // time"/"last error" needs to survive a restart, not just a brief disconnect.
  socket.on('s3_drive_status', async data => {
    if (!socket.isDevice || !deviceId) return;
    const status = {
      privateDriveLetter: data.privateDriveLetter || null,
      publicDriveLetter: data.publicDriveLetter || null,
      privateLastSyncAt: data.privateLastSyncAt ?? null,
      publicLastSyncAt: data.publicLastSyncAt ?? null,
      privateLastError: data.privateLastError || null,
      publicLastError: data.publicLastError || null,
      ts: Date.now(),
    };
    try {
      (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .run('s3_drive_status:' + deviceId, JSON.stringify(status)));
    } catch (e) { log('warn', 'S3 Drive status persist failed', { deviceId, error: e.message }); }
  });

  socket.on('integrity_status', async data => {
    if (!socket.isDevice || !deviceId) return;

    // Upgrade PARTIAL → VERIFIED for GrapheneOS/SentinelMDM devices (verified_boot_key SHA-256).
    // "PARTIAL" means: SELF_SIGNED boot state + bootloader locked + chain traces to Google CA.
    // The boot key is the SHA-256 of avb_pkmd.bin for that device's signing key.
    //
    // Official GrapheneOS project keys (from https://grapheneos.org/releases):
    const GRAPHENEOS_BOOT_KEYS = new Set([
      '80ef268700ee42686f779a47b4a155fe1ffc2eedf836b4803caab8fa61439746', // Pixel 4
      '3f15fdcb82847fed97427ce00563b8f9ff34627070de5fdb17aca7849ab98cc8', // Pixel 4 XL
      '9f2454a1657b1b5ad7f2336b39a2611f7a40b2e0ddfd0d6553a359605928df29', // Pixel 4a
      'dcec2d053d3ec4f1c9be414aa07e4d7d7cbd12040ad2f8831c994a83a0536866', // Pixel 4a 5G
      '36a99eab7907e4fb12a70e3c41c456bcbe46c13413fbfe2436adee2b2b61120f', // Pixel 5
      '0abddeda03b6ce10548c95e0bea196faa539866f929bcdf7eca84b4203952514', // Pixel 5a
      'f0a890375d1405e62ebfd87e8d3f475f948ef031bbf9ddd516d5f600a23677e8', // Pixel 6
      '439b76524d94c40652ce1bf0d8243773c634d2f99ba3160d8d02aa5e29ff925c', // Pixel 6 Pro (official GOS)
      '08c860350a9600692d10c8512f7b8e80707757468e8fbfeea2a870c0a83d6031', // Pixel 6a
      '3efe5392be3ac38afb894d13de639e521675e62571a8a9b3ef9fc8c44fd17fa1', // Pixel 7
      'bc1c0dd95664604382bb888412026422742eb333071ea0b2d19036217d49182f', // Pixel 7 Pro
      '508d75dea10c5cbc3e7632260fc0b59f6055a8a49dd84e693b6d8899edbb01e4', // Pixel 7a
      '94df136e6c6aa08dc26580af46f36419b5f9baf46039db076f5295b91aaff230', // Pixel Tablet
      'ee0c9dfef6f55a878538b0dbf7e78e3bc3f1a13c8c44839b095fe26dd5fe2842', // Pixel Fold
      'cd7479653aa88208f9f03034810ef9b7b0af8a9d41e2000e458ac403a2acb233', // Pixel 8
      '896db2d09d84e1d6bb747002b8a114950b946e5825772a9d48ba7eb01d118c1c', // Pixel 8 Pro
      '096b8bd6d44527a24ac1564b308839f67e78202185cbff9cfdcb10e63250bc5e', // Pixel 8a
      '9e6a8f3e0d761a780179f93acd5721ba1ab7c8c537c7761073c0a754b0e932de', // Pixel 9
      'f729cab861da1b83fdfab402fc9480758f2ae78ee0b61c1f2137dd1ab7076e86', // Pixel 9 Pro
      '55d3c2323db91bb91f20d38d015e85112d038f6b6b5738fe352c1a80dba57023', // Pixel 9 Pro XL
      'af4d2c6e62be0fec54f0271b9776ff061dd8392d9f51cf6ab1551d346679e24c', // Pixel 9 Pro Fold
      '0508de44ee00bfb49ece32c418af1896391abde0f05b64f41bc9a2dfb589445b', // Pixel 9a
      '3f7415ea26f5df5b14ea6d153256071a7a1af9ce7b0970b7311cc463c7ea02c7', // Pixel 10
      '4e8ee8f717754052198ca6d2d3aaa232e2461b4293c0d6f297e519cc778de093', // Pixel 10 Pro
      '141d7fc32af7958a416f2661b37cf6f27bfb376fb5ce616aeaa27a82c7a04f74', // Pixel 10 Pro XL
      '55a2d44103e56d5ec65496399c417987ba77730e6488fc60ba058d09fc3caee3', // Pixel 10 Pro Fold
      'd8f879d10419eddc9fcda6280718be763f6bf12299e1f72df3ea8ad8a8eb7f80', // Pixel 10a
      // Add your own custom-ROM AVB public-key digests here.
    ]);

    const bootKey = (data.verified_boot_key || '').toLowerCase();
    // Upgrade PARTIAL → VERIFIED for custom/official GOS builds whose boot key we trust.
    // PARTIAL covers both:
    //   (a) SELF_SIGNED + locked  (custom ROM — chain_verified may be true or false)
    //   (b) VERIFIED + locked + !chain_verified  (stock ROM, unknown attestation root CA)
    // In both cases the boot key is the trust anchor. Chain failure just means the
    // attestation root CA hash isn't in our pinned set yet — see attestation_root_spki below.
    if (data.verdict === 'PARTIAL' && data.device_locked && GRAPHENEOS_BOOT_KEYS.has(bootKey)) {
      const isCustom = data.verified_boot_state === 'SELF_SIGNED';
      data = {
        ...data,
        verdict: 'VERIFIED',
        grapheneos: true,
        // Keep chain_unverified flag so the dashboard tooltip can still distinguish
        // "verified custom build" from "verified official GOS" for admin visibility.
        chain_unverified: !data.chain_verified,
      };
    }

    const integrityJson = JSON.stringify(data);
    (await db.prepare('UPDATE devices SET integrity=? WHERE id=?').run(integrityJson, deviceId));
    const status = deviceStatus.get(deviceId);
    if (status) status.integrity = data;
    persistDevState(deviceId, socket);
    io.to(`monitor:${deviceId}`).emit('integrity_status_update', { deviceId, integrity: data });
    if (!data.chain_verified && data.attestation_root_spki) {
      log('warn', `Attestation chain UNVERIFIED — unknown root SPKI: ${data.attestation_root_spki} — add to GOOGLE_ATTESTATION_ROOT_SPKI in AttestationHelper.kt`, { deviceId });
    }
    log('info', `Integrity status: verdict=${data.verdict} boot=${data.verified_boot_state || '?'} locked=${data.device_locked} chain=${data.chain_verified}${data.attestation_root_spki ? ' root=' + data.attestation_root_spki.slice(0, 16) + '…' : ''}${data.grapheneos ? ' (GrapheneOS)' : ''}`, { deviceId });

    const verdict = data.verdict;
    if (verdict === 'COMPROMISED' || verdict === 'UNVERIFIED') {
      const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
      const label = dev ? `${dev.name} • ${dev.model}` : deviceId;
      const bootState = data.verified_boot_state || 'unknown';
      const locked    = data.device_locked ? 'Locked' : 'Unlocked';
      const secLevel  = data.security_level || '?';
      const buildTags = data.build_tags     || '?';
      const msg = verdict === 'COMPROMISED'
        ? `🚨 DEVICE INTEGRITY ALERT — ${label}\nStatus: COMPROMISED\nBoot state: ${bootState}\nBootloader: ${locked}\nSecurity: ${secLevel}\nBuild: ${buildTags}`
        : `⚠️ Device Integrity Warning — ${label}\nStatus: UNVERIFIED (unlocked bootloader or no verified boot)\nBoot state: ${bootState}\nBootloader: ${locked}\nSecurity: ${secLevel}\nBuild: ${buildTags}`;
      // Security-critical → never suppressed for public accounts (exempt class); hybrid mirrors.
      notifyAdminExempt(msg, deviceId).catch(() => {});
    }
  });

  socket.on('unlock_photo', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    if (!data.base64) { log('warn', 'Dropping empty unlock photo — device-side capture failed', { deviceId, event: data.event }); return; }
    const { id: id } = (await stmts.insertMedia.get(
      deviceId, data.event || 'unlock_unknown', encryptText(data.base64), Date.now()
    ));
    // Cap stored unlock photos at the display limit — delete anything older than the
    // RETAIN_UNLOCK_PHOTOS most recent so they don't accumulate beyond what's shown.
    try {
      const cut = (await db.prepare(
        "SELECT timestamp FROM media WHERE device_id=? AND type IN ('unlock_success','unlock_fail') ORDER BY timestamp DESC LIMIT 1 OFFSET ?"
      ).get(deviceId, RETAIN_UNLOCK_PHOTOS - 1));
      if (cut) (await db.prepare(
        "DELETE FROM media WHERE device_id=? AND type IN ('unlock_success','unlock_fail') AND timestamp < ?"
      ).run(deviceId, cut.timestamp));
    } catch (e) { log('warn', 'unlock-photo trim failed', { deviceId, error: e.message }); }
    io.to(`monitor:${deviceId}`).emit('media_received', { deviceId, type: 'unlock_photo', event: data.event, id, timestamp: Date.now() });
    log('info', 'Unlock photo received', { deviceId, event: data.event, mediaId: id });
  });

  socket.on('permission_lock_result', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('permission_lock_result', { deviceId, ...data });
    log('info', 'Permission lock result', { deviceId, success: data.success, failed: data.failed });
  });

  socket.on('app_permissions_result', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('app_permissions_result', { deviceId, ...data });
  });

  socket.on('install_filter_result', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('install_filter_result', { deviceId, ...data });
  });

  socket.on('uninstall_blocked_result', async data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('uninstall_blocked_result', { deviceId, ...data });
    if (SIGNAL_SENDER && data.package && data.blocked) {
      const dev   = decryptDevice((await stmts.getDevice.get(deviceId)));
      const label = dev ? `${dev.name}  •  ${dev.model}` : deviceId;
      notifyAdminForDevice(`🔒 Uninstall Protected\nDevice: ${label}\nPackage: ${data.package}`, deviceId);
    }
  });

  socket.on('clear_app_data_result', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('clear_app_data_result', { deviceId, ...data });
    log('info', `Clear app data result: ${data.success ? 'ok' : 'fail'} pkg=${data.package || '?'}`, { deviceId });
  });

  socket.on('uninstall_result', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('uninstall_result', { deviceId, ...data });
    log('info', `Uninstall result: ${data.success ? 'ok' : 'fail'} pkg=${data.package || '?'}`, { deviceId });
  });

  socket.on('wifi_connect_result', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('wifi_connect_result', { deviceId, ...data });
    log('info', `WiFi connect result: ${data.success ? 'ok' : 'fail'} ssid=${data.ssid || '?'} portal=${!!data.captivePortal}`, { deviceId });
  });

  socket.on('captive_portal_result', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('captive_portal_result', { deviceId, ...data });
    log('info', `Captive portal result: ${data.success ? 'ok' : 'fail'} http=${data.httpCode || '?'}`, { deviceId });
  });

  socket.on('captive_portal_bypassed', () => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('captive_portal_bypassed', { deviceId });
  });

  socket.on('status_event', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    try {
      const type = data.type || 'unknown';
      (await stmts.insertStatusEvent.run(deviceId, type, encryptText(JSON.stringify(data)), Date.now()));
      // Keep last 1000 per device
      (await db.prepare(`DELETE FROM device_status_events WHERE device_id=? AND id NOT IN
        (SELECT id FROM device_status_events WHERE device_id=? ORDER BY timestamp DESC LIMIT 1000)`)
        .run(deviceId, deviceId));
      io.to(`monitor:${deviceId}`).emit('status_event_update', { deviceId, event: data, timestamp: Date.now() });
      log('info', 'Status event', { deviceId, type, pkg: data.package });

      if (SIGNAL_SENDER && (type === 'app_installed' || type === 'app_removed' || type === 'app_updated' || type === 'install_blocked')) {
        const dev   = decryptDevice((await stmts.getDevice.get(deviceId)));
        const label = dev ? `${dev.name}  •  ${dev.model}` : deviceId;
        const appName = data.name ? `${data.name} (${data.package})` : data.package;
        let msg;
        if (type === 'app_installed') {
          const perms = Array.isArray(data.grantedPermissions) && data.grantedPermissions.length
            ? '\nPermissions: ' + data.grantedPermissions.map(p => p.replace('android.permission.', '')).join(', ')
            : '';
          const ver = data.version ? `\nVersion: ${data.version}` : '';
          msg = `📦 App Installed\nDevice: ${label}\nApp: ${appName}${ver}${perms}`;
        } else if (type === 'app_removed') {
          msg = `🗑️ App Removed\nDevice: ${label}\nPackage: ${data.package}`;
        } else if (type === 'app_updated') {
          const ver = data.version ? `\nVersion: ${data.version}` : '';
          msg = `🔄 App Updated\nDevice: ${label}\nApp: ${appName}${ver}`;
        } else if (type === 'install_blocked') {
          const modeLabel = data.filter_mode === 'whitelist' ? 'not on whitelist' : 'blacklisted';
          msg = `🚫 Install Blocked\nDevice: ${label}\nPackage: ${data.package}\nReason: ${modeLabel}`;
        }
        if (msg) notifyAdminForDevice(msg.slice(0, 4000), deviceId);
      }
    } catch (e) { log('error', 'status_event error', { error: e.message }); }
  });

  socket.on('stream_alert', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    const active = (data && data.active) ? data.active : 'stream';
    // Logged only — the 60s Signal ping was removed 2026-08-21 (alert fatigue); the
    // agent still emits stream_alert for the in-dashboard live indicator and for logs,
    // but operators no longer get a Signal message every minute while a session is up.
    log('info', 'Stream alert', { deviceId, active });
  });

  socket.on('keylog_data', async data => {
    if (!socket.isDevice || !deviceId) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    const entries = data?.entries;
    if (!Array.isArray(entries) || !entries.length) return;
    const encrypted = encryptText(JSON.stringify(entries));
    (await stmts.insertKeylog.run(deviceId, encrypted, Date.now()));
    io.to(`monitor:${deviceId}`).emit('keylog_update', { deviceId, entries });
  });

  // Pull-based screen text snapshots from ScreenTextHelper (system/root agent)
  socket.on('screen_text_data', async data => {
    if (!socket.isDevice || !deviceId) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    try {
      const { pkg = '', texts = [], ts = Date.now() } = data;
      if (!Array.isArray(texts) || !texts.length) return;
      const payload = { pkg, texts, ts };
      const encrypted = encryptText(JSON.stringify(payload));
      (await stmts.insertScreenText.run(deviceId, pkg, encrypted, ts));
      io.to(`monitor:${deviceId}`).emit('screen_text_update', { deviceId, pkg, texts, ts });
    } catch (e) { log('error', 'screen_text_data error', { error: e.message }); }
  });

  // ── Scheduled screen-text analysis (agent-initiated; server-store source) ──
  // The AGENT fires this at the device-local scheduled time (deep-sleep wake included).
  // For NON-ZK devices the server pulls the day's screen text from its OWN stored
  // screen_text_entries (the authoritative record) via an incremental lastAnalyzedTs
  // cursor — the agent's in-memory buffer is no longer the data source, so an empty
  // buffer can never produce a missed report. For ZK devices the agent's plaintext
  // `logs` payload is the only legal source (server drops screen_text_data at ingest).
  // Gated on: (1) schedule enabled, (2) same rate limits as manual Ask AI, (3) daily cap
  // for public users. Plaintext is NEVER stored — processed in-memory only.
  socket.on('scheduled_screentext_analysis', async data => {
    if (!socket.isDevice || !deviceId) return;
    const sched = await getScreentextSchedule(deviceId);
    if (!sched.enabled) { log('warn', 'scheduled_screentext_analysis: schedule not enabled', { deviceId }); return; }
    if (!opencodeApiKey()) { log('warn', 'scheduled_screentext_analysis: no OpenCode key', { deviceId }); return; }

    if (socket.ownerIsPublicUser) {
      // ZK device: plaintext exists only on the agent (before on-device ZK encryption) and the
      // server drops screen_text_data at ingest for ZK devices, so the agent's logs payload is
      // the ONLY legal source. The agent fires this even when its buffer is empty; an empty day
      // just produces no report (the server has nothing it can analyze).
      const { logs } = data || {};
      if (typeof logs !== 'string' || logs.length < 100) {
        log('warn', 'scheduled_screentext_analysis: empty or too-short logs (ZK)', { deviceId });
        return;
      }
      await runScreentextAnalysis(deviceId, logs, { entryCount: 0, fromTs: null, toTs: null });
      return;
    }

    // Non-ZK: analyze the SERVER's authoritative stored screen text for the window since the
    // last successful analysis (lastAnalyzedTs cursor). This is what makes the report complete —
    // it no longer depends on the agent's volatile in-memory buffer, so a day's data is never
    // missed just because the buffer was empty/capped/lost at fire time.
    const sinceTs = sched.lastAnalyzedTs ?? startOfTodayUtcTs();
    const rows = (await stmts.listScreenTextSince.all(deviceId, sinceTs, ALL_ROWS));
    if (!rows.length) {
      log('info', 'scheduled_screentext_analysis: no new screen text since last analysis', { deviceId });
      return;
    }
    // Record the device-local UTC offset so report timestamps render in the device's timezone.
    // Only persisted when the agent reports a finite value (always passes its current offset).
    const tzIn = Number(data?.tzOffsetMinutes);
    if (Number.isFinite(tzIn) && Math.round(tzIn) !== sched.timeZoneOffsetMinutes) {
      sched.timeZoneOffsetMinutes = Math.max(-840, Math.min(840, Math.round(tzIn)));
      await setScreentextSchedule(deviceId, {
        enabled: sched.enabled, hour: sched.hour, minute: sched.minute || 0,
        timeZoneOffsetMinutes: sched.timeZoneOffsetMinutes,
      });
    }
    const logText = buildScreentextLogFromRows(rows, sched.timeZoneOffsetMinutes);
    if (logText.length < 100) {
      log('info', 'scheduled_screentext_analysis: stored screen text too short to analyze', { deviceId, rows: rows.length });
      return;
    }
    await runScreentextAnalysis(deviceId, logText, {
      entryCount: rows.length,
      fromTs: rows[0].timestamp,
      toTs: rows[rows.length - 1].timestamp,
    });
  });

  socket.on('geofence_list', data => {
    if (!socket.isDevice || !deviceId) return;
    const fences = Array.isArray(data?.geofences) ? data.geofences : [];
    kv.setJSON('geofences:' + deviceId, fences, 30 * 24 * 60 * 60).catch(() => {});
    io.to(`monitor:${deviceId}`).emit('geofence_list', { deviceId, geofences: fences });
  });

  // Defensive rogue-AP / evil-twin alert from the agent. The agent sends ONE event per finding
  // (folding in any defense action). For NON-ZK devices it includes full detail (findings[] +
  // connected_ssid); for ZK devices it stays coarse (type/severity/count) — and even if a stale/rogue
  // agent sent detail for a ZK device, we strip it here so SSID/BSSID never reaches admin Signal.
  socket.on('rogue_ap_alert', async data => {
    if (!socket.isDevice || !deviceId) return;
    const type     = String(data?.type || 'rogue_ap');
    const sev      = String(data?.severity || 'high');
    const count    = Number(data?.count || 1);
    const defended = !!data?.defended;
    let findings      = Array.isArray(data?.findings) ? data.findings : [];
    let connectedSsid = typeof data?.connected_ssid === 'string' ? data.connected_ssid : '';
    if (socket.ownerIsPublicUser) { findings = []; connectedSsid = ''; }  // ZK: never forward SSID/BSSID to admin

    io.to(`monitor:${deviceId}`).emit('rogue_ap_alert', { deviceId, type, severity: sev, count, defended, at: Date.now() });

    const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
    const label = dev ? `${dev.name}  •  ${dev.model}` : deviceId;
    const emoji = sev === 'critical' ? '🔴' : sev === 'high' ? '🟠' : '🟡';
    const human = ({
      evil_twin_downgrade:  'Evil-twin AP (security downgrade)',
      untrusted_bssid:      'Unknown AP impersonating a watched SSID',
      deauth_suspected:     'Possible deauth / disassociation flood',
      wifi_dropped_defense: 'WiFi disabled — rogue network nearby, now on cellular',  // legacy agents (<2.8.9.0)
    })[type] || type;
    log('warn', 'Rogue AP alert', { deviceId, type, severity: sev, count, defended, detailed: findings.length > 0 });

    // "<bssid> (ch N, -NN dBm, SEC)" — only the fields the scan actually carried.
    const apStr = ap => {
      const meta = [];
      if (Number.isFinite(ap?.channel) && ap.channel > 0) meta.push(`ch ${ap.channel}`);
      if (Number.isFinite(ap?.rssi)) meta.push(`${ap.rssi} dBm`);
      if (ap?.security) meta.push(String(ap.security));
      return `${ap?.bssid || '??'}${meta.length ? ` (${meta.join(', ')})` : ''}`;
    };

    const lines = [`${emoji} Rogue WiFi detected`, `Device: ${label}`];
    if (findings.length) {
      const fLabel = { evil_twin_downgrade: 'Evil-twin / security downgrade', untrusted_bssid: 'Untrusted AP on a watched SSID' };
      for (const f of findings) {
        const fSev = String(f?.severity || sev).toUpperCase();
        lines.push('', `⚠️ ${fLabel[String(f?.type)] || human} — ${fSev}`);
        if (f?.ssid) lines.push(`SSID: "${f.ssid}"${f?.connected ? ' (currently connected)' : ''}`);
        if (f?.type === 'evil_twin_downgrade') {
          if (f?.secured_as) lines.push(`Broadcast as BOTH Open and ${f.secured_as} by different APs`);
          (Array.isArray(f?.open_aps) ? f.open_aps : []).forEach(ap => lines.push(`  • Open AP:    ${apStr(ap)}`));
          (Array.isArray(f?.secured_aps) ? f.secured_aps : []).forEach(ap => lines.push(`  • Secured AP: ${apStr(ap)}`));
        } else if (f?.type === 'untrusted_bssid') {
          (Array.isArray(f?.impostor_aps) ? f.impostor_aps : []).forEach(ap => lines.push(`  • Impostor:   ${apStr(ap)}`));
        } else if (f?.detail) {
          lines.push(String(f.detail));
        }
      }
    } else {
      lines.push(`${human}${count > 1 ? ` ×${count}` : ''} — ${sev.toUpperCase()}`);
    }
    if (defended) lines.push('', '↳ Action: WiFi disabled — now on cellular (~10 min), then re-checks the area');
    if (!findings.length) lines.push(socket.ownerIsPublicUser
      ? "(detail is end-to-end encrypted — in the owner's dashboard → Network)"
      : '(open the dashboard → Network for full SSID/BSSID detail)');

    notifyAdminForDevice(lines.join('\n'), deviceId);
  });

  // ── Bluetooth device scan results ─────────────────────────────────────────────
  socket.on('bt_device_event', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    // ZK-owned devices MUST deliver private scan data via the encrypted zk_data path, not
    // this named plaintext event — drop it here (defense-in-depth, mirrors location etc.).
    if (socket.ownerIsPublicUser) return;
    // Bound the payload: cap device count so a buggy/compromised device can't balloon
    // device_telemetry, RAM, or the live monitor broadcast.
    const raw = Array.isArray(data?.devices) ? data.devices : [];
    const bounded = raw.slice(0, 500);
    const ts = Date.now();

    // Apply the owner's safelist BEFORE relaying/persisting/alerting so "marked safe" trackers
    // stop appearing as threats (nearby list keeps them, tagged isSafe).
    let devices = bounded;
    try {
      const safelist = await getBtSafelist(deviceId);
      const safeSet = new Set(safelist.map(x => String(x.address).toUpperCase()));
      if (safeSet.size) devices = applyBtSafelist(bounded, safeSet);
    } catch (e) { log('warn', 'bt safelist apply failed', { deviceId, error: e.message }); }
    const trackerCount = devices.filter(d => d && d.isTracker).slice(0, 50).length;
    const count = devices.length;

    // Relay to live browser monitors
    io.to(`monitor:${deviceId}`).emit('bt_device_event', { deviceId, devices, count, trackerCount, ts });

    // Persist latest scan snapshot for REST read-back (overwrite, no history)
    try {
      await db.prepare(`INSERT INTO device_telemetry (device_id, bt_devices, bt_scan_ts, updated_at)
        VALUES (?,?,?,?)
        ON CONFLICT(device_id) DO UPDATE SET bt_devices=excluded.bt_devices,
          bt_scan_ts=excluded.bt_scan_ts, updated_at=excluded.updated_at`)
        .run(deviceId, JSON.stringify(devices), ts, ts);
    } catch (e) { log('warn', 'bt_device_event persist failed', { deviceId, error: e.message }); }
    // Accumulate scan history (like network_events for cells) so we have a BT fingerprint trail.
    try {
      await stmts.insertBtEvent.run(deviceId, JSON.stringify(devices), ts);
      // Auto-purge: every 100 inserts, drop rows older than 30 days (like the rest
      // of telemetry — BT fingerprint memory matches the WiFi snapshot memory).
      if (++_btEventInsertCount % 100 === 0) {
        const cutoff30d = Date.now() - 30 * 24 * 60 * 60 * 1000;
        await db.prepare('DELETE FROM bt_events WHERE timestamp < ?').run(cutoff30d);
      }
    } catch (e) { log('warn', 'bt_events insert failed', { deviceId, error: e.message }); }
  });

  // ── Bluetooth scanner ON/OFF state ───────────────────────────────────────────
  // Control-plane (not sensitive content), so accept from BOTH admin and ZK-owned devices so the
  // WebUI can reflect the real device-side scanning state regardless of ownership model.
  socket.on('bt_scan_state', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    const scanning = !!data?.scanning;
    const ts = Date.now();
    const existing = deviceStatus.get(deviceId) || {};
    deviceStatus.set(deviceId, { ...existing, btScanState: scanning, btScanStateTs: ts });
    // Live relay → browser monitors
    io.to(`monitor:${deviceId}`).emit('bt_scan_state', { deviceId, scanning, ts });
    // Persist for REST read-back (survives server restart / replica lookup)
    try {
      await db.prepare(`INSERT INTO device_telemetry (device_id, bt_scan_state, updated_at)
        VALUES (?,?,?)
        ON CONFLICT(device_id) DO UPDATE SET bt_scan_state=excluded.bt_scan_state,
          updated_at=excluded.updated_at`)
        .run(deviceId, scanning, ts);
    } catch (e) { log('warn', 'bt_scan_state persist failed', { deviceId, error: e.message }); }
  });

  socket.on('tracker_detection', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    // Same ZK guard as above — trackers are private data for ZK-owned devices.
    if (socket.ownerIsPublicUser) return;
    const raw = Array.isArray(data?.trackers) ? data.trackers : [];
    if (!raw.length) return;
    // Drop trackers the owner marked "safe" (they still appear in the nearby list, just not as threats).
    let trackers = raw.slice(0, 50);
    try {
      const safelist = await getBtSafelist(deviceId);
      const safeSet = new Set(safelist.map(x => String(x.address).toUpperCase()));
      if (safeSet.size) trackers = trackers.filter(t => !(t && t.address && safeSet.has(String(t.address).toUpperCase())));
    } catch (e) { log('warn', 'tracker safelist filter failed', { deviceId, error: e.message }); }
    if (!trackers.length) return;
    const count = trackers.length;
    const ts = Date.now();

    // Out-of-band notification gate: close-range (RSSI ≥ -75 dBm) + persistent (≥2 sightings)
    // + per-identity dedup (once per encounter, re-alert only after ≥24h absence) + a
    // per-device hourly cap. Computed BEFORE the relay so the client can know whether THIS
    // cycle is a genuine alert — the WebUI then only fires its loud banner/chime/browser
    // notification when notify=true (otherwise the banner would re-fire every ~15s cycle
    // because the close-range device SET keeps changing as devices drift in/out of -75 dBm).
    const close = trackers.filter(t => Number.isFinite(t.rssi) && t.rssi >= TRACKER_ALERT_MIN_RSSI);
    // MUST await — trackerAlertNeeded is async (Redis-backed). Without await, shouldNotify is a
    // Promise (always truthy) and the alert gate NEVER engages — every cycle would alert,
    // bypassing the RSSI floor, persistence check, per-identity dedup AND the hourly cap.
    // This single missing await is what caused the "spammed after every restart" bursts.
    const shouldNotify = await trackerAlertNeeded(deviceId, close);

    // Relay to live browser monitors (updates the WebUI tracker panel + count every cycle).
    // notify=true only on cycles that pass the alert policy — the panel stays red every
    // cycle regardless.
    io.to(`monitor:${deviceId}`).emit('tracker_detection', { deviceId, trackers, count, ts, notify: shouldNotify });

    // Alert admin/owner
    const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
    const label = dev ? `${dev.name}  •  ${dev.model}` : deviceId;
    // The alert message reflects the CLOSE-RANGE set only — distant ambient devices are
    // shown in the panel but never listed in an alert.
    const alertSet = close.length ? close : trackers;
    const brands = [...new Set(alertSet.map(t => t.trackerBrand || 'Unknown'))];
    const types  = [...new Set(alertSet.map(t => t.trackerType || 'unknown'))];
    const lines = [
      `📡 Tracker Detected ×${alertSet.length}${close.length !== trackers.length ? ` (${trackers.length} nearby)` : ''}`,
      `Device: ${label}`,
      `Brand: ${brands.join(', ')}`,
      `Type: ${types.join(', ')}`,
    ];
    // List individual trackers with RSSI
    for (const t of alertSet.slice(0, 10)) {
      const name = t.name || t.address || 'Unknown';
      const rssi = Number.isFinite(t.rssi) ? `${t.rssi} dBm` : '?';
      const detail = t.trackerDetail || t.trackerType || '';
      lines.push(`  • ${name} (${rssi})${detail ? ' — ' + detail : ''}`);
    }
    if (alertSet.length > 10) lines.push(`  … and ${alertSet.length - 10} more`);
    const msg = lines.join('\n');

    log('warn', 'Tracker detected', { deviceId, count, closeCount: close.length, brands, types });

    if (!shouldNotify) return;

    // Owner: push notification to phone (FCM/web-push) + alert-center persistence (+ email/discord per their prefs)
    if (dev?.owner_user_id) {
      notifyUser(dev.owner_user_id, msg, { category: 'tracker', deviceId }).catch(() => {});
    } else {
      // No public owner — still record the alert for every admin so tracker detections
      // ALWAYS land in the All Alerts panel, not just as a transient web-push.
      try {
        const admins = (await db.prepare("SELECT id FROM users WHERE account_type='admin'").all());
        for (const a of admins) {
          await persistUserAlert(a.id, 'tracker', msg, deviceId);
        }
      } catch (e) { log('warn', 'tracker alert admin persist failed', { deviceId, error: e.message }); }
      notifyPush('tracker', `📡 Tracker Detected ×${alertSet.length}`, `${label} — ${brands.join(', ')}`, '/').catch(() => {});
    }
    // Admin channels: Signal/Discord (+ admin web-push) — notifyAdminForDevice handles Signal/Discord;
    // notifyPush covers admins' web-push/FCM (gated by their 'tracker' preference, default on).
    notifyAdminForDevice(msg, deviceId);
  });

  socket.on('geofence_alert', async data => {
    if (!socket.isDevice || !deviceId) return;
    // OSCILLATION GUARD (before history/monitor/notifications): collapse GPS-jitter
    // enter/exit flip-flops from devices running pre-anti-flap APKs — see
    // geofenceAcceptTransition(). Suppressed flaps are dropped entirely.
    if (!(await geofenceAcceptTransition(deviceId, data.geofenceId || data.name, data.transition))) {
      log('debug', 'Geofence alert suppressed (oscillation guard)', {
        deviceId, geofenceId: data.geofenceId, transition: data.transition,
      });
      return;
    }
    const alert = { ...data, receivedAt: Date.now() };
    const history = (await kv.getJSON('geoalerts:' + deviceId)) || [];
    history.unshift(alert);
    if (history.length > 50) history.length = 50;
    kv.setJSON('geoalerts:' + deviceId, history, 30 * 24 * 60 * 60).catch(() => {});
    io.to(`monitor:${deviceId}`).emit('geofence_alert', { deviceId, alert });
    const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
    const label = dev ? `${dev.name}  •  ${dev.model}` : deviceId;
    const transition = (data.transition || 'unknown').toUpperCase();
    log('info', 'Geofence alert', { deviceId, geofenceId: data.geofenceId, name: data.name, transition });
    // Node-RED → HASS spoken TTS (Pixel 9a etc.) — own 10-min cooldown per (fence, transition).
    notifyGeofenceNodeRed(deviceId, data, label).catch(() => {});
    // NOTIFICATION GATE: history + live monitor above record every transition (panel/map stay
    // accurate), but out-of-band alerts are cooldown-gated per (fence, transition) so boundary
    // enter/exit flip-flop can't spam push / All Alerts / Signal.
    if (!(await geofenceAlertDue(deviceId, data.geofenceId, data.transition))) return;
    if (SIGNAL_SENDER) {
      const emoji = data.transition === 'enter' ? '📍' : data.transition === 'exit' ? '🚪' : '🕐';
      notifyAdminForDevice(`${emoji} Geofence ${transition}\nDevice: ${label}\nFence: ${data.name || data.geofenceId}`, deviceId);
    }
    // Push notification
    try {
      const dev = (await stmts.getDevice.get(deviceId));
      const emoji = data.transition === 'enter' ? '📍' : '🚪';
      const title = `${emoji} Geofence ${transition}`;
      const body  = `${label} — ${data.name || data.geofenceId}`;
      if (dev?.owner_user_id) {
        notifyUser(dev.owner_user_id, `${title}\n${body}`, { category: 'geofence', deviceId }).catch(()=>{});
      } else (await notifyPush('geofence', title, body, '/'));
    } catch {}
  });

  socket.on('theft_mode_timeout', async data => {
    if (!socket.isDevice || !deviceId) return;
    (await db.prepare('UPDATE devices SET theft_mode=0 WHERE id=?').run(deviceId));
    io.emit('devices_updated');
    const device = decryptDevice((await stmts.getDevice.get(deviceId)));
    const deviceLabel = device ? `${device.name} • ${device.model}` : deviceId;
    const batteryStop = data?.reason === 'battery_low';
    stopTheftModeAlerts(deviceId, deviceLabel, batteryStop ? `battery low (${data?.battery ?? '?'}%)` : 'auto-timeout (30 min)');
    io.to(`monitor:${deviceId}`).emit('theft_mode_auto_stopped', { deviceId, reason: data?.reason || 'auto_timeout', battery: data?.battery ?? null });
    log('warn', 'Theft mode auto-stop on device', { deviceId, reason: data?.reason || 'auto_timeout' });
  });

  // Device signals live tracking stopped (auto-timeout or manual stop from device side)
  socket.on('live_track_stopped', () => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('live_track_stopped', { deviceId });
  });

  // ── New feature socket events ────────────────────────────────────────────

  socket.on('notification_event', async data => {
    if (!socket.isDevice || !deviceId) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    try {
      const { pkg='', title='', text='', ts=Date.now() } = data;
      (await db.prepare('INSERT INTO notifications (device_id,pkg,title,text,timestamp) VALUES (?,?,?,?,?)')
        .run(deviceId, pkg, encryptText(title), encryptText(text), ts));
      (await db.prepare('DELETE FROM notifications WHERE device_id=? AND id NOT IN (SELECT id FROM notifications WHERE device_id=? ORDER BY timestamp DESC LIMIT 2000)')
        .run(deviceId, deviceId));
      io.to(`monitor:${deviceId}`).emit('notification_update', { deviceId, pkg, title, text, ts });
    } catch (e) { log('error', 'notification_event error', { error: e.message }); }
  });

  socket.on('clipboard_event', async data => {
    if (!socket.isDevice || !deviceId) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    try {
      const { text='', ts=Date.now() } = data;
      if (!text) return;
      (await db.prepare('INSERT INTO clipboard_events (device_id,content,timestamp) VALUES (?,?,?)')
        .run(deviceId, encryptText(text), ts));
      (await db.prepare('DELETE FROM clipboard_events WHERE device_id=? AND id NOT IN (SELECT id FROM clipboard_events WHERE device_id=? ORDER BY timestamp DESC LIMIT 500)')
        .run(deviceId, deviceId));
      io.to(`monitor:${deviceId}`).emit('clipboard_update', { deviceId, text, ts });
    } catch (e) { log('error', 'clipboard_event error', { error: e.message }); }
  });

  socket.on('contacts_data', async data => {
    if (!socket.isDevice || !deviceId) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    try {
      (await db.prepare('INSERT INTO contacts (device_id,data,timestamp) VALUES (?,?,?)')
        .run(deviceId, encryptText(JSON.stringify(data.contacts || [])), Date.now()));
      (await db.prepare('DELETE FROM contacts WHERE device_id=? AND id NOT IN (SELECT id FROM contacts WHERE device_id=? ORDER BY timestamp DESC LIMIT 5)')
        .run(deviceId, deviceId));
      io.to(`monitor:${deviceId}`).emit('contacts_update', { deviceId, contacts: data.contacts });
    } catch (e) { log('error', 'contacts_data error', { error: e.message }); }
  });

  socket.on('calendar_data', async data => {
    if (!socket.isDevice || !deviceId) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    try {
      (await db.prepare('INSERT INTO calendar_events (device_id,data,timestamp) VALUES (?,?,?)')
        .run(deviceId, encryptText(JSON.stringify(data.events || [])), Date.now()));
      (await db.prepare('DELETE FROM calendar_events WHERE device_id=? AND id NOT IN (SELECT id FROM calendar_events WHERE device_id=? ORDER BY timestamp DESC LIMIT 5)')
        .run(deviceId, deviceId));
      io.to(`monitor:${deviceId}`).emit('calendar_update', { deviceId, events: data.events });
    } catch (e) { log('error', 'calendar_data error', { error: e.message }); }
  });


  socket.on('usage_stats_data', async data => {
    if (!socket.isDevice || !deviceId) return;
    // ZK device: private data must arrive via the encrypted zk_data path — drop plaintext (defense-in-depth).
    if (socket.ownerIsPublicUser) return;
    try {
      (await db.prepare('INSERT INTO usage_stats (device_id,data,timestamp) VALUES (?,?,?)')
        .run(deviceId, JSON.stringify(data.stats || []), Date.now()));
      (await db.prepare('DELETE FROM usage_stats WHERE device_id=? AND id NOT IN (SELECT id FROM usage_stats WHERE device_id=? ORDER BY timestamp DESC LIMIT 5)')
        .run(deviceId, deviceId));
      io.to(`monitor:${deviceId}`).emit('usage_stats_update', { deviceId, stats: data.stats });
    } catch (e) { log('error', 'usage_stats_data error', { error: e.message }); }
  });

  socket.on('shell_output', async data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('shell_output', { deviceId, ...data });
    // Persist chunks for HTTP polling (sentinel-adb CLI) — matches the session row
    // opened at dispatch by sessionId marker. Capped per session; exit marker kept.
    try {
      const sid = data.sessionId || '';
      if (!sid) return;
      if (data.stream === 'stdout' || data.stream === 'stderr') {
        const line = String(data.line || '');
        if (!line) return;
        await db.prepare(`UPDATE shell_sessions SET output = output || ? WHERE device_id=? AND command LIKE ? AND length(output) < 200000`)
          .run(line + '\n', deviceId, `%${sid}%`);
      }
    } catch (_) {}
    // Accumulate output for session log (store on exit)
    if (data.stream === 'exit') {
      try {
        const sid = data.sessionId || '';
        (await db.prepare('UPDATE shell_sessions SET output=output||? WHERE device_id=? AND command LIKE ?')
          .run(`\n[exit:${data.exitCode}]`, deviceId, `%${sid}%`));
      } catch (_) {}
    }
  });

  socket.on('logcat_line', data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('logcat_line', { deviceId, ...data });
  });

  socket.on('app_foreground', async data => {
    if (!socket.isDevice || !deviceId) return;
    io.to(`monitor:${deviceId}`).emit('app_foreground', { deviceId, ...data });
    // Check watched apps for alerts
    if (data.watched) {
      const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
      const label = dev ? `${dev.name} • ${dev.model}` : deviceId;
      notifyAdminForDevice(`📱 Watched App Opened\nDevice: ${label}\nApp: ${data.pkg}`, deviceId);
    }
  });

  socket.on('sms_sent', async data => {
    if (!socket.isDevice || !deviceId) return;
    try {
      (await db.prepare('INSERT INTO sms_outbox (device_id,number,message,status,timestamp) VALUES (?,?,?,?,?)')
        .run(deviceId, data.number || '', data.message || '', data.error ? 'error' : 'sent', Date.now()));
    } catch (_) {}
    io.to(`monitor:${deviceId}`).emit('sms_sent_result', { deviceId, ...data });
  });

  socket.on('network_logs', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    const events = data.events || [];
    if (!events.length) return;
    const insert = db.prepare('INSERT INTO device_network_logs (device_id,type,data,timestamp) VALUES (?,?,?,?)');
    (await db.transaction(async () => {
      for (const e of events)
        (await insert.run(deviceId, e.type || 'unknown', encryptText(JSON.stringify(e)), e.ts || Date.now()));
    })());
    const logCutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    (await db.prepare('DELETE FROM device_network_logs WHERE device_id=? AND timestamp < ?').run(deviceId, logCutoff));
    io.to(`monitor:${deviceId}`).emit('network_log_batch', { deviceId, events });
    log('debug', 'Network logs received', { deviceId, count: events.length });
  });

  socket.on('security_logs', async data => {
    if (!socket.isDevice || !deviceId || !getServerUnlocked()) return;
    const events = data.events || [];
    if (!events.length) return;
    const insert = db.prepare('INSERT INTO device_security_logs (device_id,tag,name,data,timestamp) VALUES (?,?,?,?,?)');
    (await db.transaction(async () => {
      for (const e of events)
        (await insert.run(deviceId, e.tag || 0, e.name || '', encryptText(String(e.data || '')), e.ts || Date.now()));
    })());
    const logCutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    (await db.prepare('DELETE FROM device_security_logs WHERE device_id=? AND timestamp < ?').run(deviceId, logCutoff));
    io.to(`monitor:${deviceId}`).emit('security_log_batch', { deviceId, events });
    log('debug', 'Security logs received', { deviceId, count: events.length });
  });

  socket.on('disconnect', async reason => {
    // Clean up any in-progress chunked transfers for this device
    for (const [key, state] of fileChunkBuffers) {
      if (key.startsWith(`${deviceId}:`)) {
        clearTimeout(state.timer);
        fileChunkBuffers.delete(key);
      }
    }
    if (!deviceId) {
      // Monitor disconnect — wait a GRACE PERIOD before auto-stopping the device's stream/live-track,
      // so a transient WebSocket reconnect (LB / sticky-session churn across the 3 replicas) doesn't
      // kill an active session on every blip. After the grace, re-check the room ACROSS replicas
      // (fetchSockets() is cross-replica; allSockets()/adapter.rooms are LOCAL-only with the redis
      // adapter) and only stop if NO monitor/tracker has (re)appeared.
      const GRACE_MS = 15000;
      if (socket.isMonitor && socket.monitoredDevices.size) {
        for (const did of socket.monitoredDevices) {
          setTimeout(async () => {
            try {
              const watchers = await io.in(`monitor:${did}`).fetchSockets();
              if (watchers.length === 0) {
                // No one is watching this device anymore — stop ALL live streams (camera,
                // screen, audio) and clear their surveillance state so alerts stop too.
                for (const [cmd, type] of [['stop_audio_stream', 'audio'], ['stop_stream', 'camera'], ['stop_screen_stream', 'screen']]) {
                  emitToDevice(did, 'command', { command: cmd });
                  surveilStop(did, type).catch(() => {});
                }
                log('info', 'No monitor after grace — auto-stopped live streams', { deviceId: did });
              }
            } catch (_) {}
          }, GRACE_MS);
        }
      }
      if (socket.isMonitor && socket.liveTrackingDevice) {
        const did = socket.liveTrackingDevice;
        setTimeout(async () => {
          try {
            const trackers = await io.in(`livetrack:${did}`).fetchSockets();
            if (trackers.length === 0) {
              emitToDevice(did, 'command', { command: 'stop_live_track' });
              surveilStop(did, 'gps').catch(() => {});
              log('info', 'No live-tracker after grace — auto-stopped live tracking', { deviceId: did });
            }
          } catch (_) {}
        }, GRACE_MS);
      }
      log('debug', 'Unregistered socket disconnected', { socketId: socket.id, reason });
      return;
    }
    if (connectedSockets.get(deviceId) === socket) {
      connectedSockets.delete(deviceId);
      encryptedDevices.delete(deviceId);
      // Defer the offline-mark + owner/admin alert behind a grace window so a brief control-channel
      // flap (idle-disconnect on hostile guest WiFi during light sleep) that reconnects within the
      // grace never churns the dashboard or spams the owner with offline push/email. A reconnect
      // (this replica's register path, or a peer via `device-registered`) cancels it; only a device
      // that stays gone past the grace actually goes offline. See scheduleOfflineGrace.
      scheduleOfflineGrace(deviceId, reason);
      log('info', 'Device disconnected (offline grace pending)', { deviceId, reason, totalOnline: connectedSockets.size });
    } else {
      log('debug', 'Stale socket disconnected (device already reconnected)', { deviceId, reason });
    }
  });
});
};
