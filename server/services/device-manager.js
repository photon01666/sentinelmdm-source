// services/device-manager.js — Device emit, online/offline tracking, offline grace, theft mode.
// Factory pattern: initialized with dependencies.

const { EventEmitter } = require('events');

module.exports = function createDeviceManagerService({ db, log, decryptText, kv, state, config, notification }) {
  const { connectedSockets, encryptedDevices, deviceStatus, offlineGraceTimers, DEVICE_OFFLINE_GRACE_MS, theftModeAlertTimers } = state;
  const { redisEnabled, io } = config;

  // ── App-layer encryption (AES-128-GCM via ECDH) ──────────────────────────────
  const crypto = require('crypto');
  const { SERVER_ENC_KEY_PEM } = config;
  if (SERVER_ENC_KEY_PEM) {
    try {
      state.serverEncPrivKey = crypto.createPrivateKey(SERVER_ENC_KEY_PEM);
      console.log('[INFO] App-layer encryption: server EC P-256 key loaded');
    } catch (e) {
      console.error('[ERROR] Failed to load server EC private key:', e.message);
    }
  } else {
    console.warn('[WARN] SERVER_ENC_KEY_PEM not set — new devices cannot use app-layer encryption');
  }

  function deviceEmit(socket, event, data) {
    if (socket.encKey) {
      const iv     = crypto.randomBytes(12);
      const plain  = Buffer.from(JSON.stringify({ ev: event, d: data }), 'utf8');
      const cipher = crypto.createCipheriv('aes-128-gcm', socket.encKey, iv);
      const ct     = Buffer.concat([cipher.update(plain), cipher.final()]);
      const tag    = cipher.getAuthTag();
      socket.emit('e', { d: Buffer.concat([iv, ct, tag]).toString('base64') });
    } else {
      socket.emit(event, data);
    }
  }

  function emitToDevice(deviceId, event, data) {
    const local = connectedSockets.get(deviceId);
    if (local) { deviceEmit(local, event, data); return true; }
    if (redisEnabled) io.serverSideEmit('device-emit', { deviceId, event, data });
    return false;
  }

  function markOnline(deviceId)  { kv.sadd('online_devices', deviceId).catch(() => {}); }
  function markOffline(deviceId) { kv.srem('online_devices', deviceId).catch(() => {}); }
  async function isDeviceOnline(deviceId) {
    if (connectedSockets.has(deviceId)) return true;
    try { return await kv.sismember('online_devices', deviceId); } catch { return false; }
  }

  // ── Offline grace window ─────────────────────────────────────────────────────
  function cancelOfflineGrace(deviceId) {
    const t = offlineGraceTimers.get(deviceId);
    if (t) { clearTimeout(t); offlineGraceTimers.delete(deviceId); }
  }

  // Placeholder — scheduleOfflineGrace is complex and references stmts, io, etc.
  // Will be fully wired in server.js for now.
  function scheduleOfflineGrace(deviceId, reason) {
    cancelOfflineGrace(deviceId);
    // Full implementation lives in server.js until stmts are available
  }

  // ── Cross-replica owner update ──────────────────────────────────────────────
  function updateDeviceOwner(deviceId, ownerIsPublicUser, ownerUserId, zkPubKey) {
    const local = connectedSockets.get(deviceId);
    if (local) {
      local.ownerIsPublicUser = ownerIsPublicUser;
      local.ownerUserId       = ownerUserId;
      deviceEmit(local, 'zk_pub_key', { zkPubKey });
      return true;
    }
    if (redisEnabled) io.serverSideEmit('device-owner-update', { deviceId, ownerIsPublicUser, ownerUserId, zkPubKey });
    return false;
  }

  // ── Theft mode alert timers ─────────────────────────────────────────────────
  async function startTheftModeAlerts(deviceId, deviceLabel) {
    stopTheftModeAlerts(deviceId, deviceLabel, null);
    const startedAt = Date.now();
    notification.notifyAdminForDevice(`🚨 THEFT MODE ACTIVATED\nDevice: ${deviceLabel}\nBattery drain + camera + audio loop will run continuously.\nAuto-stops in 30 minutes.`, deviceId);
    (await notification.notifyPush('theft', '🚨 Theft mode activated', `${deviceLabel} — continuous capture running.`, '/'));
    const interval = setInterval(() => {
      const elapsed = Math.round((Date.now() - startedAt) / 60000);
      const status  = deviceStatus.get(deviceId);
      const batt    = status?.battery?.level != null ? `${status.battery.level}%` : 'unknown';
      const charging = status?.battery?.charging ? ' (charging)' : '';
      notification.notifyAdminForDevice(`⚠️ THEFT MODE STILL ACTIVE — ${elapsed} min\nDevice: ${deviceLabel}\nBattery: ${batt}${charging}\nCamera + audio uploading continuously.`, deviceId);
    }, 5 * 60 * 1000);
    theftModeAlertTimers.set(deviceId, { interval, startedAt });
  }

  function stopTheftModeAlerts(deviceId, deviceLabel, reason) {
    const entry = theftModeAlertTimers.get(deviceId);
    if (!entry) return;
    clearInterval(entry.interval);
    theftModeAlertTimers.delete(deviceId);
    if (deviceLabel && reason) {
      const elapsed = Math.round((Date.now() - entry.startedAt) / 60000);
      notification.notifyAdminForDevice(`✅ THEFT MODE DEACTIVATED\nDevice: ${deviceLabel}\nReason: ${reason}\nActive for ~${elapsed} min.`, deviceId);
    }
  }

  return {
    deviceEmit,
    emitToDevice,
    markOnline,
    markOffline,
    isDeviceOnline,
    cancelOfflineGrace,
    scheduleOfflineGrace,
    updateDeviceOwner,
    startTheftModeAlerts,
    stopTheftModeAlerts,
  };
};
