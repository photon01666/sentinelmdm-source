// services/surveillance.js — Live-monitoring (surveillance) alerts + 10-minute hard cap.
// Factory pattern: initialized with dependencies.

module.exports = function createSurveillanceService({ db, log, decryptText, kv, state, config, notification }) {
  const { SURVEIL_MAX_MS } = state; // (SURVEIL_ALERT_MS retired with the recurring pulse)

  const SURVEIL_START_CMDS = { start_stream: 'camera', start_audio_stream: 'audio', start_screen_stream: 'screen', start_live_track: 'gps' };
  const SURVEIL_STOP_CMDS  = { stop_stream:  'camera', stop_audio_stream:  'audio', stop_screen_stream:  'screen', stop_live_track:  'gps' };
  const SURVEIL_STOP_CMD_FOR = { camera: 'stop_stream', audio: 'stop_audio_stream', screen: 'stop_screen_stream', gps: 'stop_live_track' };
  const SURVEIL_LABEL = { camera: '📹 Live camera stream', audio: '🎙️ Live audio stream', screen: '🖥️ Live screen stream', gps: '📡 Live GPS tracking' };

  function surveilNotify(cur, line) {
    // (the old opts.recurring/public-owner suppression died with the 60s pulse — every
    //  remaining call site is an activation or cap-stop event, all of which should send)
    const msg = `🔴 Monitoring Alert\nDevice: ${cur.deviceName || cur.deviceId}\nTime: ${new Date().toLocaleTimeString()}\n\n${line}`;
    if (cur.ownerType === 'public' && cur.ownerUserId) return notification.notifyUser(cur.ownerUserId, msg, { force: true });
    return notification.notifyAdmin(msg);
  }

  async function surveilStart(deviceId, type) {
    try {
      const row = (await db.prepare(
        'SELECT u.id AS uid, u.account_type, d.name FROM devices d LEFT JOIN users u ON d.owner_user_id=u.id WHERE d.id=?'
      ).get(deviceId));
      const cur = (await kv.getJSON(`surveil:${deviceId}`)) || { types: {}, lastAlertAt: 0 };
      const wasActive = !!cur.types[type];
      if (!wasActive) { cur.types[type] = Date.now(); cur.lastAlertAt = Date.now(); }
      cur.deviceId      = deviceId;
      cur.ownerUserId   = row?.uid ?? null;
      cur.ownerType     = row?.account_type ?? null;
      cur.deviceName    = row?.name ? (decryptText(row.name) || deviceId) : deviceId;
      await kv.setJSON(`surveil:${deviceId}`, cur);
      await kv.sadd('surveil:active', deviceId);
      if (!wasActive) await surveilNotify(cur, `${SURVEIL_LABEL[type]} STARTED on your device.`);
    } catch (e) { log('warn', 'surveilStart error', { deviceId, type, error: e.message }); }
  }

  async function surveilStop(deviceId, type) {
    try {
      const cur = (await kv.getJSON(`surveil:${deviceId}`));
      if (!cur?.types?.[type]) return;
      delete cur.types[type];
      if (Object.keys(cur.types).length) { await kv.setJSON(`surveil:${deviceId}`, cur); }
      else { await kv.del(`surveil:${deviceId}`); await kv.srem('surveil:active', deviceId); }
    } catch (e) { log('warn', 'surveilStop error', { deviceId, type, error: e.message }); }
  }

  return {
    SURVEIL_START_CMDS,
    SURVEIL_STOP_CMDS,
    SURVEIL_STOP_CMD_FOR,
    SURVEIL_LABEL,
    surveilNotify,
    surveilStart,
    surveilStop,
  };
};
