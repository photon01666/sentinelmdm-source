// services/device-helpers.js — Shared helpers for demo devices, ZK payload routing.
// Phase-2 initialized (needs stmts which isn't available at bootstrap).
module.exports = function createDeviceHelpers({ db, DEMO_DEVICE_TABLES, deviceStatus, encryptText, kv, log, stmts }) {

function demoWifiCurrent() {
  return {
    enabled: true, ssid: 'Home-WiFi', bssid: '02:1A:2B:3C:4D:5E', signal_level: 4, rssi: -52,
    frequency_mhz: 5180, channel: 36, link_speed_mbps: 433, validated: true,
    ip: '192.168.1.42', ping_ms: 14, security: 'WPA2',
  };
}

function demoStatusPayload() {
  const now = Date.now();
  return {
    battery: { level: 82, charging: false, status: 'discharging', plugType: 'none' },
    motion: 'stationary',
    last_motion_ts: now - 5 * 60 * 1000,
    lightSleep: false,
    network: { connection_type: 'wifi', wifi_current: demoWifiCurrent() },
    clientIp: null,
    integrity: {
      verdict: 'VERIFIED', security_level: 'STRONG', grapheneos: true,
      verified_boot_state: 'VERIFIED', device_locked: true, build_tags: 'release-keys',
      chain_verified: true,
    },
  };
}

async function createDemoDeviceForUser(userId) {
  const deviceId = 'demo-' + userId;
  const now = Date.now();
  const lat = 30.2672, lng = -97.7431;

  const claimed = (await db.prepare(`INSERT INTO devices
      (id,name,model,android_version,battery,last_seen,last_lat,last_lng,online,platform,
       app_version,os_build,security_patch,owner_user_id,is_demo)
      VALUES (?,?,?,?,?,?,?,?,1,'android',?,?,?,?,1) ON CONFLICT DO NOTHING RETURNING id`)
    .get(deviceId, encryptText('Demo Phone (Sample Data)'), encryptText('Pixel 8'), encryptText('16'),
      82, now, encryptText(String(lat)), encryptText(String(lng)),
      '2.8.9.5', 'SentinelOS-16-QPR2', '2026-06-01', userId));
  if (!claimed) return;

  (await stmts.insertLocation.run(deviceId,
    encryptText(JSON.stringify({ lat: 30.2681, lng: -97.7449, accuracy: 11 })), now - 3 * 3600000));
  (await stmts.insertLocation.run(deviceId,
    encryptText(JSON.stringify({ lat, lng, accuracy: 14 })), now - 20 * 60000));

  (await stmts.insertNetwork.run(deviceId,
    encryptText(JSON.stringify({ connection_type: 'wifi', wifi_current: demoWifiCurrent() })), now));

  const calls = [
    { type: 'incoming', name: 'Mom', number: '+1 555-201-4477', duration: 184, date: now - 2 * 3600000 },
    { type: 'outgoing', name: 'Dad', number: '+1 555-201-9981', duration: 63, date: now - 5 * 3600000 },
    { type: 'missed', name: 'Alex (Friend)', number: '+1 555-330-2298', duration: 0, date: now - 8 * 3600000 },
    { type: 'incoming', number: '+1 555-999-0123', duration: 41, date: now - 26 * 3600000 },
  ];
  (await stmts.insertCallLog.run(deviceId, encryptText(JSON.stringify(calls)), now));

  const sms = [
    { type: 'received', address: 'Mom', body: "Dinner at 6, don't forget to feed the dog", date: now - 3600000 },
    { type: 'sent', address: 'Mom', body: 'Ok! Be home soon', date: now - 55 * 60000 },
    { type: 'received', address: 'Alex', body: 'are we still on for the movie tonight?', date: now - 3 * 3600000 },
    { type: 'sent', address: '+1 555-888-2211', body: 'Yes see you at 7', date: now - 2 * 3600000 - 50 * 60000 },
  ];
  (await stmts.insertSms.run(deviceId, encryptText(JSON.stringify(sms)), now));

  const apps = [
    { name: 'TikTok', package: 'com.zhiliaoapp.musically' },
    { name: 'Instagram', package: 'com.instagram.android' },
    { name: 'Snapchat', package: 'com.snapchat.android' },
    { name: 'YouTube', package: 'com.google.android.youtube' },
    { name: 'WhatsApp', package: 'com.whatsapp' },
    { name: 'Roblox', package: 'com.roblox.client' },
    { name: 'Discord', package: 'com.discord' },
    { name: 'Chrome', package: 'com.android.chrome' },
    { name: 'Gmail', package: 'com.google.android.gm' },
    { name: 'Spotify', package: 'com.spotify.music' },
    { name: 'Settings', package: 'com.android.settings', system: true },
    { name: 'Phone', package: 'com.google.android.dialer', system: true },
  ];
  (await stmts.insertAppList.run(deviceId, encryptText(JSON.stringify(apps)), now));

  const notifs = [
    { pkg: 'com.whatsapp', title: 'Mom', text: "Dinner at 6, don't forget to feed the dog", ts: now - 3600000 },
    { pkg: 'com.instagram.android', title: 'Instagram', text: 'alex_here liked your photo', ts: now - 2 * 3600000 },
    { pkg: 'com.google.android.gm', title: 'Gmail', text: 'Your Amazon order has shipped', ts: now - 4 * 3600000 },
    { pkg: 'com.zhiliaoapp.musically', title: 'TikTok', text: 'New videos from creators you follow', ts: now - 6 * 3600000 },
  ];
  for (const n of notifs)
    (await db.prepare('INSERT INTO notifications (device_id,pkg,title,text,timestamp) VALUES (?,?,?,?,?)')
      .run(deviceId, n.pkg, encryptText(n.title), encryptText(n.text), n.ts));

  (await kv.setJSON('battery:' + deviceId, {
    battery: { level: 82, health: 'Good', temp: 28.4, status: 'Discharging', plugged: 'Unplugged', voltage: 4012, chargeTimeRemainingMs: null },
    apps: [
      { name: 'TikTok', foregroundMs: 5400000, lastUsed: now - 30 * 60000 },
      { name: 'YouTube', foregroundMs: 3600000, lastUsed: now - 90 * 60000 },
      { name: 'Instagram', foregroundMs: 2700000, lastUsed: now - 45 * 60000 },
      { name: 'Roblox', foregroundMs: 1800000, lastUsed: now - 3 * 3600000 },
      { name: 'Chrome', foregroundMs: 900000, lastUsed: now - 5 * 3600000 },
    ],
    timestamp: now,
  }));

  const status = demoStatusPayload();
  deviceStatus.set(deviceId, status);
  (await kv.setJSON('devstate:' + deviceId,
    { status, dpi: { reality: true, transport: 'reality', realityNode: 'VA' }, encrypted: false }));

  log('info', 'Demo device seeded for public user', { userId, deviceId });
}

async function removeDemoDeviceForUser(userId) {
  const demoId = 'demo-' + userId;
  const row = (await db.prepare('SELECT id FROM devices WHERE id=? AND is_demo=1').get(demoId));
  if (!row) return;
  for (const table of DEMO_DEVICE_TABLES) (await db.prepare(`DELETE FROM ${table} WHERE device_id=?`).run(demoId));
  (await db.prepare('DELETE FROM devices WHERE id=?').run(demoId));
  deviceStatus.delete(demoId);
  (await kv.del('battery:' + demoId));
  (await kv.del('devstate:' + demoId));
  log('info', 'Demo device removed', { userId });
}

const ALL_ROWS = 1000000000;
function zkRowLimit(req) {
  const q = req.query.limit;
  if (q === 'all' || (parseInt(q, 10) || 0) < 0) return ALL_ROWS;
  return Math.min(parseInt(q, 10) || 2000, 2000);
}

async function maybeRespondWithZkPayloads(req, res, ...eventTypes) {
  const ownerRow = (await db.prepare(
    'SELECT u.account_type, d.is_demo FROM devices d LEFT JOIN users u ON d.owner_user_id=u.id WHERE d.id=?'
  ).get(req.params.id));
  if (ownerRow?.account_type !== 'public' || ownerRow?.is_demo) return false;
  const rowLimit = zkRowLimit(req);
  const before = parseInt(/** @type {any} */ (req.query.before), 10) || 0;
  const arrays = await Promise.all(eventTypes.map(et =>
    before > 0
      ? db.prepare(
          'SELECT id, event_type, payload, dek_wrapped, timestamp FROM zk_payloads WHERE device_id=? AND event_type=? AND timestamp<? ORDER BY timestamp DESC LIMIT ?'
        ).all(req.params.id, et, before, rowLimit)
      : db.prepare(
          'SELECT id, event_type, payload, dek_wrapped, timestamp FROM zk_payloads WHERE device_id=? AND event_type=? ORDER BY timestamp DESC LIMIT ?'
        ).all(req.params.id, et, rowLimit)
  ));
  const merged = arrays.flat().sort((a, b) => b.timestamp - a.timestamp);
  const rows = (req.query.limit != null) ? merged.slice(0, rowLimit) : merged;
  res.json({ zk: true, rows });
  return true;
}

// ── EDR helpers (used by routes + worker pollers) ──────────────────────────
const EDR_ALERT_SUPPRESS_MS = 30 * 60 * 1000;

async function getEdrEnabled(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('edr_enabled:' + deviceId));
  return !!row && row.value === 'enabled';
}
async function setEdrEnabled(deviceId, enabled) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('edr_enabled:' + deviceId, enabled ? 'enabled' : 'disabled'));
}
async function getEdrIsolated(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('edr_isolated:' + deviceId));
  return !!row && row.value === 'isolated';
}
async function setEdrIsolated(deviceId, isolated) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('edr_isolated:' + deviceId, isolated ? 'isolated' : 'restored'));
}
async function getEdrLastSeen(deviceId) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('edr_last_seen:' + deviceId));
  return row ? (parseFloat(row.value) || 0) : 0;
}
async function setEdrLastSeen(deviceId, ts) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('edr_last_seen:' + deviceId, String(ts)));
}
async function getEdrAlertSuppressedUntil(deviceId, rule) {
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get(`edr_alert_suppress:${deviceId}:${rule}`));
  return row ? (parseFloat(row.value) || 0) : 0;
}
async function setEdrAlertSuppressedUntil(deviceId, rule, until) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run(`edr_alert_suppress:${deviceId}:${rule}`, String(until)));
}

return {
  demoWifiCurrent, demoStatusPayload, createDemoDeviceForUser, removeDemoDeviceForUser,
  ALL_ROWS, zkRowLimit, maybeRespondWithZkPayloads,
  EDR_ALERT_SUPPRESS_MS, getEdrEnabled, setEdrEnabled, getEdrIsolated, setEdrIsolated,
  getEdrLastSeen, setEdrLastSeen, getEdrAlertSuppressedUntil, setEdrAlertSuppressedUntil,
};

};
