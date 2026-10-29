// helpers/wifi-location.js - the positioning primitives that wifi-aps-anchors-and-positioning
// (and the RF fix module) are built on.
//
// A HELPER module, not a route module: it registers nothing.
//
//   wifiAgeMs               PRIVATE  how old the OS says a scan reading is; pinned to 0 for
//                                    old agents that do not send age_ms
//   wifiReadingsFromSnapshot export   scan list + the live wifi_current AP as one list
//   anchorRefOrDefault      export   the reference location an anchor positions against
//   isRandomizedMac         export   Android privacy-scrambled addresses look randomised
//   approxDistM             export   planar distance in metres (small-angle, fine to ~few km)
//   latestDeviceLocation    export   most recent recorded fix for a device
//   locationAtTime          export   the fix nearest a given moment (post-processed history)
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// Three of the 5 deps are `function` declarations (decryptText L167, isValidRssi L7416,
// wifiRssi L7420) and so may be bound from any line; the other two, AUTO_CALIB_SNAPSHOT_ALIGN_MS
// (L7401) and db (L723), are bindings above L7426.
//
// The require must sit in L7402..L7518 -- after AUTO_CALIB_SNAPSHOT_ALIGN_MS is initialised,
// and before L7519 where filterFixPoints calls approxDistM. L7426 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ AUTO_CALIB_SNAPSHOT_ALIGN_MS, db, decryptText, isValidRssi, wifiRssi }) => {
// Every WiFi RSSI reading in a network snapshot: the scan list PLUS the associated AP.
// (wifi_current comes live from WifiInfo, not a cached scan — it's the freshest reading
// and the one most likely to be near the device, so it must vote and match too.)
// ageMs = how old the OS says THIS reading is (agent sends age_ms). Android returns a
// cached, multi-minute merged scan list while moving; without the age, every AP in it is
// attributed to wherever the phone is when the snapshot is REPORTED, which painted a
// phantom multi-km trail per fixed AP. Older agents don't send age_ms → 0 (old behaviour).
function wifiAgeMs(a) {
  const v = Number(a && a.age_ms);
  return Number.isFinite(v) && v > 0 ? Math.min(v, 60 * 60 * 1000) : 0;
}
function wifiReadingsFromSnapshot(nd) {
  const out = new Map(); // BSSID -> { rssi, name, ageMs, aged }
  try {
    for (const a of (nd.wifi_networks || [])) {
      const r = wifiRssi(a);
      const b = String(a.bssid || '').toUpperCase();
      // `aged` = the payload carried a per-AP age (agent 2.26.0.18+). Un-aged scan entries
      // cannot be attributed to a real scan time, so evidence consumers that need a position
      // (the anchor audit) must exclude them rather than attribute them at report time.
      const hasAge = a.age_ms != null && Number.isFinite(Number(a.age_ms));
      if (r != null && b) out.set(b, { rssi: r, name: a.ssid || '(hidden)', ageMs: wifiAgeMs(a), aged: hasAge });
    }
    const wc = nd.wifi_current;
    const b = wc ? String(wc.bssid || '').toUpperCase() : '';
    if (b && isValidRssi(wc.rssi)) out.set(b, { rssi: wc.rssi, name: wc.ssid || '(hidden)', ageMs: 0, aged: true }); // live WifiInfo
  } catch {}
  return out;
}
// Anchor 1 m reference: persisted ref_rssi when sane, else the per-kind default.
// (A stored 127 must NOT be trusted just because it's truthy.)
function anchorRefOrDefault(a) {
  const ref = Number(a.ref_rssi);
  if (isValidRssi(ref)) return ref;
  return a.kind === 'wifi' ? -35 : -59;
}
// Locally-administered MAC (U/L bit set): randomized BLE privacy addresses, phone
// hotspots, WiFi-Direct/P2P interfaces. They rotate, so a learned row can never match
// again — pure table spam. Never auto-calibrate them (manual anchors unaffected).
function isRandomizedMac(addr) {
  const m = String(addr || '').toUpperCase().replace(/[^0-9A-F]/g, '');
  if (m.length !== 12) return false;
  return (parseInt(m.slice(0, 2), 16) & 0x02) !== 0;
}

// Planar distance in metres — plenty for gating spans of a few km (small-angle).
function approxDistM(aLat, aLng, bLat, bLng) {
  const dy = (aLat - bLat) * 111320;
  const dx = (aLng - bLng) * 111320 * Math.cos(((aLat + bLat) / 2) * Math.PI / 180);
  return Math.sqrt(dx * dx + dy * dy);
}

// Latest stored GPS fix for a device (decrypts the row). Null when none/undecryptable.
async function latestDeviceLocation(deviceId) {
  try {
    const row = await db.prepare('SELECT data, timestamp FROM locations WHERE device_id=? ORDER BY timestamp DESC LIMIT 1').get(deviceId);
    if (!row) return null;
    const d = JSON.parse(decryptText(row.data));
    const lat = Number(d.lat), lng = Number(d.lng);
    if (!Number.isFinite(lat) || !Number.isFinite(lng)) return null;
    return { lat, lng, accuracy: Number(d.accuracy) || 0, ts: row.timestamp };
  } catch { return null; }
}

// Nearest stored fix to `ts` (either side, within AUTO_CALIB_SNAPSHOT_ALIGN_MS). Used to
// attribute a scan snapshot to the place the device actually was when it scanned.
async function locationAtTime(deviceId, ts) {
  const win = AUTO_CALIB_SNAPSHOT_ALIGN_MS;
  const before = await db.prepare('SELECT data, timestamp FROM locations WHERE device_id=? AND timestamp<=? ORDER BY timestamp DESC LIMIT 1').get(deviceId, ts + win);
  const after  = await db.prepare('SELECT data, timestamp FROM locations WHERE device_id=? AND timestamp>=? ORDER BY timestamp ASC LIMIT 1').get(deviceId, ts - win);
  let best = null;
  for (const row of [before, after]) {
    if (!row) continue;
    const delta = Math.abs(row.timestamp - ts);
    if (delta > win || (best && best.delta <= delta)) continue;
    try {
      const d = JSON.parse(decryptText(row.data));
      const lat = Number(d.lat), lng = Number(d.lng);
      if (!Number.isFinite(lat) || !Number.isFinite(lng)) continue;
      best = { lat, lng, accuracy: Number(d.accuracy) || 0, ts: row.timestamp, delta };
    } catch {}
  }
  return best;
}

  return {
    anchorRefOrDefault,
    approxDistM,
    isRandomizedMac,
    latestDeviceLocation,
    locationAtTime,
    wifiReadingsFromSnapshot,
  };
};
