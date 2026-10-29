// helpers/auto-calibrate-anchors.js — passive WiFi/BT anchor auto-calibration.
//
// A HELPER module, not a route module: it registers nothing. Consumer: the
// sockets/connection wiring (L4573 — moved below the block by the D1b sanctioned
// wiring-line relocation); the location handler calls it fire-and-forget at
// runtime.
//
//   autoCalibrateAnchors   export   one statistical pass: vote nearby anchors
//
// IN-PLACE splice at the block position (X = L4345). Resolution (A): the earliest
// eager consumer (sockets wiring) sits BELOW the wiring line after the D1b
// relocation; all deps are ready at the block top.
//
// Stable deps by value: AUTO_CALIB_* consts (L4304-L4317), _autoCalibLastAt
// (Map L4318 — mutated by reference, never reassigned), AUTO_CALIB_MAX_GPS_ACC_M
// (L3669), decryptText (L133), isRandomizedMac / isValidRssi / locationAtTime /
// wifiReadingsFromSnapshot (wifi-location wiring L4326-L4327), kv (L21), log
// (L250), persistAutoAnchor (wiring L4344), stmts (L1703).
// db travels as the LIVE getter `getDb: () => db` (reads rewritten to
// `getDb().…`).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ AUTO_CALIB_LIVE_FALLBACK_MS, AUTO_CALIB_MAX_GPS_ACC_M, AUTO_CALIB_MAX_SPREAD_M, AUTO_CALIB_MIN_INTERVAL_MS, AUTO_CALIB_MIN_RSSI, AUTO_CALIB_MIN_SAMPLES, AUTO_CALIB_SAMPLE_CAP, _autoCalibLastAt, decryptText, getDb, isRandomizedMac, isValidRssi, kv, locationAtTime, log, persistAutoAnchor, stmts, wifiReadingsFromSnapshot }) => {

async function autoCalibrateAnchors(deviceId, lat, lng, gpsAccM) {
  // Location fixes can arrive every second during live tracking; one statistical pass per
  // interval is plenty for a 40-sample rolling window and bounds the alignment queries.
  const now = Date.now();
  if (now - (_autoCalibLastAt.get(deviceId) || 0) < AUTO_CALIB_MIN_INTERVAL_MS) return;
  _autoCalibLastAt.set(deviceId, now);

  // Scope: the device's owner (fallback: admin-managed namespace '0').
  const dev = (await stmts.getDevice.get(deviceId));
  const ownerId = dev?.owner_user_id ? String(dev.owner_user_id) : '0';

  // Gather readings PER SOURCE with the source's own timestamp — the BT snapshot and the
  // WiFi snapshot can be hours apart, so they must be attributed to different positions.
  // Invalid RSSI (127 sentinel) and rotating (locally-administered) MACs never vote.
  /** @type {Array<{ ts: number, readings: Array<{ addr: string, rssi: any, name: any, kind: string, ageMs?: number }> }>} */
  const sources = [];
  try {
    const btRow = (await getDb().prepare('SELECT bt_devices, bt_scan_ts FROM device_telemetry WHERE device_id=?').get(deviceId));
    if (btRow?.bt_devices) {
      const readings = [];
      for (const d of JSON.parse(btRow.bt_devices)) {
        const a = String(d.address || '').toUpperCase();
        if (!a || !isValidRssi(d.rssi) || isRandomizedMac(a)) continue;
        readings.push({ addr: a, rssi: d.rssi, name: d.name || '', kind: 'bt' });
      }
      if (readings.length) sources.push({ ts: Number(btRow.bt_scan_ts) || 0, readings });
    }
  } catch {}
  try {
    const netRow = (await stmts.latestNetwork.get(deviceId));
    if (netRow?.data) {
      const nd = JSON.parse(decryptText(netRow.data));
      const readings = [];
      for (const [b, rd] of wifiReadingsFromSnapshot(nd)) {
        if (isRandomizedMac(b)) continue;
        readings.push({ addr: b, rssi: rd.rssi, name: rd.name, kind: 'wifi', ageMs: rd.ageMs || 0 });
      }
      if (readings.length) sources.push({ ts: Number(netRow.timestamp) || 0, readings });
    }
  } catch {}

  for (const src of sources) {
    // Each reading's OWN scan time = report time − age. WiFi cache entries can be minutes
    // old, so readings from one snapshot may belong to different places; resolve the
    // position per scan time (bucketed to the minute), not once for the whole snapshot.
    // A scan with no location anywhere near its time is unattributable — never vote it at "now".
    /** @type {Map<number, any[]>} */
    const byScanTs = new Map();
    for (const rd of src.readings) {
      const scanTs = Math.max(0, (src.ts || now) - (rd.ageMs || 0));
      const bucket = Math.round(scanTs / 60000) * 60000;
      if (!byScanTs.has(bucket)) byScanTs.set(bucket, []);
      byScanTs.get(bucket).push(rd);
    }
    /** @type {Map<number, { lat: number, lng: number, accuracy: number } | null>} */
    const refCache = new Map();
    for (const [scanTs, rds] of byScanTs) {
      if (!refCache.has(scanTs)) {
        /** @type {{ lat: number, lng: number, accuracy: number, ts?: number, delta?: number } | null} */
        let ref = scanTs ? await locationAtTime(deviceId, scanTs) : null;
        if (!ref && (!scanTs || (now - scanTs) <= AUTO_CALIB_LIVE_FALLBACK_MS))
          ref = { lat, lng, accuracy: gpsAccM };   // scan is seconds old — the live fix IS that spot
        refCache.set(scanTs, ref || null);
      }
      const ref = refCache.get(scanTs);
      if (!ref) continue;

      const gpsW = Math.max(0.2, 1 - (ref.accuracy || gpsAccM) / (AUTO_CALIB_MAX_GPS_ACC_M * 2)); // good fix → near-1 weight
      for (const rd of rds) {
        if (rd.rssi < AUTO_CALIB_MIN_RSSI || !isValidRssi(rd.rssi)) continue;   // too far away to vote for this spot
        const sigW = Math.pow(10, (rd.rssi + 85) / 30); // strong signal → heavy vote (≈1 @-85 … ≈32 @-60)
        const w = sigW * gpsW;
        try {
          const key = 'calib:' + rd.addr;
          const rec = (await kv.getJSON(key)) || { n: 0, samples: [], bestRssi: -999, name: '', kind: rd.kind };
          rec.n = (rec.n || 0) + 1;
          rec.samples = (rec.samples || []).concat([{ lat: ref.lat, lng: ref.lng, w }]);
          if (rec.samples.length > AUTO_CALIB_SAMPLE_CAP) rec.samples.splice(0, rec.samples.length - AUTO_CALIB_SAMPLE_CAP);
          if (rd.rssi > (rec.bestRssi || -999)) { rec.bestRssi = rd.rssi; rec.bestName = rd.name; }
          rec.name = rd.name || rec.name || rd.addr;
          rec.kind = rd.kind;
          await kv.setJSON(key, rec, 60 * 24 * 60 * 60); // 60d TTL — learning persists across restarts

          // Readiness: enough samples + tight scatter → persist as an auto anchor.
          if (rec.samples.length >= AUTO_CALIB_MIN_SAMPLES && rec.bestRssi >= AUTO_CALIB_MIN_RSSI) {
            const W = rec.samples.reduce((s, p) => s + p.w, 0);
            if (W > 0) {
              const cLat = rec.samples.reduce((s, p) => s + p.lat * p.w, 0) / W;
              const cLng = rec.samples.reduce((s, p) => s + p.lng * p.w, 0) / W;
              const spread = Math.sqrt(rec.samples.reduce((s, p) => {
                const dx = (p.lat - cLat) * 111320, dy = (p.lng - cLng) * 111320 * Math.cos(cLat * Math.PI / 180);
                return s + (dx * dx + dy * dy);
              }, 0) / rec.samples.length);
              if (spread <= AUTO_CALIB_MAX_SPREAD_M) {
                await persistAutoAnchor(ownerId, rd.addr, rec, cLat, cLng);
              }
            }
          }
        } catch (e) { log('warn', 'auto-calib vote failed', { address: rd.addr, error: e.message }); }
      }
    }
  }
}

return { autoCalibrateAnchors };

};
