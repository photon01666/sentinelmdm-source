// helpers/rf-fix.js - the single member of the helper inventory that estimates where a
// device physically is when GPS has been off for hours.
//
// A HELPER module, not a route module: it registers nothing. It exists to serve
// routes/wifi-aps-anchors-and-positioning.js, which receives it as a ctx dep below.
//
//   computeRfFix    export   scans 30 days of bt_events AND network_events for the most
//                            recent scan matching a calibrated proximity anchor, and
//                            returns the best (most recent) match.
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 7 of the 8 deps are `function` declarations, so they hoist and may be bound from any
// line; the one binding, db, is at L723, far above. All 8 are above L8182.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ anchorRefOrDefault, db, decryptText, filterFixPoints, isRandomizedMac, isValidRssi, lookupWigleAP, wifiReadingsFromSnapshot }) => {
// ── RF fingerprint fix: estimate device position from recent BT + WiFi history ──
// Searches the last 30 days of bt_events AND network_events for the most recent scan
// that matches known proximity anchors (calibrated BLE/BT/WiFi landmarks with lat/lng).
// WiFi BSSIDs from network_events are matched alongside BT addresses from bt_events,
// so the fix works from either signal type. Returns the best (most recent) match so
// the map always has a position even when GPS has been off for hours.
async function computeRfFix(deviceId, anchors, refLoc = null) {
  if (!anchors || !anchors.length) return { fix: null, source: 'rf', scannedAt: null };
  const anchorMap = new Map();
  for (const a of anchors) anchorMap.set(String(a.address).toUpperCase(), a);
  const windows = [
    Date.now() - 1 * 60 * 60 * 1000,   // 1 hour
    Date.now() - 6 * 60 * 60 * 1000,   // 6 hours
    Date.now() - 24 * 60 * 60 * 1000,  // 1 day
    Date.now() - 7 * 24 * 60 * 60 * 1000, // 7 days
    Date.now() - 30 * 24 * 60 * 60 * 1000 // 30 days (matches telemetry retention)
  ];
  for (const since of windows) {
    // Check BT scan history
    const btRows = await db.prepare(
      'SELECT data, timestamp FROM bt_events WHERE device_id=? AND timestamp>? ORDER BY timestamp DESC LIMIT 10'
    ).all(deviceId, since);
    for (const row of btRows) {
      let devices = [];
      try { devices = JSON.parse(row.data); } catch {}
      const readings = new Map();
      for (const d of devices) {
        if (isValidRssi(d.rssi)) readings.set(String(d.address || '').toUpperCase(), d.rssi);
      }
      const pts = [];
      for (const [addr, anchor] of anchorMap) {
        const rssi = readings.get(addr);
        if (rssi == null) continue;
        const d = Math.max(0.5, Math.pow(10, (anchorRefOrDefault(anchor) - rssi) / (10 * 2.0)));
        pts.push({ lat: anchor.lat, lng: anchor.lng, d, w: 1 / (d * d), name: anchor.name || addr, address: addr, kind: anchor.kind });
      }
      const usePts = filterFixPoints(pts, refLoc);
      if (usePts.length >= 2) {
        const W = usePts.reduce((s, p) => s + p.w, 0);
        const lat = usePts.reduce((s, p) => s + p.lat * p.w, 0) / W;
        const lng = usePts.reduce((s, p) => s + p.lng * p.w, 0) / W;
        const meanD = usePts.reduce((s, p) => s + p.d, 0) / usePts.length;
        const acc = Math.min(40, Math.max(2, meanD * 0.35 + Math.sqrt(usePts.reduce((s, p) => s + (p.d - meanD) ** 2, 0) / usePts.length) * 0.65));
        return {
          fix: { lat: Math.round(lat * 1e6) / 1e6, lng: Math.round(lng * 1e6) / 1e6, accuracyM: Math.round(acc * 10) / 10, source: 'bt', anchorsUsed: usePts.length },
          source: 'bt', scannedAt: row.timestamp,
          anchorNames: usePts.map(p => p.name), anchorAddrs: usePts.map(p => p.address),
          anchorPts: usePts.map(p => ({ lat: p.lat, lng: p.lng, name: p.name, address: p.address, kind: p.kind }))
        };
      }
    }
    // Check WiFi scan history (network_events stores WiFi alongside cell data)
    const netRows = await db.prepare(
      'SELECT data, timestamp FROM network_events WHERE device_id=? AND timestamp>? ORDER BY timestamp DESC LIMIT 10'
    ).all(deviceId, since);
    for (const row of netRows) {
      let nd = null;
      try { nd = JSON.parse(decryptText(row.data)); } catch {}
      if (!nd) continue;
      const readings = new Map();
      for (const [b, rd] of wifiReadingsFromSnapshot(nd)) readings.set(b, rd.rssi);
      if (!readings.size) continue;
      const pts = [];
      for (const [addr, anchor] of anchorMap) {
        const rssi = readings.get(addr);
        if (rssi == null) continue;
        const d = Math.max(0.5, Math.pow(10, (anchorRefOrDefault(anchor) - rssi) / (10 * 2.0)));
        pts.push({ lat: anchor.lat, lng: anchor.lng, d, w: 1 / (d * d), name: anchor.name || addr, address: addr, kind: anchor.kind });
      }
      const usePts = filterFixPoints(pts, refLoc);
      if (usePts.length >= 2) {
        const W = usePts.reduce((s, p) => s + p.w, 0);
        const lat = usePts.reduce((s, p) => s + p.lat * p.w, 0) / W;
        const lng = usePts.reduce((s, p) => s + p.lng * p.w, 0) / W;
        const meanD = usePts.reduce((s, p) => s + p.d, 0) / usePts.length;
        const acc = Math.min(40, Math.max(2, meanD * 0.35 + Math.sqrt(usePts.reduce((s, p) => s + (p.d - meanD) ** 2, 0) / usePts.length) * 0.65));
        return {
          fix: { lat: Math.round(lat * 1e6) / 1e6, lng: Math.round(lng * 1e6) / 1e6, accuracyM: Math.round(acc * 10) / 10, source: 'wifi', anchorsUsed: usePts.length },
          source: 'wifi', scannedAt: row.timestamp,
          anchorNames: usePts.map(p => p.name), anchorAddrs: usePts.map(p => p.address),
          anchorPts: usePts.map(p => ({ lat: p.lat, lng: p.lng, name: p.name, address: p.address, kind: p.kind }))
        };
      }
    }
  }
  // WiGLE history assist: no scan matched ≥2 calibrated anchors anywhere in 30 days —
  // take the most recent WiFi snapshot, resolve its strongest UNKNOWN (not an anchor,
  // non-randomized) BSSIDs against the wardriving DB (hits/misses cached; ≤3 lookups
  // per call), and fix from anchor matches + WiGLE points combined.
  try {
    const wrow = (await db.prepare(
      'SELECT data, timestamp FROM network_events WHERE device_id=? AND timestamp>? ORDER BY timestamp DESC LIMIT 1'
    ).get(deviceId, windows[windows.length - 1]));
    if (wrow) {
      const nd = JSON.parse(decryptText(wrow.data));
      const seen = wifiReadingsFromSnapshot(nd);
      const pts = [];
      for (const [b, rd] of seen) {
        const anchor = anchorMap.get(b);
        if (!anchor) continue;
        const d = Math.max(0.5, Math.pow(10, (anchorRefOrDefault(anchor) - rd.rssi) / (10 * 2.0)));
        pts.push({ lat: anchor.lat, lng: anchor.lng, d, w: 1 / (d * d), name: anchor.name || b, address: b, kind: 'wifi' });
      }
      const cands = [...seen.entries()]
        .filter(([b]) => !anchorMap.has(b) && !isRandomizedMac(b))
        .sort((x, y) => y[1].rssi - x[1].rssi)
        .slice(0, 3);
      for (const [b, rd] of cands) {
        const ap = await lookupWigleAP(b);
        if (!ap) continue;
        const d = Math.max(150, Math.pow(10, (-35 - rd.rssi) / 20));
        pts.push({ lat: ap.lat, lng: ap.lng, d, w: 0.25 / (d * d), name: ap.ssid || b, address: b, kind: 'wifi', ext: 'wigle' });
      }
      const usePts = filterFixPoints(pts, refLoc);
      if (usePts.length >= 2) {
        const W = usePts.reduce((s, p) => s + p.w, 0);
        const lat = usePts.reduce((s, p) => s + p.lat * p.w, 0) / W;
        const lng = usePts.reduce((s, p) => s + p.lng * p.w, 0) / W;
        const meanD = usePts.reduce((s, p) => s + p.d, 0) / usePts.length;
        let acc = Math.min(40, Math.max(2, meanD * 0.35 + Math.sqrt(usePts.reduce((s, p) => s + (p.d - meanD) ** 2, 0) / usePts.length) * 0.65));
        if (usePts.every(p => p.ext)) acc = Math.max(acc, 100);   // pure wardriven — surveyed would be tighter
        return {
          fix: { lat: Math.round(lat * 1e6) / 1e6, lng: Math.round(lng * 1e6) / 1e6, accuracyM: Math.round(acc * 10) / 10, source: 'wigle', anchorsUsed: usePts.length },
          source: 'wigle', scannedAt: Number(wrow.timestamp),
          anchorNames: usePts.map(p => p.name), anchorAddrs: usePts.map(p => p.address),
          anchorPts: usePts.map(p => ({ lat: p.lat, lng: p.lng, name: p.name, address: p.address, kind: p.kind }))
        };
      }
    }
  } catch {}
  return { fix: null, source: 'rf', scannedAt: null };
}

  return {
    computeRfFix,
  };
};
