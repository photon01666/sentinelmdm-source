// routes/wifi-aps-anchors-and-positioning.js — known WiFi APs (WiGLE), proximity-anchor CRUD,
// operator tower correction, RF indoor position estimate, anchor audit.
// Extracted from server.js L12204-12607. 7 routes.
module.exports = ({ app, _cellHistoryCache, anchorRefOrDefault, approxDistM, computeCellFix, computeRfFix, db, decryptText, filterFixPoints, isRandomizedMac, isValidRssi, latestDeviceLocation, log, lookupWigleAP, requireAuth, requireDeviceAccess, requirePerm, requireUnlocked, stmts, validCellIdentity, wifiReadingsFromSnapshot, wigleAuthHeader }) => {
// ── Known WiFi locations (WiGLE-resolved BSSIDs) ──────────────────────────────
// GET /api/wifi-aps — AP positions the caller is actually associated with (the BSSIDs
// of their own calibrated anchors). Scoped + capped deliberately: the table is GLOBAL
// (every account's resolved APs), so an unscoped SELECT leaked other users' SSIDs/
// BSSIDs/positions to any authenticated user, and the map's "all known WiFi" layer
// used to render all 5,000 rows as DOM-backed markers — enough to kill a mobile
// WebView's GPU context (Pixel 9a crash 2026-09-11). Admin gets the full set, capped.
app.get('/api/wifi-aps', requireUnlocked, requireAuth, async (req, res) => {
  try {
    const rows = req.session.role === 'admin'
      ? (await db.prepare('SELECT bssid, ssid, lat, lng, accuracy_m AS accuracyM, source FROM wifi_aps LIMIT 1000').all())
      : (await db.prepare(
          'SELECT DISTINCT w.bssid, w.ssid, w.lat, w.lng, w.accuracy_m AS accuracyM, w.source ' +
          'FROM wifi_aps w JOIN proximity_anchors a ON UPPER(a.address)=UPPER(w.bssid) ' +
          'WHERE a.user_id=? LIMIT 1000'
        ).all(String(req.session.userId)));
    res.json({ aps: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Indoor-positioning anchors (calibrated WiFi/BT landmarks) ────────────────────
// GET /api/anchors — the anchors the caller can use (admin: all; public user: their own).
app.get('/api/anchors', requireUnlocked, requireAuth, async (req, res) => {
  try {
    const rows = req.session.role === 'admin'
      ? (await db.prepare('SELECT * FROM proximity_anchors ORDER BY name, address').all())
      : (await db.prepare('SELECT * FROM proximity_anchors WHERE user_id=? ORDER BY name, address').all(String(req.session.userId)));
    res.json({ anchors: rows });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/anchors', requireUnlocked, requireAuth, async (req, res) => {
  const { kind='bt', address='', name='', lat, lng, ref_rssi, origin='manual' } = req.body || {};
  const kindOk = kind === 'wifi' || kind === 'bt';
  const addr = String(address || '').trim().toUpperCase();
  const latN = Number(lat), lngN = Number(lng);
  const refN = Number(ref_rssi);
  const originOk = origin === 'manual' || origin === 'auto';
  if (!kindOk || !addr || !Number.isFinite(latN) || !Number.isFinite(lngN) ||
      Math.abs(latN) > 90 || Math.abs(lngN) > 180 || !Number.isFinite(refN) || !originOk)
    return res.status(400).json({ error: 'kind, address, valid lat/lng, ref_rssi and origin required' });
  if (!isValidRssi(refN))
    return res.status(400).json({ error: 'ref_rssi out of plausible range (-110..-5 dBm); 127 = unknown-signal sentinel, not a measurement' });
  try {
    // Upsert on (user_id, address): the ZK client re-POSTs after localStorage loss and
    // concurrent heartbeats double-persist — both must converge on one row, never dupes.
    // A MANUAL row always wins over an auto re-POST.
    const ex = (await db.prepare('SELECT id, origin FROM proximity_anchors WHERE user_id=? AND address=?').get(String(req.session.userId), addr));
    if (ex) {
      if (ex.origin === 'manual' && origin === 'auto') return res.json({ ok: true, id: ex.id, kept: 'manual' });
      (await db.prepare(
        'UPDATE proximity_anchors SET kind=?, name=?, lat=?, lng=?, ref_rssi=?, origin=?, created_at=? WHERE id=?'
      ).run(kindOk ? kind : 'bt', String(name || '').slice(0, 80), latN, lngN, refN, originOk ? origin : 'manual', Date.now(), ex.id));
      return res.json({ ok: true, id: ex.id, updated: true });
    }
    const r = (await db.prepare(
      'INSERT INTO proximity_anchors (user_id,kind,address,name,lat,lng,ref_rssi,created_at,origin) VALUES (?,?,?,?,?,?,?,?,?) RETURNING id'
    ).get(String(req.session.userId), kindOk ? kind : 'bt', addr, String(name || '').slice(0, 80), latN, lngN, refN, Date.now(), originOk ? origin : 'manual'));
    res.json({ ok: true, id: r.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/anchors/:id', requireUnlocked, requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  try {
    const row = (await db.prepare('SELECT user_id FROM proximity_anchors WHERE id=?').get(id));
    if (!row) return res.status(404).json({ error: 'anchor not found' });
    if (req.session.role !== 'admin' && String(row.user_id) !== String(req.session.userId))
      return res.status(403).json({ error: 'not your anchor' });
    (await db.prepare('DELETE FROM proximity_anchors WHERE id=?').run(id));
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Operator tower correction (map click-to-move) ─────────────────────────────
// The operator knows where the steel really is. Stores manual_lat/lng, which wins
// over fleet-learned and OCID in towerPosition(). Admin-only: tower positions are
// global shared truth, not per-user data.
app.post('/api/cell-towers/correct', requireUnlocked, requireAuth, async (req, res) => {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  try {
    const { mcc, mnc, tac, cid, lat, lng } = req.body || {};
    const imcc = Number(mcc), imnc = Number(mnc ?? 0), itac = Number(tac ?? 0), icid = Number(cid);
    const flat = Number(lat), flng = Number(lng);
    if (!validCellIdentity(imcc, imnc, itac, icid))
      return res.status(400).json({ error: 'invalid cell identity' });
    if (!Number.isFinite(flat) || !Number.isFinite(flng) || Math.abs(flat) > 90 || Math.abs(flng) > 180)
      return res.status(400).json({ error: 'invalid lat/lng' });
    const now = Date.now();
    const row = (await db.prepare('SELECT id FROM cell_towers WHERE mcc=? AND mnc=? AND tac=? AND cid=?').get(imcc, imnc, itac, icid));
    if (row) {
      (await db.prepare('UPDATE cell_towers SET manual_lat=?, manual_lng=?, manual_at=?, updated_at=? WHERE id=?').run(flat, flng, now, now, row.id));
    } else {
      (await db.prepare(
        'INSERT INTO cell_towers (mcc,mnc,tac,cid,lat,lng,ref_dbm,samples,spread_m,source,updated_at,manual_lat,manual_lng,manual_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)'
      ).run(imcc, imnc, itac, icid, flat, flng, -90, 0, 0, 'manual', now, flat, flng, now));
    }
    log('info', 'Operator corrected tower position', { key: `${imcc}-${imnc}-${itac}-${icid}`, lat: flat, lng: flng });
    try { _cellHistoryCache.clear(); } catch {}   // history dots must re-render at the new spot
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── RF indoor position estimate (weighted trilateration from calibrated anchors) ──
// Consumes the latest BT scan + WiFi scan as RSSI readings, distances each calibrated
// anchor, and produces a weighted-centroid fix + an uncertainty radius. The result is
// EMA-smoothed per device so the map pin doesn't jitter between scans. GPS fix remains
// the authoritative source when it's good; this is the indoor fallback (and a complement
// when the device is inside).
const _rfFix = {}; // deviceId -> { lat, lng } smoothed estimate
const RF_EMA_ALPHA = 0.45;

app.get('/api/devices/:id/indoor-position', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  const devId = req.params.id;
  try {
    // 1) Determine the anchor scope: the device's owner's anchors, else all (admin-managed).
    const dev = (await stmts.getDevice.get(devId));
    const ownerId = dev?.owner_user_id ? String(dev.owner_user_id) : null;
    const anchors = ownerId
      ? (await db.prepare('SELECT * FROM proximity_anchors WHERE user_id=?').all(ownerId))
      : (await db.prepare('SELECT * FROM proximity_anchors').all());

    // 2) Latest RSSI readings: BT (device_telemetry.bt_devices) + WiFi (network_events).
    // Sentinel RSSI (127) never becomes a reading — it would pin the fix at 0.5 m.
    const readings = new Map();
    const wifiSeen = new Set(); // BSSIDs (subset of readings) — candidates for WiGLE assist
    try {
      const btRow = (await db.prepare('SELECT bt_devices FROM device_telemetry WHERE device_id=?').get(devId));
      if (btRow?.bt_devices) {
        for (const d of JSON.parse(btRow.bt_devices)) {
          if (isValidRssi(d.rssi)) readings.set(String(d.address || '').toUpperCase(), d.rssi);
        }
      }
    } catch {}
    try {
      const netRow = (await stmts.latestNetwork.get(devId));
      if (netRow?.data) {
        const nd = JSON.parse(decryptText(netRow.data));
        for (const [b, rd] of wifiReadingsFromSnapshot(nd)) { readings.set(b, rd.rssi); wifiSeen.add(b); }
      }
    } catch {}

    // 3) Weighted-centroid trilateration over anchors with a live reading.
    const pts = [];
    for (const a of anchors) {
      const rssi = readings.get(String(a.address).toUpperCase());
      if (rssi == null) continue;
      const d = Math.max(0.5, Math.pow(10, (anchorRefOrDefault(a) - rssi) / (10 * 2.0)));
      pts.push({ lat: a.lat, lng: a.lng, d, w: 1 / (d * d), name: a.name || a.address, address: a.address, kind: a.kind });
    }
    // 3b) WiGLE fallback: fewer than 2 calibrated anchors in range → resolve the
    // strongest unmatched non-randomized BSSIDs against the wardriving DB (max 3
    // lookups per poll; hits AND misses cached). External points get quarter weight
    // with a 150 m floor each — assist, not authority.
    let wigleUsed = 0;
    if (pts.length < 2 && wifiSeen.size && wigleAuthHeader()) {
      const matched = new Set(pts.map(p => String(p.address || '').toUpperCase()));
      const cands = [...wifiSeen]
        .filter(b => !matched.has(b) && !isRandomizedMac(b))
        .map(b => ({ b, rssi: readings.get(b) }))
        .filter(x => isValidRssi(x.rssi))
        .sort((x, y) => y.rssi - x.rssi)
        .slice(0, 3);
      for (const { b, rssi } of cands) {
        const ap = await lookupWigleAP(b);
        if (!ap) continue;
        const d = Math.max(150, Math.pow(10, (-35 - rssi) / 20));
        pts.push({ lat: ap.lat, lng: ap.lng, d, w: 0.25 / (d * d), name: ap.ssid || b, address: b, kind: 'wifi', ext: 'wigle' });
        wigleUsed++;
      }
    }
    // 3c) Geographic sanity: a matched anchor whose saved position is a different town away
    // is stale/mis-calibrated, not a fix. Gate against the device's latest GPS position (or
    // the strongest cluster when there is none) BEFORE any fix/line is rendered.
    const refLoc = await latestDeviceLocation(devId);
    if (pts.length) {
      const kept = filterFixPoints(pts, refLoc);
      if (kept.length !== pts.length) {
        log('info', 'RF fix: dropped far-outlier anchors', { deviceId: devId, matched: pts.length, dropped: pts.length - kept.length });
        pts.length = 0;
        pts.push(...kept);
      }
    }
    if (!pts.length) return res.json({
      fix: null, anchorsUsed: [], reason: 'no calibrated anchor in range',
      cellFix: (await computeCellFix(devId)),
      btFix: (await computeRfFix(devId, anchors, refLoc)),
      ts: Date.now()
    });

    const W = pts.reduce((s, p) => s + p.w, 0);
    let lat = pts.reduce((s, p) => s + p.lat * p.w, 0) / W;
    let lng = pts.reduce((s, p) => s + p.lng * p.w, 0) / W;
    // EMA smooth against scan-to-scan jitter.
    const prev = _rfFix[devId];
    if (prev) { lat = prev.lat + RF_EMA_ALPHA * (lat - prev.lat); lng = prev.lng + RF_EMA_ALPHA * (lng - prev.lng); }
    _rfFix[devId] = { lat, lng };
    // Uncertainty radius: single anchor → its distance; multiple → weighted scatter.
    // A pure WiGLE fix (no calibrated anchor) gets a 100 m floor — wardriven, not surveyed.
    let accuracyM;
    if (pts.length === 1) accuracyM = Math.min(30, Math.max(3, pts[0].d));
    else {
      const meanD = pts.reduce((s, p) => s + p.d, 0) / pts.length;
      const varD = pts.reduce((s, p) => s + (p.d - meanD) ** 2, 0) / pts.length;
      accuracyM = Math.min(40, Math.max(2, meanD * 0.35 + Math.sqrt(varD) * 0.65));
    }
    const calibPts = pts.filter(p => !p.ext).length;
    if (wigleUsed > 0 && calibPts === 0) accuracyM = Math.max(accuracyM, 100);
    res.json({
      fix: { lat: Math.round(lat * 1e6) / 1e6, lng: Math.round(lng * 1e6) / 1e6, accuracyM: Math.round(accuracyM * 10) / 10 },
      anchorsUsed: pts.map(p => ({ lat: p.lat, lng: p.lng, d: Math.round(p.d * 10) / 10, name: p.name, address: p.address, kind: p.kind, ext: p.ext || null })),
      anchorCount: pts.length,
      wigle: wigleUsed > 0, wigleCount: wigleUsed,
      // Cell-tower layer: current cells with learned positions + a coarse triangulated fix
      // (fallback when no WiFi/BT anchors are available — GPS-less urban/basement coverage).
      cellFix: (await computeCellFix(devId)),
      // BT fingerprint fix: most recent scan matching calibrated anchors (fills gaps when
      // GPS has been off for hours — the device still sees nearby BLE landmarks).
      btFix: (await computeRfFix(devId, anchors, refLoc)),
      ts: Date.now()
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Anchor audit: "is this detected address genuinely seen in 2 places, or is its saved
// anchor position simply wrong?" ─────────────────────────────────────────────────────────
// Joins BT/WiFi scan history against the location history AT SCAN TIME (nearest fix within
// 15 min) and reports per address: where it was actually seen, how far apart those places
// are, the saved anchor's position and its distance from the main seen area, and a verdict
// (anchor_misplaced | seen_at_multiple_places | ok). Non-ZK devices: server-side (scan and
// location data is decryptable here). ZK devices: the server cannot read the data — responds
// { zk: true, anchors } and the owner's browser runs the same join with its own key.
app.get('/api/devices/:id/anchor-audit', requireUnlocked, requireAuth, requireDeviceAccess, requirePerm('location'), async (req, res) => {
  const devId = req.params.id;
  try {
    const dev = (await stmts.getDevice.get(devId));
    const ownerId = dev?.owner_user_id ? String(dev.owner_user_id) : null;
    const anchors = ownerId
      ? (await db.prepare('SELECT * FROM proximity_anchors WHERE user_id=?').all(ownerId))
      : (await db.prepare('SELECT * FROM proximity_anchors').all());
    const slimAnchor = a => ({
      id: a.id, address: a.address, name: a.name || '', kind: a.kind,
      lat: a.lat, lng: a.lng, ref_rssi: a.ref_rssi, origin: a.origin || 'manual', created_at: a.created_at,
    });
    const ownerRow = (await db.prepare(
      'SELECT u.account_type, d.is_demo FROM devices d LEFT JOIN users u ON d.owner_user_id=u.id WHERE d.id=?'
    ).get(devId));
    if (ownerRow?.account_type === 'public' && !ownerRow?.is_demo)
      return res.json({ zk: true, anchors: anchors.map(slimAnchor), rows: [], days: 0, scans: 0, locations: 0 });

    const days = Math.min(30, Math.max(1, parseInt(/** @type {any} */ (req.query.days), 10) || 14));
    const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;

    // Location timeline (one decrypt pass; ASC for the nearest-fix search).
    const locRows = (await db.prepare(
      'SELECT data, timestamp FROM locations WHERE device_id=? AND timestamp>? ORDER BY timestamp ASC LIMIT 20000'
    ).all(devId, cutoff));
    const locsArr = [];
    for (const r of locRows) {
      try {
        const d = JSON.parse(decryptText(r.data));
        const la = Number(d.lat), ln = Number(d.lng);
        if (Number.isFinite(la) && Number.isFinite(ln)) locsArr.push({ ts: r.timestamp, lat: la, lng: ln });
      } catch {}
    }
    // Nearest fix to a scan timestamp (within `win`) — binary search over the ASC timeline.
    const nearestLoc = (ts, win) => {
      let lo = 0, hi = locsArr.length - 1, at = -1;
      while (lo <= hi) { const mid = (lo + hi) >> 1; if (locsArr[mid].ts <= ts) { at = mid; lo = mid + 1; } else hi = mid - 1; }
      let best = null;
      for (const i of [at, at + 1]) {
        const c = locsArr[i];
        if (!c) continue;
        const delta = Math.abs(c.ts - ts);
        if (delta > win) continue;
        if (!best || delta < Math.abs(best.ts - ts)) best = c;
      }
      return best;
    };

    // Accumulate seen positions per address. wifiOccIncluded/Skipped quantify how much WiFi
    // evidence was usable (per-AP age from agent 2.26.0.18+) vs excluded (pre-update payloads,
    // which have no real scan time and would be attributed at report time).
    const occ = new Map(); // addr -> { address, name, kind, points, firstSeen, lastSeen }
    let wifiOccIncluded = 0, wifiOccSkipped = 0;
    const addOcc = (addr, name, kind, ts, aged) => {
      const a = String(addr || '').toUpperCase();
      if (!a) return;
      const loc = nearestLoc(ts, 15 * 60 * 1000);
      if (!loc) return;
      if (kind === 'wifi' && aged) wifiOccIncluded++;
      let o = occ.get(a);
      if (!o) { o = { address: a, name: name || '', kind, points: [], firstSeen: ts, lastSeen: ts }; occ.set(a, o); }
      if (!o.name && name) o.name = name;
      if (o.points.length < 500) o.points.push({ lat: loc.lat, lng: loc.lng });
      if (ts < o.firstSeen) o.firstSeen = ts;
      if (ts > o.lastSeen) o.lastSeen = ts;
    };

    // Stale-scan guard: the phone re-reports the SAME cached WiFi/BT scan list for minutes
    // while moving (Android scan-result caching + a 2 s connectivity-change snapshot), which
    // made every fixed AP look like it "followed" the device across tens of km. Two
    // consecutive snapshots with an identical address→RSSI set are ONE observation, so the
    // repeat is skipped (and "Seen" becomes a count of distinct scans, not reports).
    const snapSig = list => list.map(x => `${x[0]}:${Math.round(Number(x[1]))}`).sort().join(',');
    const btRows = (await db.prepare(
      'SELECT data, timestamp FROM bt_events WHERE device_id=? AND timestamp>? ORDER BY timestamp ASC LIMIT 20000'
    ).all(devId, cutoff));
    let lastBtSig = null;
    for (const r of btRows) {
      let devices = [];
      try { devices = JSON.parse(r.data); } catch { continue; }
      const readings = devices.filter(d => d && d.address && isValidRssi(d.rssi))
        .map(d => [String(d.address).toUpperCase(), d.rssi]);
      const sig = snapSig(readings);
      if (sig === lastBtSig) continue;
      lastBtSig = sig;
      const nameByAddr = new Map(devices.map(d => [String(d.address || '').toUpperCase(), d.name]));
      for (const [addr] of readings) addOcc(addr, nameByAddr.get(addr), 'bt', r.timestamp);
    }
    const netRows = (await db.prepare(
      'SELECT data, timestamp FROM network_events WHERE device_id=? AND timestamp>? ORDER BY timestamp ASC LIMIT 20000'
    ).all(devId, cutoff));
    let lastWifiSig = null;
    for (const r of netRows) {
      let nd = null;
      try { nd = JSON.parse(decryptText(r.data)); } catch { continue; }
      const seen = wifiReadingsFromSnapshot(nd);
      const sig = snapSig([...seen.entries()].map(([b, rd]) => [String(b).toUpperCase(), rd.rssi]));
      if (sig === lastWifiSig) continue;
      lastWifiSig = sig;
      // Only WiFi readings carrying a per-AP age are trustworthy enough to place on the map;
      // un-aged entries (pre-2.26.0.18 payloads) are EXCLUDED rather than attributed at
      // report time, which is what created phantom multi-km spans.
      for (const [b, rd] of seen) {
        if (!rd.aged) { wifiOccSkipped++; continue; }
        addOcc(b, rd.name, 'wifi', r.timestamp - (rd.ageMs || 0), true);
      }
    }

    // Summarise seen positions into ~300 m cells: distinct areas, max span, main area.
    const summarize = points => {
      const cells = new Map();
      for (const p of points) {
        const k = `${Math.round(p.lat * 111320 / 300)}:${Math.round(p.lng * 111320 * Math.cos(p.lat * Math.PI / 180) / 300)}`;
        let c = cells.get(k);
        if (!c) { c = { n: 0, lat: 0, lng: 0 }; cells.set(k, c); }
        c.n++; c.lat += p.lat; c.lng += p.lng;
      }
      const centers = [...cells.values()].map(c => ({ lat: c.lat / c.n, lng: c.lng / c.n, n: c.n }));
      let spanM = 0;
      for (let i = 0; i < centers.length; i++)
        for (let j = i + 1; j < centers.length; j++)
          spanM = Math.max(spanM, approxDistM(centers[i].lat, centers[i].lng, centers[j].lat, centers[j].lng));
      const main = centers.length ? centers.reduce((a, b) => (b.n > a.n ? b : a)) : null;
      return { areas: centers.length, spanM, main };
    };

    const anchorByAddr = new Map(anchors.map(a => [String(a.address).toUpperCase(), a]));
    const fmtKm = m => m >= 1000 ? `${(m / 1000).toFixed(m >= 10000 ? 0 : 1)} km` : `${Math.round(m)} m`;
    const rows = [];   // problem findings only
    const allRows = []; // every detected address (inventory) — lets the UI show "what was seen"
    for (const o of occ.values()) {
      const st = summarize(o.points);
      const anchor = anchorByAddr.get(o.address) || null;
      const anchorDeltaM = (anchor && st.main) ? approxDistM(anchor.lat, anchor.lng, st.main.lat, st.main.lng) : null;
      let verdict = 'seen', why;
      if (anchor && anchorDeltaM != null && anchorDeltaM > 1000 && st.spanM <= 1000) {
        verdict = 'anchor_misplaced';
        why = `Saved anchor is ${fmtKm(anchorDeltaM)} from the only area this address is actually seen in.`;
      } else if (st.spanM > 1000) {
        verdict = 'seen_at_multiple_places';
        why = `Seen across ${st.areas} area(s) spanning ${fmtKm(st.spanM)}${anchorDeltaM != null ? ` — saved anchor ${fmtKm(anchorDeltaM)} from the main area` : ''}.`;
      } else if (anchor) {
        verdict = 'ok';
        why = `Seen in one area${anchorDeltaM != null ? `, saved anchor ${fmtKm(anchorDeltaM)} away` : ''}.`;
      } else {
        why = `Seen in ${st.areas} area(s), span ${fmtKm(st.spanM)}.`;
      }
      const entry = {
        address: o.address, name: o.name, kind: o.kind,
        count: o.points.length, firstSeen: o.firstSeen, lastSeen: o.lastSeen,
        areas: st.areas, spanM: Math.round(st.spanM),
        main: st.main ? { lat: Math.round(st.main.lat * 1e6) / 1e6, lng: Math.round(st.main.lng * 1e6) / 1e6 } : null,
        anchor: anchor ? slimAnchor(anchor) : null,
        anchorDeltaM: anchorDeltaM == null ? null : Math.round(anchorDeltaM),
        verdict, why,
      };
      allRows.push(entry);
      if (verdict === 'anchor_misplaced' || verdict === 'seen_at_multiple_places' || verdict === 'ok') rows.push(entry);
    }
    const rank = v => v === 'anchor_misplaced' ? 0 : v === 'seen_at_multiple_places' ? 1 : 2;
    rows.sort((a, b) => rank(a.verdict) - rank(b.verdict) || (b.spanM - a.spanM) || ((b.anchorDeltaM || 0) - (a.anchorDeltaM || 0)));
    allRows.sort((a, b) => (b.count - a.count) || (b.spanM - a.spanM));
    res.json({
      zk: false, days, locations: locsArr.length, scans: btRows.length + netRows.length,
      wifiOccIncluded, wifiOccSkipped,
      detectedWiFi: allRows.filter(r => r.kind === 'wifi').length,
      detectedBT: allRows.filter(r => r.kind === 'bt').length,
      detected: allRows.slice(0, 200),
      anchors: anchors.map(slimAnchor), rows: rows.slice(0, 200),
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
};
