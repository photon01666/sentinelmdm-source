// routes/bluetooth-safelist-and-proximity.js — Bluetooth tracker safelist CRUD,
// Bluetooth scan history, and RF-proximity context (WiFi + BT with distance estimates).
// Extracted verbatim from server.js L10694-L10792. 5 routes.
// getBtSafelist/applyBtSafelist stay in server.js (socket handlers use them) and are injected.
module.exports = ({ app, applyBtSafelist, db, decryptText, getBtSafelist, maybeRespondWithZkPayloads, requireAuth, requireDeviceAccess, requireUnlocked, setBtSafelist, stmts }) => {
app.get('/api/devices/:id/bluetooth', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  const scanRow = await db.prepare('SELECT bt_scan_state FROM device_telemetry WHERE device_id=?').get(req.params.id);
  const scanning = !!(scanRow?.bt_scan_state);
  const safelist = await getBtSafelist(req.params.id);
  const safeSet = new Set(safelist.map(x => String(x.address).toUpperCase()));
  // ZK-owned devices still deliver it via maybeRespondWithZkPayloads (we can't decrypt here).
  if ((await maybeRespondWithZkPayloads(req, res, 'bt_device_event'))) return;
  const row = await db.prepare('SELECT bt_devices, bt_scan_ts FROM device_telemetry WHERE device_id=?').get(req.params.id);
  if (!row || !row.bt_devices) return res.json({ devices: [], timestamp: null, scanning, safeList: safelist });
  let devices = [];
  try { devices = JSON.parse(row.bt_devices); } catch {}
  // Defense-in-depth: re-apply the safelist at read time too (covers any stored payload that
  // predates the write-time filter, e.g. the ZK read-back path).
  devices = applyBtSafelist(devices, safeSet);
  res.json({ devices, timestamp: row.bt_scan_ts, scanning, safeList: safelist });
});

// Mark a nearby device's MAC address as "safe" (suppresses its tracker flags + alerts).
app.post('/api/devices/:id/bluetooth/safe', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  const address = String(req.body?.address || '').trim().toUpperCase();
  if (!/^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(address))
    return res.status(400).json({ error: 'valid MAC address required' });
  const name = String(req.body?.name || '').slice(0, 80);
  const safelist = await getBtSafelist(req.params.id);
  if (!safelist.some(x => String(x.address).toUpperCase() === address)) {
    safelist.push({ address, name, ts: Date.now() });
    await setBtSafelist(req.params.id, safelist);
  }
  return res.json({ ok: true, safeList: safelist });
});

// Remove a MAC from the safelist (no longer "safe").
app.post('/api/devices/:id/bluetooth/unsafe', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  const address = String(req.body?.address || '').trim().toUpperCase();
  const safelist = (await getBtSafelist(req.params.id)).filter(x => String(x.address).toUpperCase() !== address);
  await setBtSafelist(req.params.id, safelist);
  return res.json({ ok: true, safeList: safelist });
});

// ── Bluetooth scan history (accumulated bt_events) ──────────────────────────
// Returns all BT scan snapshots from the last 30 days so the WebUI can show where the
// device has been based on nearby BLE/classic devices — useful when GPS/location is off.
app.get('/api/devices/:id/bluetooth/history', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  const cutoff30d = Date.now() - 30 * 24 * 60 * 60 * 1000;
  const rows = await db.prepare('SELECT data, timestamp FROM bt_events WHERE device_id=? AND timestamp>? ORDER BY timestamp DESC').all(req.params.id, cutoff30d);
  const history = rows.map(r => {
    let devices = [];
    try { devices = JSON.parse(r.data); } catch {}
    return { timestamp: r.timestamp, devices };
  });
  res.json({ history, count: history.length });
});

// ── Indoor anchors: nearby WiFi APs + Bluetooth devices (RSSI + distance estimate) ──
// Merges the latest WiFi scan (from the network_info stream) with the latest BT scan
// (device_telemetry.bt_devices) so the Location tab can show RF-proximity context for
// indoor fixes (GPS is unreliable inside buildings). Distances are estimates from the
// log-distance path-loss model d = 10^((Ptx − RSSI)/(10·n)) with per-band defaults.
app.get('/api/devices/:id/proximity', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  const devId = req.params.id;
  let wifi = [], wifiCurrent = null, ts = null;
  try {
    const row = (await stmts.latestNetwork.get(devId));
    if (row?.data) {
      const d = JSON.parse(decryptText(row.data));
      wifi = Array.isArray(d.wifi_networks) ? d.wifi_networks : [];
      wifiCurrent = d.wifi_current || null;
      ts = row.timestamp || null;
    }
  } catch {}
  let bt = [];
  try {
    const row = (await db.prepare('SELECT bt_devices, bt_scan_ts FROM device_telemetry WHERE device_id=?').get(devId));
    if (row?.bt_devices) {
      const devices = JSON.parse(row.bt_devices);
      bt = devices
        .map(x => ({ address: x.address, name: x.name || '', rssi: Number.isFinite(x.rssi) ? x.rssi : null, bonded: x.bondState === 12 }))
        .filter(x => x.rssi != null);
      if (row.bt_scan_ts && (!ts || row.bt_scan_ts > ts)) ts = row.bt_scan_ts;
    }
  } catch {}
  const est = (rssi, tx, n) => (rssi == null ? null : Math.round(Math.pow(10, (tx - rssi) / (10 * n)) * 10) / 10);
  const wifiOut = wifi.slice(0, 12).map(a => ({
    ssid: a.ssid || '(hidden)', bssid: a.bssid, rssi: a.rssi,
    connected: !!(wifiCurrent && a.bssid && wifiCurrent.bssid === a.bssid),
    frequency: a.frequency, channel: a.channel, security: a.security,
    distM: est(a.rssi, -35, 2.7)   // 2.4/5GHz AP EIRP ≈ −35 dBm @1m, n≈2.7 indoors
  }));
  const btOut = bt.slice(0, 12).map(b => ({
    address: b.address, name: b.name, rssi: b.rssi, bonded: b.bonded,
    distM: est(b.rssi, -59, 2.0)   // BLE tx ≈ −59 dBm @1m (iBeacon-like), n≈2.0
  }));
  const all = [
    ...wifiOut.map(w => ({ kind: 'wifi', label: w.ssid, rssi: w.rssi, distM: w.distM })),
    ...btOut.map(b => ({ kind: 'bt', label: b.name || b.address, rssi: b.rssi, distM: b.distM }))
  ].filter(x => x.rssi != null);
  all.sort((a, b) => b.rssi - a.rssi);
  res.json({ wifi: wifiOut, bt: btOut, closest: all[0] || null, ts });
});
};
