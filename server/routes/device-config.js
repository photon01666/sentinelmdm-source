// routes/device-config.js - Per-device power/security toggles (deep sleep, theft mode),
// WiFi auto-join + unlock-capture config, captive-portal bypass, and airline WiFi
// profiles/credentials. Extracted VERBATIM from server.js L5139-L5407 (14 routes).
//
// PRESERVED PRE-EXISTING BUG -- deliberately NOT fixed here.
module.exports = ({ app, db, decryptDevice, detectAirline, emitToDevice, getAirlineProfile, getAirlineProfiles, getUnlockCapture, getWifiAutoJoin, io, log, normalizeUnlockCapture, normalizeWifiAutoJoin, requireAuth, requireDeviceAccess, requireDeviceController, requireUnlocked, setWifiAutoJoin, startTheftModeAlerts, stmts, stopTheftModeAlerts, validateCredentials }) => {
// ── Deep sleep ────────────────────────────────────────────────────────────────

// Monitor/admin toggles deep sleep for a device.
app.post('/api/devices/:id/deep-sleep', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  const { enabled } = req.body;
  const deviceId = req.params.id;
  (await db.prepare('UPDATE devices SET deep_sleep=? WHERE id=?').run(enabled ? 1 : 0, deviceId));
  // If the device is online (on any replica), command it to sleep immediately.
  if (enabled) emitToDevice(deviceId, 'command', { command: 'deep_sleep' });
  io.emit('devices_updated');
  log('info', `Deep sleep ${enabled ? 'enabled' : 'disabled'}`, { deviceId });
  res.json({ ok: true });
});

// Monitor/admin toggles theft mode for a device.
app.post('/api/devices/:id/theft-mode', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  const { enabled } = req.body;
  const deviceId = req.params.id;
  (await db.prepare('UPDATE devices SET theft_mode=? WHERE id=?').run(enabled ? 1 : 0, deviceId));
  emitToDevice(deviceId, 'command', { command: enabled ? 'start_theft_mode' : 'stop_theft_mode' });
  io.emit('devices_updated');
  log('info', `Theft mode ${enabled ? 'ENABLED' : 'disabled'}`, { deviceId });
  const device = decryptDevice((await stmts.getDevice.get(deviceId)));
  const deviceLabel = device ? `${device.name} • ${device.model}` : deviceId;
  if (enabled) (await startTheftModeAlerts(deviceId, deviceLabel));
  else stopTheftModeAlerts(deviceId, deviceLabel, 'manually stopped');
  res.json({ ok: true });
});

// ── Aggressive open-WiFi auto-join config (per device; owner OR admin via requireDeviceAccess) ──
// Stored in settings 'wifi_autojoin:<id>', pushed to the agent on change + on every reconnect.
// ⚠️ Default OFF — auto-joining arbitrary open APs is a rogue-AP exposure for the device's traffic.
app.get('/api/devices/:id/wifi-autojoin', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  res.json(await getWifiAutoJoin(req.params.id));
});
app.post('/api/devices/:id/wifi-autojoin', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  const cfg = normalizeWifiAutoJoin(req.body || {});
  (await setWifiAutoJoin(req.params.id, cfg));
  emitToDevice(req.params.id, 'command', { command: 'set_wifi_autojoin', ...cfg });
  io.emit('devices_updated');
  log('info', `WiFi auto-join ${cfg.enabled ? 'ENABLED' : 'disabled'}`, { deviceId: req.params.id, allow: cfg.allow.length, deny: cfg.deny.length });
  res.json({ ok: true, ...cfg });
});

// ── Unlock-attempt capture config (Photos tab; owner OR admin via requireDeviceAccess) ──
// Controls WHAT the agent grabs on a lock-screen unlock (front-camera photo and/or screenshot) and
// WHEN (failed unlocks when a capture type is on; successful unlocks only when onSuccess). Stored in
// settings 'unlock_capture:<id>', pushed to the agent on change + on every reconnect. All default OFF
// — nothing is captured on unlock until an operator opts in.
app.get('/api/devices/:id/unlock-capture', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  res.json(await getUnlockCapture(req.params.id));
});
app.post('/api/devices/:id/unlock-capture', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  const cfg = normalizeUnlockCapture(req.body || {});
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('unlock_capture:' + req.params.id, JSON.stringify(cfg)));
  emitToDevice(req.params.id, 'command', { command: 'set_unlock_capture', ...cfg });
  log('info', `Unlock capture set camera=${cfg.camera} screenshot=${cfg.screenshot} onSuccess=${cfg.onSuccess}`, { deviceId: req.params.id });
  res.json({ ok: true, ...cfg });
});

// ── Bypass captive portal (admin confirm: "this network has real internet") ───
app.post('/api/devices/:id/bypass-captive-portal', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), (req, res) => {
  emitToDevice(req.params.id, 'command', { command: 'bypass_captive_portal' });
  log('info', 'Admin bypassed captive portal — promoting WiFi to default route', { deviceId: req.params.id });
  res.json({ ok: true });
});

// ── Airline WiFi auto-login ────────────────────────────────────────────────
// Detect airline from SSID and submit credentials automatically.
// Stored in settings 'airline_wifi:<id>', pushed on change + on every reconnect.

/**
 * GET /api/airline-profiles — List all known airline WiFi profiles (for UI dropdowns)
 */
app.get('/api/airline-profiles', requireUnlocked, requireAuth, (req, res) => {
  const profiles = getAirlineProfiles().map(p => ({
    id: p.id,
    name: p.name,
    ssidPatterns: p.ssidPatterns.map(r => r.source),
    fields: p.fields,
    altFields: p.altFields || [],
    submitMethod: p.submitMethod,
    notes: p.notes,
    freeTier: p.freeTier,
    freeEntertainment: p.freeEntertainment
  }));
  res.json(profiles);
});

/**
 * GET /api/devices/:id/airline-wifi — Get ALL saved airline WiFi credentials for a device
 * Returns: { airlines: { southwest: {enabled, credentials, ...}, jetblue: {...} } }
 */
app.get('/api/devices/:id/airline-wifi', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  const row = await db.prepare("SELECT value FROM settings WHERE key=?").get('airline_wifi:' + req.params.id);
  if (!row) return res.json({ airlines: {} });
  const parsed = JSON.parse(row.value);
  // Migrate legacy single-airline format to multi-airline
  if (parsed.airline && !parsed.airlines) {
    return res.json({ airlines: { [parsed.airline]: parsed } });
  }
  res.json({ airlines: parsed.airlines || {} });
});

/**
 * POST /api/devices/:id/airline-wifi — Save ONE airline's credentials (add/update, doesn't overwrite others)
 * Body: { airline, credentials, enabled }
 */
app.post('/api/devices/:id/airline-wifi', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  const { airline, credentials, enabled } = req.body || {};
  if (!airline) return res.status(400).json({ error: 'Airline ID required' });
  
  const profile = getAirlineProfile(airline);
  if (!profile) return res.status(400).json({ error: 'Unknown airline profile' });
  
  // Load existing multi-airline config
  const row = await db.prepare("SELECT value FROM settings WHERE key=?").get('airline_wifi:' + req.params.id);
  let airlines = {};
  if (row) {
    const parsed = JSON.parse(row.value);
    // Migrate legacy format
    if (parsed.airline && !parsed.airlines) {
      airlines[parsed.airline] = parsed;
    } else {
      airlines = parsed.airlines || {};
    }
  }
  
  // Add/update this airline
  airlines[airline] = {
    enabled: enabled !== false,
    credentials: credentials || {},
    updatedAt: Date.now()
  };
  
  const cfg = { airlines };
  await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('airline_wifi:' + req.params.id, JSON.stringify(cfg));
  
  // Push full config to device
  emitToDevice(req.params.id, 'command', { command: 'set_airline_wifi', ...cfg });
  
  log('info', `Airline WiFi ${airline}: ${enabled !== false ? 'saved' : 'disabled'}`, { deviceId: req.params.id });
  res.json({ ok: true, airlines });
});

/**
 * DELETE /api/devices/:id/airline-wifi/:airline — Remove one airline's credentials
 */
app.delete('/api/devices/:id/airline-wifi/:airline', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  const { airline } = req.params;
  const row = await db.prepare("SELECT value FROM settings WHERE key=?").get('airline_wifi:' + req.params.id);
  if (!row) return res.json({ ok: true, airlines: {} });
  
  const parsed = JSON.parse(row.value);
  let airlines = parsed.airlines || {};
  delete airlines[airline];
  
  const cfg = { airlines };
  await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('airline_wifi:' + req.params.id, JSON.stringify(cfg));
  
  emitToDevice(req.params.id, 'command', { command: 'set_airline_wifi', ...cfg });
  
  log('info', `Airline WiFi ${airline}: removed`, { deviceId: req.params.id });
  res.json({ ok: true, airlines });
});

/**
 * POST /api/devices/:id/airline-wifi-login — Trigger airline WiFi login on device
 * Body: { airline } — which airline to login with (or auto-detect from SSID)
 */
app.post('/api/devices/:id/airline-wifi-login', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  const row = await db.prepare("SELECT value FROM settings WHERE key=?").get('airline_wifi:' + req.params.id);
  if (!row) return res.status(400).json({ error: 'No airline WiFi configured for this device' });
  
  const parsed = JSON.parse(row.value);
  const airlines = parsed.airlines || {};
  const targetAirline = req.body?.airline;
  
  // Find the airline to use
  let airlineId, airlineCfg;
  if (targetAirline && airlines[targetAirline]) {
    airlineId = targetAirline;
    airlineCfg = airlines[targetAirline];
  } else {
    // Use first enabled airline with credentials
    for (const [id, cfg] of Object.entries(airlines)) {
      if (cfg.enabled && Object.keys(cfg.credentials || {}).length > 0) {
        airlineId = id;
        airlineCfg = cfg;
        break;
      }
    }
  }
  
  if (!airlineId || !airlineCfg) {
    return res.status(400).json({ error: 'No enabled airline with credentials found' });
  }
  
  const profile = getAirlineProfile(airlineId);
  if (!profile) return res.status(400).json({ error: 'Unknown airline profile' });

  // The device performs the login against the portal IT actually sees — there is no static
  // per-airline login URL (tokenized/JS portals vary per aircraft vendor). It reports back
  // via `airline_login_test_result`.
  emitToDevice(req.params.id, 'command', {
    command: 'test_airline_login',
    airline: airlineId
  });

  log('info', `Airline WiFi login triggered: ${profile.name}`, { deviceId: req.params.id });
  res.json({ ok: true, airline: profile.name, note: 'Login will be attempted on the device against the inflight portal it is currently connected to' });
});

/**
 * POST /api/devices/:id/airline-wifi-detect — Auto-detect airline from current SSID
 * Returns the matching profile if the device is connected to a known airline WiFi.
 */
app.post('/api/devices/:id/airline-wifi-detect', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  const { ssid } = req.body || {};
  if (!ssid) return res.status(400).json({ error: 'SSID required' });
  
  const profile = detectAirline(ssid);
  if (!profile) return res.json({ detected: false });
  
  // Check if we have saved credentials for this airline (multi-airline format, with legacy
  // single-airline rows accepted for backwards compatibility)
  const row = await db.prepare("SELECT value FROM settings WHERE key=?").get('airline_wifi:' + req.params.id);
  const saved = row ? JSON.parse(row.value) : null;
  const savedAirlines = (saved && saved.airlines) || {};
  const savedCfg = savedAirlines[profile.id]
    || (saved && saved.airline === profile.id ? saved : null);
  const hasCredentials = !!savedCfg && savedCfg.enabled !== false && Object.keys(savedCfg.credentials || {}).length > 0;

  res.json({
    detected: true,
    profile: {
      id: profile.id,
      name: profile.name,
      fields: profile.fields,
      altFields: profile.altFields || [],
      notes: profile.notes,
      freeTier: profile.freeTier,
      freeEntertainment: profile.freeEntertainment
    },
    hasCredentials,
    savedCredentials: hasCredentials ? savedCfg.credentials : null
  });
});

/**
 * POST /api/airline-wifi-validate — Validate airline credentials against the airline's website
 * Body: { airline, credentials, useAlt }
 * Returns { valid: boolean|null, message: string }
 */
app.post('/api/airline-wifi-validate', requireUnlocked, requireAuth, async (req, res) => {
  const { airline, credentials, useAlt } = req.body || {};
  if (!airline) return res.status(400).json({ error: 'Airline ID required' });
  if (!credentials) return res.status(400).json({ error: 'Credentials required' });
  
  try {
    const result = await validateCredentials(airline, credentials, useAlt);
    res.json(result);
  } catch (e) {
    res.json({ valid: null, message: `Validation error: ${e.message}` });
  }
});
};
