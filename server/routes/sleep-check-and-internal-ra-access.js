// routes/sleep-check-and-internal-ra-access.js — deep-sleep wake poll (device-signature auth)
// + INTERNAL_KEY-authed bastion ownership gate. Both pre-auth/pre-unlock by design (see comments).
module.exports = ({ app, authenticateDeviceRequest, db, deviceOwnerInfo, express }) => {
// Device polls this while in deep sleep to check whether it should wake up.
// Registered BEFORE app.use(requireUnlocked): deep_sleep and theft_mode are plaintext
// columns; device signature auth doesn't need the enc key. Placing it here prevents a
// startup race where server.listen() fires before tryAutoUnlock() completes — a 503
// response would be treated as wake=false, leaving sleeping devices indefinitely stuck
// across rolling-restart deploys in the 3-replica HA setup.
// Must also be before app.use(requireAuth): device uses key-based auth, not session cookies.
app.get('/api/devices/:id/sleep-check', async (req, res) => {
  if (!(await authenticateDeviceRequest(req)))
    return res.status(401).json({ error: 'unauthorized' });
  // SECURITY (IDOR): the signature only proves possession of the x-device-id key. Bind the lookup
  // to that authenticated device so an enrolled device can't read ANOTHER device's deep_sleep /
  // theft_mode state by passing a different :id in the path.
  if (req.headers['x-device-id'] !== req.params.id)
    return res.status(403).json({ error: 'forbidden' });
  const device = (await db.prepare('SELECT deep_sleep, theft_mode FROM devices WHERE id=?').get(req.params.id));
  if (!device) return res.status(404).json({ error: 'not found' });
  res.json({ wake: device.deep_sleep === 0 || device.theft_mode === 1 });
});

// ── Bastion → server ownership gate (INTERNAL_KEY-authed, fail-closed) ─────────────────────────
// Placed BEFORE requireUnlocked/requireAuth: this is an internal service-to-service route, not a
// user-facing endpoint. The bastion authenticates with the shared INTERNAL_KEY secret. Session-
// level auth would reject the bastion's request (it has no session cookie), so this runs upstream
// of every session middleware. See the ZK Security invariant rows in docs/ARCHITECTURE.md for the design.
app.post('/api/internal/ra-access', express.json(), async (req, res) => {
  const key = (req.get('x-api-key') || req.get('X-Api-Key') || '').toString();
  if (!key) return res.status(401).json({ error: 'Missing API key' });
  try {
    const internalKey = require('fs').readFileSync('/run/secrets/sentinel_bastion_internal_key', 'utf8').trim();
    if (!internalKey || key !== internalKey)
      return res.status(401).json({ error: 'Invalid API key' });
  } catch {
    return res.status(503).json({ error: 'Internal key not configured — gate is fail-closed' });
  }

  const label = String(req.body?.label || '');
  if (!label) return res.status(400).json({ error: 'Missing label' });

  const row = (await db.prepare(
    "SELECT device_id FROM remote_assist_sessions WHERE bastion_label=? ORDER BY created_at DESC LIMIT 1"
  ).get(label));
  if (!row) return res.status(404).json({ error: 'Unknown label — no session row with that bastion_label' });

  const { isZk } = await deviceOwnerInfo(row.device_id);
  return res.json({ allow: !isZk, zk_owned: isZk, device_id: row.device_id });
});
};
