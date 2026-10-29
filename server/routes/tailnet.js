// routes/tailnet.js - Tailnet Access: admin group management + per-device assignment.
// Extracted verbatim from server.js L8475-L8620 (see git log for that commit).
// The ctx below is the COMPLETE module-scope dependency set for this block;
// completeness is machine-checked by dev-tools/check-ctx.py.
module.exports = ({ TAILNET_UUID, TS_TAILNET, app, db, deviceOwnerInfo, emitToDevice, express, getTsApiToken, io, log, requireAdmin, requireAuth, requireUnlocked, sanitizeSubnet, sanitizeSubnets, tailnetCommand }) => {

  // Tailnet group CRUD (admin only).
  app.get('/api/admin/tailnet/groups', requireUnlocked, requireAdmin, async (req, res) => {
    const groups = (await db.prepare('SELECT id,name,subnets,created_at FROM tailnet_groups ORDER BY created_at').all());
    res.json(groups.map(g => ({ ...g, subnets: (() => { try { return JSON.parse(g.subnets); } catch { return []; } })() })));
  });

  app.post('/api/admin/tailnet/groups', requireUnlocked, requireAdmin, express.json(), async (req, res) => {
    const name    = (req.body?.name || '').trim();
    const subnets = sanitizeSubnets(req.body?.subnets);   // drops/normalises bad entries (e.g. ip:port)
    if (!name) return res.status(400).json({ error: 'name required' });
    const id = require('crypto').randomUUID();
    (await db.prepare('INSERT INTO tailnet_groups (id,name,subnets,created_at) VALUES (?,?,?,?)')
      .run(id, name, JSON.stringify(subnets), Date.now()));
    log('info', 'Tailnet group created', { id, name, subnets: subnets.length });
    res.json({ id, name, subnets });
  });

  app.put('/api/admin/tailnet/groups/:gid', requireUnlocked, requireAdmin, express.json(), async (req, res) => {
    const { gid } = req.params;
    const name    = (req.body?.name || '').trim();
    const subnets = sanitizeSubnets(req.body?.subnets);   // drops/normalises bad entries (e.g. ip:port)
    if (!name) return res.status(400).json({ error: 'name required' });
    const r = (await db.prepare('UPDATE tailnet_groups SET name=?,subnets=? WHERE id=?').run(name, JSON.stringify(subnets), gid));
    if (!r.changes) return res.status(404).json({ error: 'Group not found' });
    // Re-push updated subnets to all devices currently in this group.
    const cmd = await tailnetCommand(gid);
    const devices = (await db.prepare('SELECT id FROM devices WHERE tailnet_group_id=?').all(gid));
    for (const d of devices) emitToDevice(d.id, 'command', cmd);
    log('info', 'Tailnet group updated', { gid, name, subnets: subnets.length, pushed: devices.length });
    res.json({ ok: true });
  });

  app.delete('/api/admin/tailnet/groups/:gid', requireUnlocked, requireAdmin, async (req, res) => {
    const { gid } = req.params;
    // Clear assignments and notify affected devices before deleting.
    const devices = (await db.prepare('SELECT id FROM devices WHERE tailnet_group_id=?').all(gid));
    if (devices.length) {
      (await db.prepare('UPDATE devices SET tailnet_group_id=NULL WHERE tailnet_group_id=?').run(gid));
      const disableCmd = { command: 'set_tailnet', enabled: false };
      for (const d of devices) emitToDevice(d.id, 'command', disableCmd);
    }
    (await db.prepare('DELETE FROM tailnet_groups WHERE id=?').run(gid));
    log('info', 'Tailnet group deleted', { gid, devicesCleared: devices.length });
    res.json({ ok: true });
  });

  // Tailscale API proxy — server fetches device list on behalf of the browser (key never hits browser).
  app.get('/api/admin/tailnet/ts-devices', requireUnlocked, requireAdmin, async (req, res) => {
    const token = await getTsApiToken();
    if (!token) return res.json({ available: false });
    try {
      const r = await fetch(`https://api.tailscale.com/api/v2/tailnet/${TS_TAILNET}/devices`, {
        headers: { 'Authorization': `Bearer ${token}` }
      });
      if (!r.ok) return res.json({ available: false });
      const data = /** @type {any} */ (await r.json());
      const devices = (data.devices || []).map(d => ({
        name: d.name || d.hostname || '',
        addresses: d.addresses || [],
        tags: d.tags || [],
        routes: d.enabledRoutes || [],
      }));
      res.json({ available: true, devices });
    } catch (e) { res.json({ available: false }); }
  });

  // Per-device tailnet group assignment (admin only; blocked on ZK-owned devices).
  app.get('/api/devices/:id/tailnet', requireUnlocked, requireAuth, requireAdmin, async (req, res) => {
    const device = (await db.prepare('SELECT tailnet_group_id FROM devices WHERE id=?').get(req.params.id));
    if (!device) return res.status(404).json({ error: 'Device not found' });
    if (!device.tailnet_group_id) return res.json({ group_id: null, group_name: null, subnets: [] });
    const group = (await db.prepare('SELECT name,subnets FROM tailnet_groups WHERE id=?').get(device.tailnet_group_id));
    res.json({
      group_id: device.tailnet_group_id,
      group_name: group?.name || null,
      subnets: group ? (() => { try { return JSON.parse(group.subnets); } catch { return []; } })() : [],
    });
  });

  app.patch('/api/devices/:id/tailnet', requireUnlocked, requireAuth, requireAdmin, express.json(), async (req, res) => {
    const deviceId  = req.params.id;
    const groupId   = req.body?.group_id || null;
    // Block assigning tailnet access to a ZK-owned (public user) device.
    const { isZk } = await deviceOwnerInfo(deviceId);
    if (isZk) return res.status(403).json({ error: 'Tailnet access cannot be assigned to a private (ZK-owned) device' });
    if (groupId) {
      const group = (await db.prepare('SELECT id FROM tailnet_groups WHERE id=?').get(groupId));
      if (!group) return res.status(404).json({ error: 'Tailnet group not found' });
    }
    (await db.prepare('UPDATE devices SET tailnet_group_id=? WHERE id=?').run(groupId, deviceId));
    const cmd = groupId ? await tailnetCommand(groupId) : { command: 'set_tailnet', enabled: false };
    emitToDevice(deviceId, 'command', cmd);
    io.emit('devices_updated');
    log('info', `Tailnet group ${groupId ? 'assigned' : 'cleared'}`, { deviceId, groupId });
    res.json({ ok: true });
  });
};
