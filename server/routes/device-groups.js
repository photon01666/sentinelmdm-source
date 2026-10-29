// routes/device-groups.js - Sidebar device groups (WebUI organization only): list/create/
// rename/delete groups and assign a device to a group (admin + public; business_sub reads only).
// Extracted verbatim from server.js (see git log for that commit).
// The ctx below is the COMPLETE module-scope dependency set for this block;
// completeness is machine-checked by dev-tools/check-ctx.py.
module.exports = ({ app, crypto, db, deviceOwnerInfo, express, groupOwnerKey }) => {
function requireGroupManager(req, res, next) {
  if (req.session?.role === 'admin' || req.session?.account_type === 'public') return next();
  res.status(403).json({ error: 'Not allowed' });
}

// List the groups in the caller's scope (their own, or — for a business sub-user — the fleet
// owner's), each with its member device ids. groupOwnerKey() already returns null for anyone with
// no scope at all (admin_created sub-users), so that null IS the access check; a separate
// role==='admin'||account_type==='public' gate here would re-exclude business_sub after
// groupOwnerKey resolved them and silently reinstate the empty-sidebar bug.
app.get('/api/device-groups', async (req, res) => {
  const owner = groupOwnerKey(req);
  if (!owner) return res.json([]);
  const rows = (await db.prepare(
    'SELECT g.id, g.name, g.sort_order, d.id AS device_id ' +
    'FROM device_groups g LEFT JOIN devices d ON d.ui_group_id = g.id ' +
    'WHERE g.owner_key = ? ORDER BY g.sort_order, g.created_at'
  ).all(owner));
  const map = new Map();
  for (const r of rows) {
    if (!map.has(r.id)) map.set(r.id, { id: r.id, name: r.name, sort_order: r.sort_order, device_ids: [] });
    if (r.device_id) map.get(r.id).device_ids.push(r.device_id);
  }
  res.json([...map.values()]);
});

app.post('/api/device-groups', requireGroupManager, express.json(), async (req, res) => {
  const owner = groupOwnerKey(req);
  if (!owner) return res.status(400).json({ error: 'no owner' });
  const name = (req.body?.name || '').toString().trim().slice(0, 60);
  if (!name) return res.status(400).json({ error: 'name required' });
  const id = crypto.randomUUID();
  const maxRow = (await db.prepare('SELECT COALESCE(MAX(sort_order),0) AS m FROM device_groups WHERE owner_key=?').get(owner));
  const sort = (Number(maxRow?.m) || 0) + 1;
  (await db.prepare('INSERT INTO device_groups (id,owner_key,name,sort_order,created_at) VALUES (?,?,?,?,?)')
    .run(id, owner, name, sort, Date.now()));
  res.json({ id, name, sort_order: sort, device_ids: [] });
});

app.patch('/api/device-groups/:id', requireGroupManager, express.json(), async (req, res) => {
  const owner = groupOwnerKey(req);
  const name = (req.body?.name || '').toString().trim().slice(0, 60);
  if (!name) return res.status(400).json({ error: 'name required' });
  const r = (await db.prepare('UPDATE device_groups SET name=? WHERE id=? AND owner_key=?').run(name, req.params.id, owner));
  if (!r.changes) return res.status(404).json({ error: 'Group not found' });
  res.json({ ok: true });
});

app.delete('/api/device-groups/:id', requireGroupManager, async (req, res) => {
  const owner = groupOwnerKey(req);
  // Scope the delete to the owner; only clear membership if the group was actually theirs.
  const r = (await db.prepare('DELETE FROM device_groups WHERE id=? AND owner_key=?').run(req.params.id, owner));
  if (!r.changes) return res.status(404).json({ error: 'Group not found' });
  (await db.prepare('UPDATE devices SET ui_group_id=NULL WHERE ui_group_id=?').run(req.params.id));
  res.json({ ok: true });
});

// Assign / clear a device's sidebar group. group_id=null clears it. The caller must control the
// device (admin → fleet/non-ZK device; public → a device they own) and own the target group.
app.patch('/api/devices/:id/ui-group', requireGroupManager, express.json(), async (req, res) => {
  const owner = groupOwnerKey(req);
  const deviceId = req.params.id;
  const groupId = req.body?.group_id || null;
  const dev = (await db.prepare('SELECT id FROM devices WHERE id=?').get(deviceId));
  if (!dev) return res.status(404).json({ error: 'Device not found' });
  const { isZk, ownerUserId } = await deviceOwnerInfo(deviceId);
  if (req.session.role === 'admin') {
    if (isZk) return res.status(403).json({ error: 'Admin groups apply to fleet devices only' });
  } else {
    // public user: must own the device
    if (!(req.session.account_type === 'public' && ownerUserId === req.session.userId))
      return res.status(403).json({ error: 'Not your device' });
  }
  if (groupId) {
    const g = (await db.prepare('SELECT id FROM device_groups WHERE id=? AND owner_key=?').get(groupId, owner));
    if (!g) return res.status(404).json({ error: 'Group not found' });
  }
  (await db.prepare('UPDATE devices SET ui_group_id=? WHERE id=?').run(groupId, deviceId));
  res.json({ ok: true });
});
};
