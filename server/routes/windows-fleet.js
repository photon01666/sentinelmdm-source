module.exports = ({ app, db, decryptText, fleetFanOut, log, raUpdateTargetForDevice, requireAdmin, requireAuth, requireFleetAccess, requireUnlocked, stripDangerousWildcardFolders }) => {
app.post('/api/remote-assist/fleet/install-mode', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const mode = req.body?.mode === 'audit' ? 'audit' : 'enforce';
  const groupId = req.body?.groupId || null;
  const bastionClient = require('../bastionClient');
  const results = await fleetFanOut(req, id => bastionClient.srpDeploy(id, { allowedPaths: [], mode }), groupId);
  log('info', 'Fleet Install Mode change', { mode, groupId, deviceCount: results.length });
  res.json({ ok: true, mode, results });
});

// Fleet "Update Agent" — same fleetFanOut() gating as every other fleet action, which is what
// makes the public-vs-admin push gating requirement fall out for free: an admin caller's fleet
// devices are exactly the non-ZK/admin-fleet set (fleetControllableRemoteAssistDeviceIds() never
// includes a ZK device for a non-owning caller), and a public caller's fleet devices are exactly
// their OWN devices — clicking this themselves is still "up to them when", never an admin push.
app.post('/api/remote-assist/fleet/agent-update', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const groupId = req.body?.groupId || null;
  const bastionClient = require('../bastionClient');
  const results = await fleetFanOut(req, async id => {
    const target = (await raUpdateTargetForDevice(id));
    if (!target) throw new Error('no linked account');
    return bastionClient.agentUpdate(id, target.accountId, target.adminAgent);
  }, groupId);
  log('info', 'Fleet agent update triggered', { groupId, deviceCount: results.length, caller: req.session?.username });
  res.json({ ok: true, results });
});

// Admin-only "Windows Agent Update" panel data — deliberately a SEPARATE panel/route from the
// Android APK "REMOTE APK UPDATE" panel's /api/admin/mass-update (they used to leak into each
// other — see ANDROID_ONLY_DEVICES above). Lists every RA device with its live installed/latest
// version so admin has full fleet visibility, but `pushable` is only true for admin-fleet/unowned
// devices — a public-owned device's row comes back with pushable:false + an explanatory note so
// the WebUI can grey out its push control instead of hiding the row entirely. Admin force-pushing
// to a public user's own device is never exposed here, by design (see the fleet route above).
app.get('/api/admin/remote-assist-updates', requireUnlocked, requireAdmin, async (req, res) => {
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return res.status(503).json({ error: 'Bastion bridge not configured on the server' });
  const rows = (await db.prepare(
    "SELECT d.id, d.name, d.owner_user_id, u.account_type FROM devices d LEFT JOIN users u ON d.owner_user_id=u.id " +
    "WHERE d.platform='windows' AND d.agent_kind='remote_assist' ORDER BY d.name"
  ).all());
  let latestVersion = null;
  try { latestVersion = (await bastionClient.getLatestAgentVersion())?.version || null; } catch {}
  const devices = await Promise.all(rows.map(async d => {
    let status = {};
    try { status = (await bastionClient.sessionStatus(d.id)); } catch (e) { status = {}; }
    const isPublicOwned = d.account_type === 'public';
    return {
      id: d.id,
      name: decryptText(d.name) || d.id,
      connected: !!status.connected,
      installedVersion: status.agent_version || null,
      latestVersion: status.latest_agent_version || latestVersion,
      updateAvailable: !!status.agent_update_available,
      pushable: !!d.owner_user_id && !isPublicOwned,
      ownerNote: !d.owner_user_id ? 'No linked account' : isPublicOwned ? 'Owner-controlled — only the device owner can trigger this update' : null,
    };
  }));
  res.json({ latestVersion, devices });
});

app.get('/api/remote-assist/fleet/what-ran', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const groupId = req.query?.groupId || null;
  const bastionClient = require('../bastionClient');
  const results = await fleetFanOut(req, id => bastionClient.srpInstallModeEvents(id), groupId);
  // Merge + dedupe by literal path across devices, for a single fleet-wide "select all -> approve"
  // list — the same path (e.g. a common installer temp path) commonly shows up on several boxes.
  const merged = new Map();
  for (const r of results) {
    if (!r.ok || !Array.isArray(r.data?.paths)) continue;
    for (const p of r.data.paths) {
      if (!p?.path) continue;
      const cur = merged.get(p.path) || { path: p.path, count: 0, lastSeen: 0, deviceIds: [] };
      cur.count += p.count || 0;
      cur.lastSeen = Math.max(cur.lastSeen, p.lastSeen || 0);
      if (!cur.deviceIds.includes(r.deviceId)) cur.deviceIds.push(r.deviceId);
      merged.set(p.path, cur);
    }
  }
  res.json({ ok: true, devices: results, merged: [...merged.values()] });
});

// Same live-AppLocker-log source as the per-device "Check Blocked & Ran" button
// (bastionClient.srpActivity / bastion's /srp/activity — see the per-device route above) —
// continuous Enforce-mode 8002/8003/8004 events, no Install Mode toggle, no full filesystem scan.
// Replaces the old /what-ran fleet route as the fleet panel's primary view; /what-ran itself is
// left in place (still reachable, still backs the Install-Mode-only "what would have run" case)
// but the Windows Fleet panel no longer calls it.
app.get('/api/remote-assist/fleet/srp/activity', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const groupId = req.query?.groupId || null;
  const bastionClient = require('../bastionClient');
  const results = await fleetFanOut(req, id => bastionClient.srpActivity(id), groupId);
  // Merge + dedupe by literal path across devices, separately for blocked vs. already-allowed/ran —
  // same shape as /what-ran's `merged` so the fleet UI can reuse the same select-all/approve flow.
  const mergeGroup = (key) => {
    const merged = new Map();
    for (const r of results) {
      if (!r.ok || !Array.isArray(r.data?.[key])) continue;
      for (const p of r.data[key]) {
        if (!p?.path) continue;
        const cur = merged.get(p.path) || { path: p.path, count: 0, firstSeen: 0, lastSeen: 0, deviceIds: [] };
        cur.count += p.count || 0;
        cur.firstSeen = cur.firstSeen ? Math.min(cur.firstSeen, p.firstSeen || cur.firstSeen) : (p.firstSeen || 0);
        cur.lastSeen = Math.max(cur.lastSeen, p.lastSeen || 0);
        if (!cur.deviceIds.includes(r.deviceId)) cur.deviceIds.push(r.deviceId);
        merged.set(p.path, cur);
      }
    }
    return [...merged.values()];
  };
  res.json({ ok: true, devices: results, merged: mergeGroup('blocked'), mergedRan: mergeGroup('ran') });
});

// Approves the given literal paths on EVERY device the caller controls (not only the ones that
// reported them, and scoped to `groupId` when one is given) — deliberate fleet-consistency
// choice: an app approved on one machine is meant to stop getting blocked fleet-wide (or
// group-wide), not just on whichever box happened to run it first. Backs both the old
// Install-Mode-events flow and the new "Check Blocked & Ran" fleet panel.

// ── Remote Assist fleet actions (IT audit, winupdate, telemetry, sentry, defender, EDR, arp, powershell) — routes/remote-assist-fleet-actions.js ──
// ── Registered here, immediately before the fleet block, to preserve the exact
// route-registration order it had before extraction. It uses the SRP wildcard helper,
// which now lives at module scope above and is injected into routes/srp.js. ──
app.post('/api/remote-assist/fleet/what-ran/approve', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const rawPaths = Array.isArray(req.body?.paths) ? req.body.paths.map(String).filter(Boolean) : [];
  const { kept: paths, rejected } = stripDangerousWildcardFolders(rawPaths);
  if (!paths.length) return res.status(400).json({ ok: false, error: rejected.length ? `all requested paths are common malware drop locations (Desktop/Downloads/Public/Temp) — never wildcard-approved: ${rejected.join(', ')}` : 'paths required' });
  const groupId = req.body?.groupId || null;
  const bastionClient = require('../bastionClient');
  const results = await fleetFanOut(req, id => bastionClient.srpDeploy(id, { allowedPaths: paths }), groupId);
  log('info', 'Fleet Show-What-Ran approve', { pathCount: paths.length, rejectedCount: rejected.length, groupId, deviceCount: results.length });
  res.json({ ok: true, results, rejectedFolders: rejected.length ? rejected : undefined });
});
};
