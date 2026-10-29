module.exports = ({ app, db, log, raUpdateTargetForDevice, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked }) => {
// "Up to them when" button — reachable by the device's owner OR an admin via the existing
// requireDeviceAccess/requireDeviceController/requireRemoteAssistDevice chain (same as every other
// per-device RA route above), so no extra gating is needed here: ownership already determines who
// can even reach this route.
 app.post('/api/devices/:id/remote-assist/agent-update', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const target = (await raUpdateTargetForDevice(req.params.id));
  if (!target) return res.status(400).json({ error: 'Device has no linked account' });
  const bastionClient = require('../../bastionClient');
  try {
    const result = (await bastionClient.agentUpdate(req.params.id, target.accountId, target.adminAgent));
    log('info', 'Remote-assist agent update triggered', { deviceId: req.params.id, ok: result.ok, from: result.from_version, to: result.to_version });
    res.json(result);
  } catch (e) {
    log('error', 'Remote-assist agent update failed', { deviceId: req.params.id, error: e.message });
    res.status(502).json({ error: 'Agent update failed', detail: e.message });
  }
});

// TOTAL agent nuke (2.0.3) — dispatches the bastion's nuke (feature reverts + SYSTEM --nuke task
// that removes the agent and EVERYTHING it placed on the box). The box's sshd dies seconds later,
// so ok means DISPATCHED, not completed; the device row is then unbound (owner_user_id=NULL),
// all sessions ended, and Hop-2 keys dropped — the row stays for forensics, a fresh download
// re-installs the agent. IRREVERSIBLE: guarded by an explicit confirm on the client.
app.post('/api/devices/:id/remote-assist/nuke', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const deviceId = req.params.id;
  try {
    const result = (await bastionClient.nukeAgent(deviceId));
    // 2.0.4 (found live 2026-08-05 on the test VM): the bastion used to report ok for a nuke that
    // never happened (its PS1 always exited 0), so the device got unbound while the box stayed
    // fully installed. NEVER unbind while the response carries an error, even if ok is truthy.
    if (!result.ok || result.error) {
      log('error', 'Remote-assist nuke dispatch failed', { deviceId, error: result.error || 'unknown error' });
      return res.status(400).json({ error: 'Nuke dispatch failed', detail: result.error || 'unknown error' });
    }
    // Unbind + revoke standing access regardless of what the box does next.
    try {
      (await db.prepare("UPDATE devices SET owner_user_id=NULL, public_key=NULL, online=0, last_seen=? WHERE id=?").run(Date.now(), deviceId));
      (await db.prepare("UPDATE remote_assist_sessions SET status='ended', ended_at=? WHERE device_id=? AND status='active'").run(Date.now(), deviceId));
      (await db.prepare('DELETE FROM ra_hop2_keys WHERE device_id=?').run(deviceId));
      (await db.prepare("DELETE FROM settings WHERE key='ra_auto:' || ?").run(deviceId));
    } catch (e) { log('warn', 'nuke post-cleanup error', { deviceId, error: e.message }); }
    log('info', 'Remote-assist NUKE dispatched + device unbound', { deviceId });
    res.json({ ok: true, dispatched: true, unbound: true });
  } catch (e) {
    log('error', 'Remote-assist nuke error', { deviceId, error: e.message });
    res.status(502).json({ error: 'Nuke failed', detail: e.message });
  }
});
};
