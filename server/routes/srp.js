// routes/srp.js - SRP / AppLocker audit + deploy (Hop-2 via bastionClient).
// Extracted verbatim from server.js L7900-L7954.
// The only transform applied is require('./bastionClient') ->
// require('../bastionClient'): that specifier must resolve to server/bastionClient.js
// from one directory deeper. Everything else is byte-identical.
module.exports = ({ app, fleetFanOut, log, requireAuth, requireDeviceAccess, requireDeviceController, requireFleetAccess, requireRemoteAssistDevice, requireUnlocked, stripDangerousWildcardFolders }) => {
// ── SRP (Software Restriction Policies) — audit & deploy ─────────────────────
app.post('/api/devices/:id/remote-assist/srp/audit', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../bastionClient');
  try { res.json((await bastionClient.srpAudit(req.params.id))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'SRP audit failed' }); }
});
app.get('/api/devices/:id/remote-assist/srp/audit-status', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../bastionClient');
  try { res.json((await bastionClient.srpAuditStatus(req.params.id))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'SRP audit status fetch failed' }); }
});
app.post('/api/devices/:id/remote-assist/srp/deploy', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../bastionClient');
  const body = req.body || {};
  const { kept, rejected } = stripDangerousWildcardFolders(body.allowedPaths);
  try {
    const result = (await bastionClient.srpDeploy(req.params.id, { ...body, allowedPaths: kept }));
    if (rejected.length) result.rejectedFolders = [...new Set([...(result.rejectedFolders || []), ...rejected])];
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'SRP deploy failed' }); }
});
app.get('/api/devices/:id/remote-assist/srp/install-mode-events', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../bastionClient');
  try { res.json((await bastionClient.srpInstallModeEvents(req.params.id))); }
  catch (e) { res.status(502).json({ ok: false, error: e.bastionError || e.message || 'Failed to read Install Mode events' }); }
});
app.get('/api/devices/:id/remote-assist/srp/activity', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../bastionClient');
  try { res.json((await bastionClient.srpActivity(req.params.id))); }
  catch (e) { res.status(502).json({ ok: false, error: e.bastionError || e.message || 'Failed to read AppLocker activity' }); }
});
app.post('/api/devices/:id/remote-assist/srp/publisher-info', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../bastionClient');
  try { res.json((await bastionClient.srpPublisherInfo(req.params.id, (req.body || {}).path))); }
  catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'Publisher info lookup failed' }); }
});

};
