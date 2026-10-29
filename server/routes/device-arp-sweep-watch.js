// routes/device-arp-sweep-watch.js — per-device ARP sweep watch status/toggle (GET/POST
// /api/devices/:id/remote-assist/arp-sweep-watch). Extracted verbatim from server.js L4569-L4585.
// The only transform applied is require('./bastionClient') -> require('../bastionClient') at both
// in-route sites, because that specifier must resolve to server/bastionClient.js from one
// directory deeper.
module.exports = ({ app, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked, setArpSweepWatchEnabled }) => {
app.get('/api/devices/:id/remote-assist/arp-sweep-watch', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../bastionClient');
  try {
    const result = (await bastionClient.arpSweepWatchStatus(req.params.id));
    if (result?.ok) (await setArpSweepWatchEnabled(req.params.id, !!result.installed));
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'ARP sweep watch status fetch failed' }); }
});
app.post('/api/devices/:id/remote-assist/arp-sweep-watch', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../bastionClient');
  const enable = !!req.body?.enable;
  try {
    const result = (await (enable ? bastionClient.arpSweepWatchEnable(req.params.id) : bastionClient.arpSweepWatchDisable(req.params.id)));
    if (result?.ok) (await setArpSweepWatchEnabled(req.params.id, enable));
    res.json(result);
  } catch (e) { res.status(502).json({ error: e.bastionError || e.message || 'ARP sweep watch toggle failed' }); }
});
};
