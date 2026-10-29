module.exports = ({ app, XRAY_VPN_UUID, emitToDevice, getVpn, io, log, normalizeVpn, requireAuth, requireDeviceAccess, requireDeviceController, requireUnlocked, setVpn, vpnCommand }) => {
app.get('/api/devices/:id/vpn', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  res.json(await getVpn(req.params.id));
});
app.post('/api/devices/:id/vpn', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  if (!XRAY_VPN_UUID) return res.status(503).json({ error: 'VPN egress not configured on the server (missing sentinel_xray_vpn_uuid secret)' });
  const cfg = normalizeVpn(req.body || {});
  (await setVpn(req.params.id, cfg));
  emitToDevice(req.params.id, 'command', vpnCommand(cfg));
  io.emit('devices_updated');
  log('info', `Device VPN ${cfg.force ? 'FORCED-ON (all traffic)' : cfg.enabled ? 'open-WiFi auto' : cfg.tailnetOnly ? 'tailnet-only (split tunnel)' : 'disabled'}`, { deviceId: req.params.id });
  res.json({ ok: true, ...cfg });
});
};
