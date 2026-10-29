// routes/remote-assist/remote-assist-fleet-actions.js — Windows Fleet fan-out actions (it-audit, winupdate,
// telemetry, sentry, defender-exclusion, EDR, EDR isolate, arp-scan, arp-sweep-watch, powershell).
// Extracted verbatim from server.js L7104-L7238 (10 routes).
// The only transform applied is require('./bastionClient') -> require('../../bastionClient'),
// because that specifier must resolve to server/bastionClient.js from two directories deeper.
module.exports = ({ app, emitToDevice, fleetFanOut, ingestArpScanResult, log, requireAuth, requireFleetAccess, requireUnlocked, setArpSweepWatchEnabled, setEdrEnabled, setWinUpdateForceActive }) => {
app.post('/api/remote-assist/fleet/it-audit/run', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const groupId = req.body?.groupId || null;
  const bastionClient = require('../../bastionClient');
  const results = await fleetFanOut(req, id => bastionClient.runAudit(id), groupId);
  log('info', 'Fleet IT Mode Audit run', { groupId, deviceCount: results.length });
  res.json({ ok: true, results });
});

// action is passed straight through to bastionClient.winUpdate exactly like the per-device route
// does (server.js never allowlists it there either — bastion-side is the actual gate).
app.post('/api/remote-assist/fleet/winupdate/:action', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const action = req.params.action;
  const groupId = req.body?.groupId || null;
  const bastionClient = require('../../bastionClient');
  const results = await fleetFanOut(req, async id => {
    const r = (await bastionClient.winUpdate(id, action, req.body || {}));
    // Same stale -L-forward fix as the per-device route — see its comment.
    if (action === 'enable' && r?.ok) emitToDevice(id, 'command', { command: 'restart_ra_tunnel' });
    if (action === 'force-start' && r?.ok) (await setWinUpdateForceActive(id, true));
    if (action === 'security-start' && r?.ok) (await setWinUpdateForceActive(id, true));
    if (action === 'security-schedule' && r?.ok) (await setWinUpdateForceActive(id, !(req.body || {}).clear));
    if (action === 'force-cancel' && r?.ok) (await setWinUpdateForceActive(id, false));
    return r;
  }, groupId);
  log('info', 'Fleet Windows Update action', { action, groupId, deviceCount: results.length });
  res.json({ ok: true, results });
});

// action is passed straight through to bastionClient.blockTelemetry exactly like the per-device
// route does (server.js never allowlists it there either — bastion-side is the actual gate).
app.post('/api/remote-assist/fleet/telemetry/:action', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const action = req.params.action;
  const groupId = req.body?.groupId || null;
  const bastionClient = require('../../bastionClient');
  const results = await fleetFanOut(req, id => bastionClient.blockTelemetry(id, action, req.body || {}), groupId);
  log('info', 'Fleet telemetry action', { action, groupId, deviceCount: results.length });
  res.json({ ok: true, results });
});

// Sentry Mode fleet action — enable/disable across all controllable devices.
app.post('/api/remote-assist/fleet/sentry/:action', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const action = req.params.action;
  const groupId = req.body?.groupId || null;
  const bastionClient = require('../../bastionClient');
  if (action === 'enable') {
    const results = await fleetFanOut(req, id => bastionClient.sentryEnable(id, req.body || {}), groupId);
    log('info', 'Fleet sentry enable', { groupId, deviceCount: results.length });
    res.json({ ok: true, results });
  } else if (action === 'disable') {
    const results = await fleetFanOut(req, id => bastionClient.sentryDisable(id), groupId);
    log('info', 'Fleet sentry disable', { groupId, deviceCount: results.length });
    res.json({ ok: true, results });
  } else {
    res.status(400).json({ error: 'Unknown sentry fleet action' });
  }
});

app.post('/api/remote-assist/fleet/defender-exclusion/:action', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const action = req.params.action;
  const groupId = req.body?.groupId || null;
  const bastionClient = require('../../bastionClient');
  const results = await fleetFanOut(req, id => bastionClient.defenderExclusion(id, action, req.body || {}), groupId);
  log('info', 'Fleet defender exclusion action', { action, groupId, deviceCount: results.length });
  res.json({ ok: true, results });
});

app.post('/api/remote-assist/fleet/edr/:action', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const enable = req.params.action !== 'disable';
  const groupId = req.body?.groupId || null;
  const bastionClient = require('../../bastionClient');
  const results = await fleetFanOut(req, async id => {
    const r = enable ? (await bastionClient.edrEnable(id)) : (await bastionClient.edrDisable(id));
    if (r?.ok) {
      (await setEdrEnabled(id, enable));
      // Same stale -L-forward fix as the per-device EDR-enable route — see its comment.
      if (enable) emitToDevice(id, 'command', { command: 'restart_ra_tunnel' });
    }
    return r;
  }, groupId);
  log('info', 'Fleet EDR toggle', { enable, groupId, deviceCount: results.length });
  res.json({ ok: true, results });
});

// "Isolate all" / "Restore all" across every controllable device — deliberately its own fleet
// route rather than folded into the toggle above (isolation is a much heavier action than
// enable/disable and deserves its own confirm-gated button, same posture as Windows Update
// total-disable's own dedicated fleet route).
app.post('/api/remote-assist/fleet/edr-isolate/:action', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const block = req.params.action !== 'unblock';
  const groupId = req.body?.groupId || null;
  const bastionClient = require('../../bastionClient');
  const results = await fleetFanOut(req, id => block ? bastionClient.edrIsolateBlock(id) : bastionClient.edrIsolateUnblock(id), groupId);
  log('info', 'Fleet EDR isolation toggle', { block, groupId, deviceCount: results.length });
  res.json({ ok: true, results });
});

app.post('/api/remote-assist/fleet/arp-scan', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const groupId = req.body?.groupId || null;
  const bastionClient = require('../../bastionClient');
  const results = await fleetFanOut(req, async id => {
    const r = await bastionClient.arpScan(id);
    if (r?.ok) (await ingestArpScanResult(id, r));
    return r;
  }, groupId);
  log('info', 'Fleet ARP scan', { groupId, deviceCount: results.length });
  res.json({ ok: true, results });
});

app.post('/api/remote-assist/fleet/arp-sweep-watch', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  const enable = !!req.body?.enable;
  const groupId = req.body?.groupId || null;
  const results = await fleetFanOut(req, async id => {
    const r = await (enable ? bastionClient.arpSweepWatchEnable(id) : bastionClient.arpSweepWatchDisable(id));
    if (r?.ok) (await setArpSweepWatchEnabled(id, enable));
    return r;
  }, groupId);
  log('info', 'Fleet ARP sweep watch toggle', { enable, groupId, deviceCount: results.length });
  res.json({ ok: true, results });
});

// Arbitrary PowerShell across every controllable device at once. This is unrestricted remote code
// execution on every enrolled Windows box — logged (truncated preview) for an audit trail given
// the blast radius; see bastionClient.runPowerShell()/bastion-web.py's _run_powershell_over_hop2()
// for the transport (base64 -EncodedCommand, never a raw/interpolated string).
app.post('/api/remote-assist/fleet/powershell', requireUnlocked, requireAuth, requireFleetAccess, async (req, res) => {
  const script = (req.body?.script || '').toString();
  if (!script.trim()) return res.status(400).json({ ok: false, error: 'script required' });
  const timeoutSec = req.body?.timeoutSec;
  const groupId = req.body?.groupId || null;
  const bastionClient = require('../../bastionClient');
  const results = await fleetFanOut(req, id => bastionClient.runPowerShell(id, script, { timeoutSec }), groupId);
  log('info', 'Fleet PowerShell run', { groupId, deviceCount: results.length, scriptPreview: script.slice(0, 200) });
  res.json({ ok: true, results });
});
};
