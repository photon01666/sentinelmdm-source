// routes/remote-assist/remote-assist-powershell-and-hop2.js — per-device Remote Assist direct access: run a
// one-shot PowerShell script (POST) or build the copy-paste OpenSSH ProxyJump Hop-2 command (GET).
// Extracted verbatim from server.js L5525-L5577 (2 routes).
// The only transform applied is require('./bastionClient') -> require('../../bastionClient') at both
// in-route sites, because that specifier must resolve to server/bastionClient.js from
// two directories deeper.
module.exports = ({ app, db, log, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked }) => {
// Single-device counterpart to the Windows Fleet menu's /api/remote-assist/fleet/powershell (that
// one fans out via requireFleetAccess/fleetControllableRemoteAssistDeviceIds; this scopes to ONE
// device via the standard per-device middleware chain, same as every other srp/* route above).
// Added as the missing piece the AI Live Chat feature's run_powershell tool call needs — the
// bastionClient.runPowerShell() primitive already existed (used only by the fleet route until now).
app.post('/api/devices/:id/remote-assist/powershell', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const script = (req.body?.script || '').toString();
  if (!script.trim()) return res.status(400).json({ ok: false, error: 'script required' });
  const timeoutSec = req.body?.timeoutSec;
  const bastionClient = require('../../bastionClient');
  try { res.json((await bastionClient.runPowerShell(req.params.id, script, { timeoutSec }))); }
  catch (e) { res.status(502).json({ ok: false, error: e.bastionError || e.message || 'PowerShell run failed' }); }
});

// No in-browser terminal (deliberate — there is no trustworthy browser-side SSH client to hold a
// ZK-owned device's private key; see the SentinelRemoteAssist plan doc's terminal-library
// decision). Instead: a plain, standard OpenSSH ProxyJump command the user copies and pastes into
// their OWN terminal/cmd/PowerShell — no custom relay, no WASM, nothing running server-side that
// touches the SSH stream at all. Mirrors this codebase's existing Hop-1 (Windows agent -> bastion
// reverse tunnel) / Hop-2 (admin -> bastion's loopback-forwarded port -> Windows box) terminology
// — today Hop-2 requires `docker exec` into the bastion container; this exposes the equivalent
// access as a single portable `ssh -J` command instead, scoped per-session via a bastion-side
// authorized_keys grant restricted to ONLY that session's forwarded port (permitopen, no shell).
app.get('/api/devices/:id/remote-assist/hop2-command', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const sessionToken = (req.query?.sessionToken || '').toString();
  const row = sessionToken ? (await db.prepare('SELECT * FROM remote_assist_sessions WHERE id=? AND device_id=?').get(sessionToken, req.params.id)) : null;
  if (!row?.ssh_public_key || row.status !== 'active' || !row.bastion_port)
    return res.status(400).json({ error: 'No active remote-assist session — call /remote-assist/start first' });
  const bastionClient = require('../../bastionClient');
  try {
    (await bastionClient.grantJumpAccess(req.params.id, row.ssh_public_key, row.bastion_port));
    // Platform-dependent Hop-2 login: Linux sentineld's sshd (etc/sshd_hop2_config) has
    // AllowUsers sentinel-support — 'sentinel-support' only exists on the Windows agent's ephemeral
    // account. A Windows-baked command pasted at a Linux device fails "Invalid user sentinel-support"
    // (found live 2026-08-06, sshd log) with no hint to the operator.
    const hop2User = req.raPlatform === 'linux' ? 'sentinel-support' : 'sentinel-support';
    res.json({
      ok: true,
      // Double quotes (not single) around ProxyCommand are load-bearing: the client substitutes
      // <path-to-your-private-key> with a literal $K/$k, which single quotes would prevent both
      // bash and PowerShell from expanding — ssh would then see a bare "-i" immediately followed
      // by "-W", swallow "-W" as the identity filename, and the whole chain falls apart with a
      // "Could not resolve hostname" error two tokens later. Found live 2026-08-06.
      command: `ssh -o ProxyCommand="ssh -i <path-to-your-private-key> -W 127.0.0.1:%p -p 22022 jump-user@bastion.example.com" -i <path-to-your-private-key> -p ${row.bastion_port} ${hop2User}@127.0.0.1`,
      note: 'Save the private key you generated for this session to a file, then paste this ' +
            'command into a terminal — it reaches the device directly (2 hops: this server\'s ' +
            'bastion, then the device itself) without needing anything else installed.',
    });
  } catch (e) {
    log('error', 'Remote-assist hop2-command grant failed', { deviceId: req.params.id, error: e.message });
    res.status(502).json({ error: 'Failed to grant jump access' });
  }
});
};
