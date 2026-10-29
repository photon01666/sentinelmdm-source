// routes/remote-assist/remote-assist-session.js — Persistent Hop-2 key (get / regen / ZK-save) + Remote Assist
// session SSH-key registration, Connect (/start), Reconnect and Stop for Windows + Linux agents.
// Extracted from server.js L5246-L5550. 7 routes. Helpers zkWrapForOwner + _ensureHop2KeyMaterial
// moved in-module (their only callers are inside this block); raUpdateTargetForDevice deliberately
// stayed in server.js (fleet agent-update caller at L6987).
module.exports = ({ app, XRAY_REMOTEASSIST_UUID, crypto, db, decryptText, deviceOwnerInfo, emitRemoteAssistProvision, emitToDevice, encryptText, log, randomUUID, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked, syncDeviceDisplayNameToBastion }) => {
// Browser posts ONLY its freshly generated SSH public key for this session — the private key
// never leaves the browser (sessionStorage/in-memory, same custody model as zk_priv_key). Pushed
// ── Persistent Hop-2 key — saved encrypted server-side so the owner can retrieve their
// SSH private key + connect command after a browser refresh without regenerating the keypair.
// The key is minted ONCE on the bastion (per-session hop2_ed25519) and NEVER rotates unless
// the "Regen Private Key" button is explicitly clicked.
// GET — returns the stored Hop-2 key data. For ZK (public-owned) devices, the data is
// ZK-wrapped (ECDH to owner's EC P-256 key) — the server returns a {zk:true, payload, dek_wrapped}
// blob that the browser decrypts with zkDecryptRow(). For non-ZK (admin-fleet) devices, the data
// is server-encrypted at rest and returned as plaintext JSON over the authenticated channel.
app.get('/api/devices/:id/remote-assist/hop2-key', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  try {
    const row = (await db.prepare('SELECT encrypted_data FROM ra_hop2_keys WHERE device_id=?').get(req.params.id));
    if (row) {
      const raw = decryptText(row.encrypted_data);
      const data = JSON.parse(raw);
      if (data.zk) return res.json(data);
      return res.json({ ok: true, ...data });
    }
    return res.json({ ok: true, priv_key: null });
  } catch (e) {
    log('info', 'Failed to get Hop-2 key', { deviceId: req.params.id, error: e.message });
    return res.status(502).json({ error: e.bastionError || e.message || 'Failed to retrieve Hop-2 key' });
  }
});

app.post('/api/devices/:id/remote-assist/hop2-key/regen', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try {
    (await db.prepare('DELETE FROM ra_hop2_keys WHERE device_id=?').run(req.params.id));
    (await bastionClient.regenSessionHop2Key(req.params.id));
    const row = await _ensureHop2KeyMaterial(req.params.id);
    const raw = decryptText(row.encrypted_data);
    const data = JSON.parse(raw);
    if (data.zk) return res.json(data);
    return res.json({ ok: true, regenerated: true, ...data });
  } catch (e) {
    log('info', 'Failed to regenerate Hop-2 key', { deviceId: req.params.id, error: e.message });
    return res.status(502).json({ error: e.bastionError || e.message || 'Failed to regenerate Hop-2 key' });
  }
});

// Accept the browser's locally-generated private key + connect command and persist it
// ZK-encrypted so ONLY the owning public user's browser can decrypt. The server
// structurally cannot read this data — it stores ciphertext wrapped to the owner's
// EC P-256 public key. requireDeviceController() additionally gates access.
app.post('/api/devices/:id/remote-assist/hop2-key/save', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  try {
    const privPem = String(req.body?.privPem || '').trim();
    const connectCmd = String(req.body?.connectCmd || '').trim();
    const connectCmdOnHost = String(req.body?.connectCmdOnHost || '').trim();
    if (!privPem) return res.status(400).json({ error: 'privPem required' });
    const payload = JSON.stringify({ priv_key: privPem, connect_cmd: connectCmd, connect_cmd_on_host: connectCmdOnHost });
    const wrapped = await zkWrapForOwner(req.params.id, payload);
    if (!wrapped) return res.status(400).json({ error: 'Owner has no ZK public key — cannot encrypt. Generate a key in your account settings first.' });
    (await db.prepare('INSERT INTO ra_hop2_keys (device_id, encrypted_data, created_at) VALUES (?,?,?) ON CONFLICT (device_id) DO UPDATE SET encrypted_data=excluded.encrypted_data, created_at=excluded.created_at')
      .run(req.params.id, encryptText(JSON.stringify(wrapped)), Date.now()));
    res.json({ ok: true, saved: true });
  } catch (e) {
    log('info', 'Failed to save Hop-2 key (ZK)', { deviceId: req.params.id, error: e.message });
    res.status(500).json({ error: e.message || 'Failed to save key' });
  }
});

// ══════════════════════════════════════════════════════════════════════════════
// ZK wrap for owner — AES-256-GCM under a random DEK; DEK ECDH-wrapped to the
// owner's EC P-256 public key. Same format as device→browser zk_payloads rows:
//   { payload: b64(iv(12B) || ct || tag(16B)), dek_wrapped: { eph_pub, iv, ct } }
// See the doc comment on zkDecryptRow() in app.js for the matching decrypt path.
// ══════════════════════════════════════════════════════════════════════════════
async function zkWrapForOwner(deviceId, plaintext) {
  const owner = (await db.prepare(
    "SELECT u.zk_public_key FROM devices d JOIN users u ON d.owner_user_id=u.id WHERE d.id=?"
  ).get(deviceId));
  if (!owner?.zk_public_key) return null;
  // Owner's key is SPKI DER (91 bytes); extract last 65 bytes = raw uncompressed EC point
  const ownerPubSpki = Buffer.from(owner.zk_public_key, 'base64');
  if (ownerPubSpki.length < 65) return null;
  const ownerPubRaw = ownerPubSpki.subarray(ownerPubSpki.length - 65);
  const ecdh = crypto.createECDH('prime256v1');
  const ephPubRaw = ecdh.generateKeys();
  // Raw point → SPKI for the browser's zkDecryptRow() import
  const spkiPrefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
  const ephPubSpki = Buffer.concat([spkiPrefix, ephPubRaw]);
  const sharedSecret = ecdh.computeSecret(ownerPubRaw);
  const wrapKey = crypto.hkdfSync('sha256', sharedSecret, Buffer.alloc(32), 'sentinel-dek-wrap', 32);
  const dek = crypto.randomBytes(32);
  const payIv = crypto.randomBytes(12);
  const payCipher = crypto.createCipheriv('aes-256-gcm', dek, payIv);
  const payCt = Buffer.concat([payCipher.update(plaintext, 'utf8'), payCipher.final()]);
  const payTag = payCipher.getAuthTag();
  const payload = Buffer.concat([payIv, payCt, payTag]).toString('base64');
  const dekIv = crypto.randomBytes(12);
  const dekCipher = crypto.createCipheriv('aes-256-gcm', wrapKey, dekIv);
  const dekCt = Buffer.concat([dekCipher.update(dek), dekCipher.final()]);
  const dekTag = dekCipher.getAuthTag();
  return {
    zk: true,
    payload,
    dek_wrapped: {
      eph_pub: ephPubSpki.toString('base64'),
      iv: dekIv.toString('base64'),
      ct: Buffer.concat([dekCt, dekTag]).toString('base64'),
    },
  };
}

// Helper — fetches the bastion's session Hop-2 keymaterial, ZK-wraps it for the
// owner, stores the ZK blob in ra_hop2_keys, and pushes the pubkey to the device.
async function _ensureHop2KeyMaterial(deviceId) {
  const bastionClient = require('../../bastionClient');
  const km = (await bastionClient.getSessionHop2Key(deviceId));
  if (!km?.priv_key) throw new Error('No Hop-2 key available for this device — provision a session first');
  emitToDevice(deviceId, 'remote_assist_ssh_key', {
    publicKeyOpenSsh: km.pub_key,
    sessionToken: km.bastion_label,
    excludeSharedOperatorKey: false,
  });
  const payload = JSON.stringify({
    priv_key: km.priv_key,
    pub_key: km.pub_key,
    connect_cmd: km.connect_cmd || '',
    connect_cmd_on_host: km.connect_cmd_on_host || '',
    bastion_port: km.bastion_port || null,
    bastion_label: km.bastion_label || null,
  });
  const wrapped = await zkWrapForOwner(deviceId, payload);
  if (!wrapped) throw new Error('Owner has no ZK public key — cannot ZK-wrap Hop-2 key');
  // At-rest layer: encrypt the ZK blob with the server key so a raw DB dump is gated twice
  (await db.prepare('INSERT INTO ra_hop2_keys (device_id, encrypted_data, created_at) VALUES (?,?,?) ON CONFLICT (device_id) DO UPDATE SET encrypted_data=excluded.encrypted_data, created_at=excluded.created_at')
    .run(deviceId, encryptText(JSON.stringify(wrapped)), Date.now()));
  return { encrypted_data: encryptText(JSON.stringify(wrapped)) };
}

// STRAIGHT TO THE DEVICE over the control socket (never through the bastion bridge — Hop-1
// session provisioning in bastionClient.js is a completely separate, unrelated identity) so the
// Windows agent can install it into its own ephemeral local account's authorized_keys. On a
// ZK-owned device `excludeSharedOperatorKey:true` tells the agent to install ONLY this key and
// skip the compiled-in Config.AdminHopTwoPublicKey — the mechanism that makes admin access
// physically impossible, not merely ACL-denied. See the "ZK Security" access-control design.
app.post('/api/devices/:id/remote-assist/ssh-key', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const publicKeyOpenSsh = (req.body?.publicKeyOpenSsh || '').toString().trim();
  if (!publicKeyOpenSsh.startsWith('ssh-')) return res.status(400).json({ error: 'publicKeyOpenSsh required (OpenSSH format)' });
  const { isZk } = (await deviceOwnerInfo(req.params.id));
  // Connect is an EXPLICIT user action — they are asking for support. Always include the
  // admin-support key so Snap/Forensics work. ZK privacy is enforced on AUTO-reconnect
  // (the reconnect handler below), where no user explicitly approved the session.
  const id = randomUUID();
  (await db.prepare(`INSERT INTO remote_assist_sessions
    (id, device_id, requested_by_user_id, ssh_public_key, status, created_at)
    VALUES (?,?,?,?,'key_pending',?)`).run(id, req.params.id, req.session.userId, publicKeyOpenSsh, Date.now()));
  emitToDevice(req.params.id, 'remote_assist_ssh_key', { publicKeyOpenSsh, sessionToken: id, excludeSharedOperatorKey: false });

  // 2.0.4 fix — the comment above promised the admin-support key, but the agent no longer BAKES
  // it (AdminHopTwoPublicKey is empty since the "standing admin key removed" migration), and
  // nothing ever pushed it — so the box ended up with ONLY the browser key and the BASTION's
  // hop-2 (which authenticates with the admin-support key for account-linked sessions) failed
  // with "Permission denied (publickey)" on EVERY WebUI feature (found live 2026-08-03 on the
  // clean 2.0.4 box: BitLocker/forensics/PowerShell all 502). Push the bastion's admin-support
  // pubkey alongside the browser key; the agent's setup installs it like any pushed key.
  try {
    const bastionClient = require('../../bastionClient');
    if (bastionClient.configured()) {
      const adminPub = (await bastionClient.adminSupportPubKey());
      if (adminPub && adminPub.startsWith('ssh-')) {
        emitToDevice(req.params.id, 'remote_assist_ssh_key', { publicKeyOpenSsh: adminPub, sessionToken: null, excludeSharedOperatorKey: false });
      }
    }
  } catch (e) {
    log('warn', 'remote-assist: could not push admin-support key', { deviceId: req.params.id, error: e.message });
  }

  res.json({ ok: true, sessionToken: id });
});

app.post('/api/devices/:id/remote-assist/start', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  if (!XRAY_REMOTEASSIST_UUID) return res.status(503).json({ error: 'Remote-assist transport not configured on the server (missing sentinel_xray_remoteassist_uuid secret)' });
  const sessionToken = (req.body?.sessionToken || '').toString();
  const row = sessionToken ? (await db.prepare('SELECT * FROM remote_assist_sessions WHERE id=? AND device_id=?').get(sessionToken, req.params.id)) : null;
  if (!row?.ssh_public_key) return res.status(400).json({ error: 'Call /remote-assist/ssh-key first to register a session SSH key' });
  const bastionClient = require('../../bastionClient');
  if (!bastionClient.configured()) return res.status(503).json({ error: 'Bastion bridge not configured on the server (missing sentinel_bastion_internal_key secret)' });
  try {
    // Hop-1 (reverse-tunnel identity/port) only — Hop-2 key material already went straight to the
    // device above, this call has no knowledge of it. accountId is bookkeeping only now (which
    // SentinelMDM account this session belongs to) — the actual Hop-1 authentication key is this
    // device's OWN (Hop1Identity.cs, stored on register), not looked up by account. For a
    // ZK/public-owned device the owner is unambiguous (only the owner can ever reach this route,
    // see requireDeviceController()); admin-fleet devices have no single "owner" by design, so this
    // falls back to whoever is calling /start right now.
    const { ownerUserId } = (await deviceOwnerInfo(req.params.id));
    const accountId = ownerUserId || req.session.userId;
    const hop1Row = (await db.prepare('SELECT hop1_public_key FROM devices WHERE id=?').get(req.params.id));
    if (!hop1Row?.hop1_public_key) return res.status(409).json({ error: 'Device has not reported a Hop-1 key yet — it needs to reconnect once with an agent build that supports account-linked Remote Assist.' });
    const provisioned = (await bastionClient.provisionSession(req.params.id, accountId, hop1Row.hop1_public_key, req.raPlatform));
    syncDeviceDisplayNameToBastion(req.params.id).catch(() => {}); // best-effort, never blocks Connect
    // End any prior active session for this device so we don't accumulate duplicates.
    (await db.prepare("UPDATE remote_assist_sessions SET status='ended', ended_at=? WHERE device_id=? AND status='active' AND id<>?").run(Date.now(), req.params.id, sessionToken));
    (await db.prepare("UPDATE remote_assist_sessions SET status='active', bastion_label=?, bastion_port=? WHERE id=?")
      .run(provisioned.label, provisioned.port || null, sessionToken));
    // Always push on explicit Connect — this is the user clicking the button, not an
    // automatic reconnect. The reconnect handler no longer re-pushes (which was the loop
    // cause), so this one-shot push is safe. The agent needs it to configure xray and
    // start the reverse SSH tunnel.
    await emitRemoteAssistProvision(req.params.id, req.raPlatform, provisioned.port);
    // Linux arm: sentineld's interactive Hop-2 session key is trusted with NO TTL (removed
    // entirely 2026-08-18 — libexec/hop2-authkeys.sh trusts /run/sentinel-ra/hop2-armed.pub
    // while it exists; the arm file is removed by hop2_session_close, a newer re-arm, or a box
    // reboot). This event was never
    // emitted (the README's "server.js side: explicitly NOT drafted" gap), so every Linux
    // connect command failed "Permission denied (publickey)" even with Hop-1/control healthy
    // (found live 2026-08-06; the standing admin key kept bastion automation working, masking
    // it). The arm file only gates NEW connections — never touches an already-authenticated
    // session. Payload shape must match cmd/sentineld/daemon.go's hop2OpenPayload.
    if (req.raPlatform === 'linux') {
      emitToDevice(req.params.id, 'hop2_session_open', { pubkey: row.ssh_public_key });
    }
    log('info', 'Remote-assist session started', { deviceId: req.params.id, label: provisioned.label, port: provisioned.port });
    res.json({ ok: true, sessionToken });
  } catch (e) {
    log('error', 'Remote-assist start failed', { deviceId: req.params.id, error: e.message });
    res.status(502).json({ error: 'Failed to provision remote-assist session' });
  }
});

// Idempotent "bring the tunnel back up" call for the dashboard's everyday Reconnect button —
// distinct from /start, which the browser calls ONLY from Regen Private Key and which ALWAYS
// mints a fresh browser keypair + re-pushes the transport command (tearing down and rebuilding
// a currently-live tunnel even when nothing needed to change). Reconnect instead: (1) checks live
// bastion status first and, if already connected, does nothing but report that back — no key
// push, no re-provision, no disruption; (2) if not connected, reuses the LAST KNOWN ssh_public_key
// already on file for this device (the same key the automatic on-socket-reconnect handler above
// reuses) to bring Hop-1 back up, so no new key material is minted and nothing on the box needs
// to re-run its elevated setup script beyond re-installing a key it has already seen before.
app.post('/api/devices/:id/remote-assist/reconnect', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  if (!bastionClient.configured()) return res.status(503).json({ error: 'Bastion bridge not configured on the server (missing sentinel_bastion_internal_key secret)' });
  try {
    const status = await bastionClient.sessionStatus(req.params.id);
    if (status?.connected) {
      return res.json({ ok: true, alreadyConnected: true });
    }
    if (!XRAY_REMOTEASSIST_UUID) return res.status(503).json({ error: 'Remote-assist transport not configured on the server (missing sentinel_xray_remoteassist_uuid secret)' });
    const lastKey = await db.prepare(
      "SELECT ssh_public_key, id FROM remote_assist_sessions WHERE device_id=? AND ssh_public_key IS NOT NULL ORDER BY created_at DESC LIMIT 1"
    ).get(req.params.id);
    if (!lastKey?.ssh_public_key) {
      return res.status(400).json({ error: 'No prior session key on file for this device — use Regen Private Key to connect for the first time.' });
    }
    const { ownerUserId } = (await deviceOwnerInfo(req.params.id));
    const accountId = ownerUserId || req.session.userId;
    const hop1Row = (await db.prepare('SELECT hop1_public_key FROM devices WHERE id=?').get(req.params.id));
    if (!hop1Row?.hop1_public_key) return res.status(409).json({ error: 'Device has not reported a Hop-1 key yet — it needs to reconnect once with an agent build that supports account-linked Remote Assist.' });
    const provisioned = (await bastionClient.provisionSession(req.params.id, accountId, hop1Row.hop1_public_key, req.raPlatform));
    syncDeviceDisplayNameToBastion(req.params.id).catch(() => {}); // best-effort, never blocks Reconnect
    (await db.prepare("UPDATE remote_assist_sessions SET status='ended', ended_at=? WHERE device_id=? AND status='active' AND id<>?").run(Date.now(), req.params.id, lastKey.id));
    (await db.prepare("UPDATE remote_assist_sessions SET status='active', bastion_label=?, bastion_port=? WHERE id=?")
      .run(provisioned.label, provisioned.port || null, lastKey.id));
    // ⚠️ ORDER IS LOAD-BEARING: push the Hop-2 key BEFORE emitRemoteAssistProvision(), never
    // after. On Windows that helper sends remoteAssistTransportCommand(), which makes the agent
    // reconfigure its xray transport — and reconfiguring TEARS DOWN the control channel this very
    // emit travels over. Observed on the test VM 2026-08-03: "Remote-assist transport configured —
    // requesting session" at 04:08:37.8037 followed by "Control channel disconnected (transport
    // close)" 9ms later, with the channel gone for ~3.8s. emitToDevice() is fire-and-forget with
    // no ack and no retry, so a key emitted into that window is silently dropped and the device
    // never installs it — administrators_authorized_keys stays stale and the user's connect
    // command fails "Permission denied (publickey)" while every dashboard feature keeps working
    // (those authenticate with the bastion's admin-support key, which is already installed).
    // Agent 2.0.8's on-disk pending-key persistence does NOT cover this: it protects keys that
    // ARRIVED and then lost their process, not keys that never arrived at all.
    //
    // Explicit user action (clicked Reconnect), same reasoning as /ssh-key above — always include
    // the admin-support key so Snap/Forensics/IT-Audit/AppLocker work. Linux has no equivalent
    // (its admin trust is armed via emitRemoteAssistProvision's adminPubKey below, not a
    // per-connect key push), so only push this for Windows.
    if (req.raPlatform !== 'linux') {
      emitToDevice(req.params.id, 'remote_assist_ssh_key', { publicKeyOpenSsh: lastKey.ssh_public_key, sessionToken: lastKey.id, excludeSharedOperatorKey: false });
    }
    await emitRemoteAssistProvision(req.params.id, req.raPlatform, provisioned.port);
    // Linux: reconnect is an explicit user action too — re-arm the same last-known key so the
    // copied connect command keeps working after a tunnel bounce (no TTL on the arm since
    // 2026-08-18).
    if (req.raPlatform === 'linux') {
      emitToDevice(req.params.id, 'hop2_session_open', { pubkey: lastKey.ssh_public_key });
    }
    log('info', 'Remote-assist session reconnected (reused last key)', { deviceId: req.params.id, label: provisioned.label, port: provisioned.port });
    res.json({ ok: true, alreadyConnected: false, sessionToken: lastKey.id });
  } catch (e) {
    log('error', 'Remote-assist reconnect failed', { deviceId: req.params.id, error: e.message });
    res.status(502).json({ error: 'Failed to reconnect remote-assist session' });
  }
});

app.post('/api/devices/:id/remote-assist/stop', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  const bastionClient = require('../../bastionClient');
  try { (await bastionClient.endSession(req.params.id)); } catch (e) { log('warn', 'Remote-assist stop: bastion endSession failed', { deviceId: req.params.id, error: e.message }); }
  (await db.prepare("UPDATE remote_assist_sessions SET status='ended', ended_at=? WHERE device_id=? AND status='active'").run(Date.now(), req.params.id));
  // Linux counterpart of the arm above — sentineld removes the TTL arm file on
  // hop2_session_close (disarmHop2); without it a forgotten session stays armed until the
  // 900s TTL expires on its own. Fire-and-forget, same as every other control emit.
  if (req.raPlatform === 'linux') {
    emitToDevice(req.params.id, 'hop2_session_close', {});
  }
  res.json({ ok: true });
});
};
