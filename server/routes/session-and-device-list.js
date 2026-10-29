// routes/session-and-device-list.js — core session identity (mobile-auth-token, /api/me,
// business-banner-dismiss) + the device fleet list (/api/devices).
module.exports = ({ ADMIN_USER, HONEYPOT_MGMT_KEY, app, connectedSockets, crypto, db,
                    decryptText, deviceStatus, encryptedDevices, kv, redisEnabled, stmts }) => {
// ── REST API ───────────────────────────────────────────────────────────────

// Issue a one-time WebView session token (valid 2 min). Called by the mobile
// agent app immediately after a successful OkHttp login, before opening WebView.
app.get('/api/mobile-auth-token', (req, res) => {
  const token = crypto.randomBytes(32).toString('hex');
  // Fire-and-forget; 2-min TTL handled by Redis (shared across replicas).
  kv.setJSON('mobauth:' + token, {
    authenticated:    req.session.authenticated,
    username:         req.session.username,
    role:             req.session.role,
    userId:           req.session.userId,
    account_type:     req.session.account_type,
    permissions:      req.session.permissions      || {},
    enabled_features: req.session.enabled_features || {},
    is_support_delegate: !!req.session.is_support_delegate,
  }, 120).catch(() => {});
  res.json({ token });
});

app.get('/api/me', async (req, res) => {
  const sessUser = req.session.username ? (await stmts.userByName.get(req.session.username)) : null;
  // Always read enabled_features fresh from DB for public users so changes made by
  // the admin (via FEATURE ACCESS toggles or device assignment) take effect immediately
  // without requiring the user to log out and back in.
  let enabledFeatures = req.session.enabled_features || {};
  // Always read fresh from DB (not the session snapshot) so an admin's business-mode revert
  // takes effect immediately without requiring the owner to log out and back in.
  let businessMode = false;
  if (req.session.account_type === 'public' && req.session.userId) {
    const dbUser = (await db.prepare('SELECT enabled_features, business_mode FROM users WHERE id=?').get(req.session.userId));
    if (dbUser) {
      enabledFeatures = JSON.parse(decryptText(dbUser.enabled_features || '{}') || '{}');
      req.session.enabled_features = enabledFeatures;
      businessMode = !!dbUser.business_mode;
    }
  }
  // Business Account compliance banner "don't show again" preference — per VIEWING account (any
  // role: admin, owner, sub-user all see this banner independently, keyed off the DEVICE's
  // business_mode, not the viewer's — see applyPermissionsForDevice()'s comment), persisted
  // server-side (not localStorage) so it survives a refresh/new browser/device, not just this tab.
  let bizBannerDismissed = false;
  if (req.session.userId) {
    const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('biz_banner_dismissed:' + req.session.userId));
    bizBannerDismissed = row?.value === '1';
  }
  res.json({
    username:         req.session.username    || ADMIN_USER,
    id:               req.session.userId      || null,
    // Public users always have role='user'; only fall back to 'admin' for admin sessions
    role:             req.session.role        || (req.session.account_type === 'public' ? 'user' : 'admin'),
    permissions:      req.session.permissions || {},
    account_type:     req.session.account_type || 'admin_created',
    enabled_features: enabledFeatures,
    business_mode:    businessMode,
    biz_banner_dismissed: bizBannerDismissed,
    // Only meaningful for account_type==='business_sub' sessions — the business owner's user id.
    parent_owner_id:  req.session.parent_owner_id || null,
    // ZK fields returned only for public users so browser can derive KEK
    zk_salt:               (sessUser?.account_type === 'public' ? (sessUser.zk_salt || null) : null),
    zk_encrypted_priv_key: (sessUser?.account_type === 'public' ? (sessUser.zk_encrypted_priv_key || null) : null),
    // Whether this account has 2FA enabled — 2FA is optional at signup (see
    // /api/register/skip-totp), so the UI needs this to decide whether to show/require a code
    // on re-auth-gated actions (Secure my account, change email).
    totp_verified: (sessUser?.totp_secret && decryptText(sessUser.totp_secret) === 'DISABLED') ? false : (req.session.username === ADMIN_USER || !!sessUser?.totp_verified),
    // Enrollment token — shown in the getting-started panel; admin uses it in the ADB setup command
    enrollment_token: sessUser?.enrollment_token || null,
    // Provide the honeypot key so the frontend can append ?k= to the WebUI URL
    hp_mgmt_key: (req.session.role === 'admin' || !req.session.role && req.session.account_type !== 'public' ? HONEYPOT_MGMT_KEY : null),
    // True while an admin's session is swapped to a support-delegate identity — drives the
    // persistent "Impersonating <owner>" banner + Exit button in the WebUI.
    impersonating: !!req.session.impersonating,
    impersonator_admin_username: req.session.impersonating ? (req.session._preImpersonation?.username || null) : null,
  });
});

// "Don't show this again" for the Business Account compliance banner — persisted per viewing
// account (not localStorage), so dismissing it survives a refresh and a different browser/device
// signed into the same account, not just the current tab.
app.post('/api/account/business-banner-dismiss', async (req, res) => {
  if (!req.session?.userId) return res.status(401).json({ error: 'Not signed in' });
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('biz_banner_dismissed:' + req.session.userId, '1'));
  res.json({ ok: true });
});

app.get('/api/devices', async (req, res) => {
  const devices = (await stmts.allDevices.all());
  // Build set of device IDs owned by public users (for zk_owned flag). Demo devices are excluded —
  // they're synthetic sample data, never real ZK-encrypted hardware (see is_demo invariant).
  const zkOwnedIds = new Set(
    (await db.prepare("SELECT d.id FROM devices d JOIN users u ON d.owner_user_id=u.id WHERE u.account_type=? AND COALESCE(d.is_demo,0)=0")
      .all('public')).map(r => r.id)
  );
  // Business Account compliance mode — surfaced per device so the client can grey out the
  // blocked-command buttons (audio/video/screen-recording/keylog/manual-photo) without a round-trip.
  const businessModeIds = new Set(
    (await db.prepare("SELECT d.id FROM devices d JOIN users u ON d.owner_user_id=u.id WHERE u.business_mode=1").all()).map(r => r.id)
  );
  // Orphaned-locked devices (email lineage set, NO current owner → the account was wiped) are RESERVED
  // for a same-email reclaim and are fully admin-inaccessible. Hide them from the admin fleet list
  // entirely — the row survives for reclaim, but the admin should never see a wiped public device.
  const orphanLockedIds = new Set(
    (await db.prepare("SELECT id FROM devices WHERE locked_identity_email IS NOT NULL AND owner_user_id IS NULL AND COALESCE(lineage_kind,'public') <> 'admin'").all()).map(r => r.id)
  );
  // Presence is authoritative in the Redis 'online_devices' set (sadd/srem on connect/disconnect
  // across ALL replicas, reconciled by the zombie sweep). The devices.online DB column is NOT
  // reliable in multi-replica — every replica's startup runs `UPDATE devices SET online=0`, which
  // globally zeroes devices still connected to the OTHER replicas — so overlay Redis here.
  const onlineSet = redisEnabled ? new Set(await kv.smembers('online_devices')) : new Set(connectedSockets.keys());
  // Latest ZK-encrypted device_status blob per public-user device (browser decrypts for the card).
  const zkStatusMap = new Map((await db.prepare(
    'SELECT device_id, status_zk, status_dek, status_ts FROM device_telemetry WHERE status_zk IS NOT NULL'
  ).all()).map(r => [r.device_id, r]));
  const bastionClientForAudit = require('../bastionClient');
  // Owner email map so the admin dashboard can group public-user devices by
  // owner ACCOUNT instead of the numeric owner_user_id (known-behavior-losses #1:
  // this projection never carried the field, so the panel silently degraded to
  // grouping by id via its own `d.owner_email || d.owner_user_id` fallback).
  const ownerEmailMap = new Map();
  try {
    const ownerRows = (await db.prepare(
      "SELECT d.id AS device_id, u.email AS email_enc, u.username FROM devices d JOIN users u ON d.owner_user_id=u.id WHERE u.account_type='public'"
    ).all());
    for (const r of ownerRows) {
      ownerEmailMap.set(r.device_id, (r.email_enc ? decryptText(r.email_enc) : null) || r.username || null);
    }
  } catch (_) {}
  const withStatus = await Promise.all(devices.map(async d => {
    const isZkDev = zkOwnedIds.has(d.id);
    // IT Mode Audit (malware/inventory scan) verdict for the "Malware: CLEAN/ATTENTION/COMPROMISE"
    // card badge -- Windows Remote Assist devices only. Cached bastion-side (sessionAuditCached) so a
    // slow/unreachable bastion can never block this hot list endpoint; any failure just leaves
    // this null (card shows PENDING).
    let remoteAssistAudit = null;
    if ((d.platform === 'windows' || d.platform === 'linux') && bastionClientForAudit.configured()) {
      try { remoteAssistAudit = await bastionClientForAudit.sessionAuditCached(d.id); } catch (_) { /* best-effort */ }
    }
    const live = redisEnabled ? await kv.getJSON('devstate:' + d.id) : null;   // cross-replica snapshot
    // ZK devices: never surface cached plaintext status — owner decrypts last_status_zk instead.
    // But include clientIp (non-sensitive, needed for card display) and dpi (REALITY/VPN badges).
    const zkLive = deviceStatus.get(d.id);
    const status = isZkDev ? null : ((live?.status) ?? zkLive ?? null);
    const dbIntegrity = d.integrity ? (() => { try { return JSON.parse(d.integrity); } catch { return null; } })() : null;
    const sock = connectedSockets.get(d.id);
    const zs = isZkDev ? zkStatusMap.get(d.id) : null;
    return {
      ...d,
      // SECURITY: never expose the device's raw auth public key to any client (admin or owner).
      // The socket handshake's legacy enrollment-auth branch trusts a client-presented {deviceId,
      // publicKey} pair whenever it matches this column — so leaking it here would let anyone who
      // can read this endpoint (e.g. an admin session) forge that device's control-channel socket
      // without ever proving possession of the private key.
      public_key: undefined,
      // ZK devices: battery is private — null the plaintext column; owner decrypts last_status_zk.
      battery: isZkDev ? null : d.battery,
      name: decryptText(d.name),
      model: decryptText(d.model),
      android_version: decryptText(d.android_version),
      last_lat: d.last_lat ? (parseFloat(decryptText(String(d.last_lat))) || null) : null,
      last_lng: d.last_lng ? (parseFloat(decryptText(String(d.last_lng))) || null) : null,
      integrity: status?.integrity ?? dbIntegrity,
      status,
      // ZK devices: status is null (ciphertext only), but the card needs IP for display.
      // Pull from deviceStatus map (updated by zk_data handler for device_status events).
      client_ip: (zkLive?.clientIp) ?? null,
      encrypted: isZkDev ? true : (live?.encrypted ?? encryptedDevices.has(d.id)),
      // Demo devices have no live socket to report DPI transport — show a plausible "connected"
      // badge instead of a row of gray "inactive" ones (purely cosmetic; not persisted).
      dpi: d.is_demo ? { reality: true, transport: 'reality', realityNode: 'VA' } : ((live?.dpi) ?? sock?.dpi ?? null),
      // Demo devices always read "online" — there's no real heartbeat to reflect, and an
      // obviously-fake "offline" placeholder would undercut the whole point of the demo.
      online: d.is_demo ? 1 : (onlineSet ? (onlineSet.has(d.id) ? 1 : 0) : d.online),   // Redis presence wins over the clobbered DB column
      owner_user_id: d.owner_user_id || null,
      ui_group_id: d.ui_group_id || null,
      owner_email: ownerEmailMap.get(d.id) || null,
      zk_owned: isZkDev,
      // Permanent email-lineage lock (see DELETE /api/devices/:id) — lets the WebUI show accurate
      // "removed, but reserved to this account" copy instead of implying a full erasure.
      locked: !!d.locked_identity_email,
      business_mode: businessModeIds.has(d.id),
      // Latest encrypted status blob (battery/motion/network) for the owner's browser to decrypt.
      last_status_zk: zs ? { payload: zs.status_zk,
        dek_wrapped: (() => { try { return JSON.parse(zs.status_dek); } catch { return null; } })(),
        ts: zs.status_ts } : null,
      remote_assist_audit: remoteAssistAudit,
    };
  }));
  // Operator API token (request-scoped, see operator-token-auth): it carries NO session, so the
  // role/account_type filters below would return an empty list and break the CLI's "resolve device
  // IDs" step. A device-scoped token sees ONLY its bound device; an unbound (admin-fleet) token sees
  // the same set the admin session filter returns (non-orphan, non-demo) — no ZK group/owner leakage
  // beyond what the fleet view already shows.
  if (req.operatorTokenAuth) {
    const bound = req.operatorTokenAuth.deviceId;
    return res.json(bound
      ? withStatus.filter(d => d.id === bound)
      : withStatus.filter(d => !orphanLockedIds.has(d.id) && !d.is_demo));
  }
  // Admin sees every non-orphan, non-demo device, but a public (ZK) device's ui_group_id belongs
  // to the public OWNER's private grouping — null it so the admin never sees public users' group
  // layout. Demo devices are synthetic sample data private to their owner — never shown to admin
  // (mirrors the orphan-hide treatment; would otherwise clutter the fleet view one-per-trial-signup).
  if (req.session.role === 'admin') return res.json(withStatus
    .filter(d => !orphanLockedIds.has(d.id) && !d.is_demo)
    .map(d => d.zk_owned ? { ...d, ui_group_id: null } : d));
  // Public users: see only devices where they are the owner
  if (req.session.account_type === 'public') {
    const uid = req.session.userId;
    return res.json(withStatus.filter(d => d.owner_user_id === uid));
  }
  // Business sub-users: scoped to just their PARENT OWNER's devices (never the wider admin
  // fleet) AND a truthy permission-map entry for that device.
  if (req.session.account_type === 'business_sub') {
    const parentId = req.session.parent_owner_id;
    const perms = req.session.permissions || {};
    return res.json(withStatus.filter(d => {
      if (d.owner_user_id !== parentId) return false;
      const dp = perms[d.id] || {};
      return Object.values(dp).some(Boolean);
    }));
  }
  // Admin-created sub-users: filter by device-scoped permissions
  const perms = req.session.permissions || {};
  res.json(withStatus.filter(d => {
    const dp = perms[d.id] || {};
    return Object.values(dp).some(Boolean);
  }));
});
};
