module.exports = ({ PLAN_KEY_BY_PRICE, app, connectedSockets, crypto, db, decryptText, deviceLimitForUser, deviceLockState, deviceStatus, encryptText, encryptedDevices, findDeviceNameConflict, getUserSubscriptionRow, io, isDeviceLocked, log, markOffline, pushDeviceDisplayNameToBastion, r2Del, redisEnabled, requireAdmin, requireAuth, requireDeviceAccess, requireDeviceController, requireUnlocked, signalAlert, stmts, updateDeviceOwner, userIdentityEmail }) => {
app.put('/api/devices/:id/name', requireAuth, requireDeviceAccess, async (req, res) => {
  const name = (req.body.name || '').trim().slice(0, 64);
  if (!name) return res.status(400).json({ error: 'Name required' });
  const conflictId = (await findDeviceNameConflict(name, req.params.id, req));
  if (conflictId) return res.status(409).json({ error: `Another device is already named "${name}"` });
  (await db.prepare('UPDATE devices SET name=? WHERE id=?').run(encryptText(name), req.params.id));
  io.emit('devices_updated');
  log('info', `Device renamed to "${name}"`, { deviceId: req.params.id, user: req.session?.username });
  pushDeviceDisplayNameToBastion(req.params.id, name).catch(e =>
    log('warn', 'Failed to push device display name to bastion', { deviceId: req.params.id, error: e.message }));
  res.json({ ok: true });
});

// Owner archives (hides) / unarchives one of their OWN devices — a NON-destructive soft-hide that
// keeps the row, the email-lineage lock, and all ZK data intact (individual devices can't be
// deleted — see DELETE /:id/self). Owner-only via requireDeviceController() so an admin can never
// hide a public user's device from them. Plaintext `archived` flag only; reversible.
app.patch('/api/devices/:id/archive', requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  const v = req.body.archived ? 1 : 0;
  (await db.prepare('UPDATE devices SET archived=? WHERE id=?').run(v, req.params.id));
  io.emit('devices_updated');
  log('info', `Device ${v ? 'archived' : 'unarchived'}`, { deviceId: req.params.id, user: req.session?.username });
  res.json({ ok: true, archived: !!v });
});

// ── Single-use enrollment ticket (public-user auto-enrollment) ───────────────
// Issued only to an authenticated public user (TOTP is already enforced by /login before a
// public session exists). Bound to (userId, deviceId); consumed exactly once in the socket
// handshake to auto-enroll + permanently lock the device. This is the ONLY way a public-user
// device binding is ever created or moved — no admin/HTTP path can bind a public device, so a
// stolen admin session cannot redirect a device to an attacker-controlled key.
app.post('/api/enrollment/ticket', requireAuth, async (req, res) => {
  // Public (parent) claimers create FamilySafe/ZK devices; business_sub (Team) and admins +
  // sub-users (the ADMIN agent) create admin-fleet devices (lineage_kind='admin' is set at bind).
  // Both prove email ownership via the lock. business_sub added 2026-08-02 (auto-provisioning
  // installer variant — Team accounts mint installer agents for their own fleet).
  const isPublicClaimer = req.session.account_type === 'public';
  const isBizClaimer    = req.session.account_type === 'business_sub';
  const isAdminClaimer  = req.session.role === 'admin' || req.session.account_type === 'admin_created';
  if (!isPublicClaimer && !isBizClaimer && !isAdminClaimer)
    return res.status(403).json({ error: 'This account type cannot enroll devices' });
  const deviceId = (req.body?.deviceId || '').toString().trim();
  if (!deviceId) return res.status(400).json({ error: 'deviceId required' });

  const me = (await db.prepare('SELECT id, email, username, status FROM users WHERE id=?').get(req.session.userId));
  if (!me || me.status !== 'active')
    return res.status(403).json({ error: 'Account not active' });
  const myEmail = userIdentityEmail(me);

  // Lock pre-check (the authoritative re-check also runs at consumption, since state can change
  // during the ticket's lifetime). Reject + Signal-alert any cross-account / cross-identity attempt.
  const lock = (await deviceLockState(deviceId));
  if (lock.state === 'ACTIVE' && lock.ownerUserId !== me.id) {
    (await signalAlert('🚨 Device Lock Violation',
      `Account "${me.username}" (#${me.id}) requested an enrollment ticket for device ${deviceId}, which is permanently locked to another account.`, req, deviceId));
    return res.status(409).json({ error: 'This device is permanently registered to another account.' });
  }
  if (lock.state === 'RELEASED_PENDING_IDENTITY' && lock.identityEmail !== myEmail) {
    (await signalAlert('🚨 Device Lock Violation',
      `Account "${me.username}" (#${me.id}, ${myEmail}) requested a ticket for device ${deviceId} whose lineage is locked to a different identity (${lock.identityEmail}).`, req, deviceId));
    return res.status(409).json({ error: 'This device can only be re-registered to its original account identity.' });
  }

  // Plan device-count limit (public/FamilySafe accounts only). Paid 1device_* plans get 5 devices;
  // free-trial / no-live-sub accounts get TRIAL_DEVICE_LIMIT (10); unlimited_* lifts the cap.
  // Re-enrolling a device they already own is always allowed (the id<>deviceId predicate excludes it).
  // The synthetic demo device never counts against the plan cap — a "5 device" plan must not be
  // blocked from ever enrolling a REAL device just because the sample placeholder occupies the slot.
  if (isPublicClaimer) {
    const deviceLimit = (await deviceLimitForUser(me));
    if (Number.isFinite(deviceLimit)) {
      const owned = (await db.prepare('SELECT COUNT(*) AS n FROM devices WHERE owner_user_id=? AND id<>? AND COALESCE(is_demo,0)=0').get(me.id, deviceId)).n;
      if (owned >= deviceLimit) {
        const limitRow = (await getUserSubscriptionRow(req));
        const limitPlan = limitRow ? PLAN_KEY_BY_PRICE[limitRow.price_id] : null;
        const hint = ' Delete excess devices or upgrade to Unlimited to add more.';
        log('info', 'Enrollment ticket blocked — plan device limit reached', { userId: me.id, deviceId, limit: deviceLimit, owned });
        return res.status(409).json({ error: `Your plan covers ${deviceLimit} device${deviceLimit === 1 ? '' : 's'}.${hint}` });
      }
    }
  }

  const ticket = crypto.randomBytes(32).toString('hex');
  const now = Date.now();
  (await stmts.insertEnrollTicket.run(ticket, me.id, deviceId, now + 10 * 60 * 1000, now));
  log('info', 'Enrollment ticket issued', { userId: me.id, deviceId });
  res.json({ ticket, expires_in: 600 });
});

// Self-provisioning: a public user claims an unowned device from the device itself.
// Called by AccountLinkActivity after the parent logs in on the child's device.
// Security rules:
//   - Only public user accounts (not admin/sub) may call this.
//   - The device must be enrolled (exists in devices table).
//   - The device must have no current owner, OR already be owned by this user.
// ⚠️ DEPRECATED binding path. Device binding is now created ONLY by the device presenting a
// single-use ticket over its signed handshake (see POST /api/enrollment/ticket + the handshake
// consumer). An HTTP-only claim would let a stolen admin session (which can mint a same-email
// account) bind a device without the physical device — so this endpoint no longer binds anything.
// It is kept as an idempotent no-op for already-owned devices; everything else is redirected to
// the in-app enrollment flow.
app.post('/api/devices/:id/claim', async (req, res) => {
  if (req.session.account_type !== 'public') {
    return res.status(403).json({ error: 'Only parent accounts can register devices' });
  }
  const device = (await stmts.getDevice.get(req.params.id));
  if (device && device.owner_user_id === req.session.userId) {
    return res.json({ ok: true, already_claimed: true });
  }
  return res.status(409).json({
    error: 'Open the SentinelMDM app on the device and sign in to register it.',
    use_ticket_flow: true,
  });
});

// Assign (or reassign) a device to a user account. Pass userId=null to clear ownership.
app.patch('/api/devices/:id/owner', requireAdmin, async (req, res) => {
  const deviceId = req.params.id;
  const device = (await stmts.getDevice.get(deviceId));
  if (!device) return res.status(404).json({ error: 'Device not found' });

  // Permanent lock: a locked public-user device can never be reassigned or cleared — by anyone,
  // including admin. The only release is DELETE /api/users/:id/wipe.
  if ((await isDeviceLocked(deviceId))) {
    (await signalAlert('⚠️ Blocked Owner Reassignment',
      `Admin attempted to change the owner of permanently-locked device ${deviceId}.`, req, deviceId));
    return res.status(409).json({ error: 'Device is permanently locked to a user account and cannot be reassigned.', locked: true });
  }

  const ownerId = req.body.userId ? parseInt(req.body.userId, 10) : null;
  if (ownerId !== null) {
    const owner = (await db.prepare('SELECT id, status, account_type FROM users WHERE id=?').get(ownerId));
    if (!owner) return res.status(404).json({ error: 'User not found' });
    if (owner.status !== 'active') return res.status(400).json({ error: 'User account is not active' });
    // Public-user device bindings are created ONLY by the device's signed ticket handshake, never
    // by an admin API — so a stolen admin session can never redirect a device to an attacker key.
    if (owner.account_type === 'public')
      return res.status(403).json({ error: 'Public-user devices self-enroll from the device; admin cannot assign them.' });
    // Grant owner full device permissions if public user
    if (owner.account_type === 'public') {
      const userRow = (await stmts.getUserById.get(ownerId));
      if (userRow) {
        const perms = JSON.parse(decryptText(userRow.permissions) || '{}');
        perms[deviceId] = {
          location: true, photos: true, audio: true, screenshots: true, stream: true,
          network: true, files: true, calls: true, sms: true, apps: true,
          contacts: true, notifications: true, keylogs: true,
          screentext: true, geofences: true, schedules: true, timeline: true,
          shell: false, logcat: false, commands: true,
        };
        (await stmts.updateUserPerms.run(encryptText(JSON.stringify(perms)), ownerId));
        // Also enable all matching features so the UI tabs become visible for the public user
        const features = JSON.parse(decryptText(userRow.enabled_features || '{}') || '{}');
        Object.assign(features, {
          location: true, photos: true, audio: true, screenshots: true, stream: true,
          network: true, files: true, calls: true, sms: true, apps: true,
          contacts: true, notifications: true, keylogs: true,
          screentext: true, geofences: true, schedules: true, timeline: true,
          commands: true,
        });
        (await db.prepare('UPDATE users SET enabled_features=? WHERE id=?')
          .run(encryptText(JSON.stringify(features)), ownerId));
      }
    }
  }

  (await db.prepare('UPDATE devices SET owner_user_id=? WHERE id=?').run(ownerId, deviceId));
  // Also sync telemetry table
  (await db.prepare('UPDATE device_telemetry SET owner_user_id=? WHERE device_id=?').run(ownerId, deviceId));
  // Update in-memory ZK flag on any live socket for this device and push
  // the owner's ZK public key so the device activates encryption immediately.
  // Update owner/ZK flags on the device's live socket (on whichever replica holds
  // it) so it switches encryption without a reconnect.
  if (ownerId) {
    const ownerRow2 = (await db.prepare('SELECT id, account_type, zk_public_key FROM users WHERE id=?').get(ownerId));
    const isPublic = ownerRow2?.account_type === 'public';
    updateDeviceOwner(deviceId, isPublic, isPublic ? ownerRow2.id : null,
      (isPublic && ownerRow2?.zk_public_key) ? ownerRow2.zk_public_key : null);
  } else {
    updateDeviceOwner(deviceId, false, null, null);
  }
  io.emit('devices_updated');
  log('info', 'Device owner updated', { deviceId, ownerId });
  res.json({ ok: true });
});

// Owner self-service removal: a public user removes THEIR OWN device. Purges the device's data and
// detaches it (owner_user_id → NULL), but KEEPS the permanent email-lineage lock
// (RELEASED_PENDING_IDENTITY) — so a child holding the phone, or any other account, can never
// re-enroll it; only a NEW same-email account can re-add it (the wipe rebind path). This is the
// per-device equivalent of the account wipe. Admin still CANNOT delete a locked device (the
// requireAdmin route below 409s) — only the owner (here) or a full account wipe releases it.
// Per-device self-removal is DISABLED by design (2026-06-07). A public user can NEVER drop a single
// device from their account. The only way to remove devices is to wipe the WHOLE account; each
// device then stays welded to the email lineage and the same-email account re-adds it by signing in
// on the device. (Endpoint kept so stale clients get a clear message instead of a 404.)
// Owner self-release — lets a PUBLIC account (device owner) remove one of their own devices so
// it stops occupying a paid device slot. Anti-theft is preserved: this is a RELEASE, not a
// hard-delete — all device data is wiped, ownership is dropped (freeing the slot), but the row
// and its locked_identity_email lineage survive, so only a new account with that SAME email,
// claiming from the physical device, can ever bind it again (same guarantee as admin release).
app.delete('/api/devices/:id/self', requireUnlocked, requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'Only account owners can release their own devices' });
  const id = req.params.id;
  const dev = (await db.prepare("SELECT id, owner_user_id, agent_kind, is_demo FROM devices WHERE id=?").get(id));
  if (!dev) return res.status(404).json({ error: 'Device not found' });
  if (dev.owner_user_id !== req.session.userId)
    return res.status(403).json({ error: 'This device is not on your account' });
  try {
    // Windows SentinelRemoteAssist devices: tear down the bastion-side Hop-1 session first.
    if (dev.agent_kind === 'remote_assist') {
      const bastionClient = require('../bastionClient');
      if (bastionClient.configured()) {
        try { (await bastionClient.revokeSession(id)); }
        catch (e) { log('warn', 'RA bastion session revoke failed during owner self-release (continuing)', { deviceId: id, err: e.message }); }
      }
    }
    // Best-effort R2 cleanup (a hiccup must not abort the DB cleanup).
    try {
      for (const { filename } of (await stmts.deviceFileNames.all(id))) await r2Del(`uploads/${filename}`);
      for (const { filename } of (await db.prepare('SELECT filename FROM stream_recordings WHERE device_id=?').all(id))) await r2Del(`streams/${filename}`);
    } catch (e) { log('warn', 'R2 cleanup error during owner self-release (continuing)', { deviceId: id, err: e.message }); }
    (await wipeDeviceDataTables(id));
    // Release ownership: frees the slot (slot count = devices WHERE owner_user_id=?) while the
    // lineage lock + row survive for same-email reclaim.
    (await db.prepare('UPDATE devices SET owner_user_id=NULL, archived=0 WHERE id=?').run(id));
    try { (await db.prepare('UPDATE device_telemetry SET owner_user_id=NULL WHERE device_id=?').run(id)); } catch {}
    const localSock = connectedSockets.get(id);
    if (localSock) { localSock.disconnect(true); connectedSockets.delete(id); encryptedDevices.delete(id); }
    else if (redisEnabled) io.serverSideEmit('device-disconnect', { deviceId: id });
    markOffline(id);
    deviceStatus.delete(id);
    io.emit('devices_updated');
    log('info', 'Device released by owner (self-release)', { deviceId: id, user: req.session?.username });
    res.json({ ok: true, released: true });
  } catch (e) {
    log('error', 'Owner self-release failed', { deviceId: id, err: e.message });
    res.status(500).json({ error: 'Failed to remove device' });
  }
});

// Cascade-wipes every data table for a device (locations, media, files, ZK payloads, logs, …)
// inside one transaction. Shared by both branches of DELETE /api/devices/:id below — a full
// hard-delete and a lineage-preserving release both need every OTHER table emptied first; they
// only differ on what happens to the `devices` row itself afterward.
async function wipeDeviceDataTables(did) {
  (await db.transaction(async () => {
    (await stmts.delDevLocs.run(did));
    (await stmts.delDevMedia.run(did));
    (await stmts.delDevNetwork.run(did));
    (await stmts.delDevBtEvents.run(did));
    (await stmts.delDevFiles.run(did));
    (await stmts.delDevCalls.run(did));
    (await stmts.delDevSms.run(did));
    (await stmts.delDevApps.run(did));
    (await stmts.delDevStatusEvts.run(did));
    (await stmts.delDevKeylogs.run(did));
    (await stmts.delDevScreenText.run(did));
    // ZK private-user blobs + stream-recording rows have no FK cascade (foreign_keys
    // pragma is off) — remove them explicitly so nothing orphans after deletion.
    (await db.prepare('DELETE FROM zk_payloads WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM stream_recordings WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM zk_stream_sessions WHERE device_id=?').run(did));
    // device_telemetry (current-state row incl. the ZK status blob) has no FK cascade either —
    // without this it orphans after deletion, leaving a ghost the dashboard can still show.
    (await db.prepare('DELETE FROM device_telemetry WHERE device_id=?').run(did));
    // Per-device tables added after this cascade was first written — also no FK cascade,
    // so they'd otherwise orphan forever under a dead device_id.
    (await db.prepare('DELETE FROM notifications WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM clipboard_events WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM contacts WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM calendar_events WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM browser_history WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM usage_stats WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM shell_sessions WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM scheduled_commands WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM alert_config WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM watched_apps WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM sms_outbox WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM device_network_logs WHERE device_id=?').run(did));
    (await db.prepare('DELETE FROM device_security_logs WHERE device_id=?').run(did));
    // SentinelRemoteAssist (Windows) session history — no FK cascade either. The actual bastion-side
    // teardown (authorized_keys/tunnel/session dir) is a separate best-effort call in the caller
    // (bastionClient.revokeSession) since it's a network hop that must never abort this transaction.
    (await db.prepare('DELETE FROM remote_assist_sessions WHERE device_id=?').run(did));
  })());
}

app.delete('/api/devices/:id', requireAdmin, async (req, res) => {
  const id = req.params.id;
  // Permanent email-lineage lock (see device-permanent-lock-autoenroll): a device ever bound via
  // the ticket-based enrollment (public-user OR admin-fleet sub-user claim) carries
  // locked_identity_email forever — this is the compromised-admin guarantee. Erasing the ROW would
  // erase the lock with it, so a locked device is never hard-deleted. Instead admin gets a RELEASE:
  // every data table is wiped and the device drops off that account's dashboard (and, for public/ZK
  // devices, out of the admin fleet view too — same as today's orphan-hide filter), but the row and
  // its locked_identity_email/lineage_kind survive untouched. Only a NEW account with that SAME
  // email, claiming from the physical device itself, can ever bind it again — identical to what the
  // existing "wipe account" / "forgot password" flow already does for a whole account at once. A
  // truly UNLOCKED device (never claimed) has no lineage to protect, so it keeps the old behavior:
  // full row delete + re-queue into pending enrollment.
  const lock = (await deviceLockState(id));
  const locked = lock.state === 'ACTIVE' || lock.state === 'RELEASED_PENDING_IDENTITY';
  try {
    // Windows SentinelRemoteAssist devices: tear down the bastion-side Hop-1 session (authorized_
    // keys line, live tunnel, session dir, built exe) BEFORE the row itself is wiped/released below
    // — runs unconditionally ahead of the locked/unlocked split since releasing ownership must kill
    // remote access even when the row (and its lineage lock) is intentionally kept. Best-effort: a
    // bastion outage must never block the device removal itself (mirrors the R2-cleanup try/catch
    // immediately below). Previously nothing ever called this, which is how the fleet accumulated
    // stale ra-<hash>/test-VM bastion sessions with no matching device row.
    const raRow = (await db.prepare("SELECT platform, agent_kind FROM devices WHERE id=?").get(id));
    if (raRow?.agent_kind === 'remote_assist') {
      const bastionClient = require('../bastionClient');
      if (bastionClient.configured()) {
        try { (await bastionClient.revokeSession(id)); }
        catch (e) { log('warn', 'Remote-assist bastion session revoke failed during device delete (continuing)', { deviceId: id, err: e.message }); }
      }
    }
    // Delete pulled files and stream recordings from R2 (and local disk fallback).
    // Wrapped so a single R2 hiccup can't abort the DB cleanup or crash the process.
    try {
      for (const { filename } of (await stmts.deviceFileNames.all(id)))
        await r2Del(`uploads/${filename}`);
      for (const { filename } of (await db.prepare('SELECT filename FROM stream_recordings WHERE device_id=?').all(id)))
        await r2Del(`streams/${filename}`);
    } catch (e) {
      log('warn', 'R2 cleanup error during device delete (continuing with DB cleanup)', { deviceId: id, err: e.message });
    }
    if (locked) {
      (await wipeDeviceDataTables(id));
      // Release, don't delete: clear ownership but keep the lineage lock + row. Clear `archived`
      // too so a same-email reclaim re-adds the device VISIBLE (mirrors wipeUserAccount()).
      (await db.prepare('UPDATE devices SET owner_user_id=NULL, archived=0 WHERE id=?').run(id));
      try { (await db.prepare('UPDATE device_telemetry SET owner_user_id=NULL WHERE device_id=?').run(id)); } catch {}
      // Loud alert — same principle as the account-wipe alert: a stolen admin session detaching a
      // live-owned device from someone's dashboard must never happen quietly.
      (await signalAlert('🔓 Device Released by Admin',
        `Admin removed locked device ${id} (was ${lock.state}) from its owner's account. All device data was wiped; the device remains permanently reserved to email lineage "${lock.identityEmail || 'n/a'}" and can only be reclaimed by a new account with that same email, from the physical device.`,
        req, id));
      log('warn', 'Locked device released by admin (data wiped, lineage lock preserved)', { deviceId: id, priorState: lock.state, admin: req.session?.username });
    } else {
      // Save public key + device info BEFORE deleting so device can re-appear in enrollment tab
      const savedDevRow = (await db.prepare('SELECT public_key, model, android_version FROM devices WHERE id=?').get(id));
      (await wipeDeviceDataTables(id));
      (await stmts.deleteDevice.run(id));
      // Re-queue device in pending enrollment so it reconnects and appears in the enrollment tab
      if (savedDevRow?.public_key) {
        (await stmts.insertPendingKey.run(id, savedDevRow.model || '', savedDevRow.android_version || '', savedDevRow.public_key, Date.now(), null));
        io.to('monitors').emit('enrollment_update');
        log('info', 'Device key re-queued for enrollment after removal', { deviceId: id });
      }
      log('info', 'Device removed', { deviceId: id });
    }
    // Disconnect the device socket on whichever replica holds it.
    const localSock = connectedSockets.get(id);
    if (localSock) { localSock.disconnect(true); connectedSockets.delete(id); encryptedDevices.delete(id); }
    else if (redisEnabled) io.serverSideEmit('device-disconnect', { deviceId: id });
    markOffline(id);
    deviceStatus.delete(id);
    io.emit('devices_updated');
    res.json({ ok: true, released: locked });
  } catch (e) {
    log('error', 'Device delete failed', { deviceId: id, err: e.message });
    res.status(500).json({ error: 'Failed to remove device' });
  }
});
};
