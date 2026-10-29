// helpers/public-user-wipe.js - the public-user account wipe used by a forgotten password or
// key reset.
//
// A HELPER module, not a route module: it registers nothing. It exists to serve the account
// lifecycle routes and the admin user-detail route, which receive it as ctx deps.
//
//   wipeUserAccount   export   destroys a public user's stored identity and re-keys the
//                              devices bound to it. Reachable only through the reset and
//                              admin paths below, never from an unauthenticated caller.
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 4 of the 12 deps are `function` declarations and hoist (decryptText L167, log L447,
// hwidHmac L3707, userIdentityEmail L3829). The lowest non-hoisted binding is normIdent
// (L3826), so the call must sit at or after L3827; and the earliest consumer of the export
// is L5339, so it must be at or before L5338. L5230 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ DEMO_DEVICE_TABLES, db, decryptText, deviceStatus, emitToDevice, hwidHmac, io, kv, log, normIdent, updateDeviceOwner, userIdentityEmail }) => {
// ── Public-user wipe (forgotten password / key reset) ─────────────────────
// Deletes all ZK-encrypted payloads + ZK media for every device the user owns,
// un-assigns those devices (owner_user_id → NULL), pushes a zk_pub_key=null
// socket event to any live device so it stops encrypting for the old key, then
// deletes the user account. The device KEEPS its permanent lock's email lineage
// (locked_identity_email is intentionally NOT cleared) → it enters RELEASED_PENDING_IDENTITY, so
// only a NEW account registered with the SAME email can re-bind it, and only by signing in from
// the device itself (the signed ticket handshake). This wipe is destructive-only: it can detach a
// device + destroy its data but can NEVER hand access to anyone — rebind requires the physical
// device, which a stolen admin session does not have.
// Reusable account wipe. Chosen trial-expiry scope: delete the user + ALL their data, and RELEASE
// their devices to the email lineage (owner_user_id→NULL, locked_identity_email kept) — NOT a remote
// factory-reset. Only a NEW same-email account can re-bind, and only from the physical device (signed
// handshake), so this is destructive-only and can never hand access to a stolen admin session. Shared
// by the admin wipe route and the trial auto-wipe sweep.
async function wipeUserAccount(userId) {
  const user = (await db.prepare('SELECT id, username, email, role, account_type, trial_started_at, comp_plan, comp_expires_at FROM users WHERE id=?').get(userId));
  if (!user) return { ok: false, error: 'User not found', code: 404 };
  if (user.role === 'admin') return { ok: false, error: 'Cannot wipe admin accounts', code: 400 };
  const lineageEmail = userIdentityEmail(user);
  // Email-lineage HMAC (matches the trial_starts ledger): keys the account_continuity stash so a
  // NEW same-email account can resume the trial + comp plan after this wipe (see POST /api/register).
  const emailPlain = normIdent(decryptText(user.email));
  const emailHmac  = emailPlain ? hwidHmac(emailPlain) : null;
  // Demo devices (synthetic sample data — never real hardware) are DELETED outright below, never
  // released/lineage-locked: there's no physical device to ever reclaim, so keeping an orphaned
  // `demo-<id>` row around would just leak into the admin's orphan/fleet views.
  const owned   = (await db.prepare('SELECT id, is_demo FROM devices WHERE owner_user_id=?').all(userId));
  const demoIds = owned.filter(d => d.is_demo).map(d => d.id);
  const devIds  = owned.filter(d => !d.is_demo).map(d => d.id);

  (await db.transaction(async () => {
    for (const devId of demoIds) {
      for (const table of DEMO_DEVICE_TABLES) (await db.prepare(`DELETE FROM ${table} WHERE device_id=?`).run(devId));
      (await db.prepare('DELETE FROM devices WHERE id=?').run(devId));
    }
    for (const devId of devIds) {
      (await db.prepare('DELETE FROM zk_payloads WHERE device_id=?').run(devId));
      (await db.prepare('DELETE FROM media WHERE device_id=? AND zk_encrypted=1').run(devId));
      // Release ownership; locked_identity_email is left intact (RELEASED_PENDING_IDENTITY rebind gate).
      // Clear `archived` too so a same-email reclaim re-adds the device VISIBLE (the owner's hide
      // choice doesn't silently carry across the account lineage onto a freshly re-enrolled device).
      (await db.prepare('UPDATE devices SET owner_user_id=NULL, archived=0 WHERE id=?').run(devId));
      try { (await db.prepare('UPDATE device_telemetry SET owner_user_id=NULL WHERE device_id=?').run(devId)); } catch {}
    }
    // Clear EVERY users(id) reference first (foreign_keys is ON). NOT-NULL FKs deleted; nullable
    // business/chargeback FKs (orders, ToS, RMA) detached so those records survive the wipe.
    try {
      const tids = (await db.prepare('SELECT id FROM support_threads WHERE user_id=?').all(userId)).map(t => t.id);
      for (const tid of tids) (await db.prepare('DELETE FROM support_messages WHERE thread_id=?').run(tid));
      (await db.prepare('DELETE FROM support_threads WHERE user_id=?').run(userId));
    } catch {}
    try { (await db.prepare('DELETE FROM entitlements   WHERE user_id=?').run(userId)); } catch {}
    try { (await db.prepare('UPDATE orders          SET user_id=NULL WHERE user_id=?').run(userId)); } catch {}
    try { (await db.prepare('UPDATE tos_acceptances SET user_id=NULL WHERE user_id=?').run(userId)); } catch {}
    try { (await db.prepare('UPDATE rma_requests    SET user_id=NULL WHERE user_id=?').run(userId)); } catch {}
    // DETACH (not delete) any Stripe subscription — it belongs to the EMAIL, not this row, so it must
    // outlive the wipe. user_id→NULL (mirroring orders/ToS/RMA) lets a same-email re-registration
    // re-link it (POST /api/register), so billing picks up where it left off.
    try { (await db.prepare('UPDATE subscriptions SET user_id=NULL WHERE user_id=?').run(userId)); } catch {}
    // Same for the trial-abuse-lineage ledger (trial_starts) — it's an append-only audit trail that
    // MUST survive the wipe (see checkTrialLineageAbuse), so detach rather than delete. Missing this
    // left `DELETE FROM users` below throwing a foreign-key violation (23503) for any account that had
    // ever started a trial — the exception was swallowed by the global unhandled-rejection safety net
    // (never reaching the res.json() below), so the request hung forever with no response ever sent.
    try { (await db.prepare('UPDATE trial_starts SET user_id=NULL WHERE user_id=?').run(userId)); } catch {}
    (await db.prepare('DELETE FROM users WHERE id=?').run(userId));
  })());

  // STASH the trial countdown + admin comp plan (they live ON the now-deleted users row) keyed by the
  // email lineage. A new same-email account restores them at registration → the trial resumes at its
  // remaining days (NOT a fresh 30; also closes the trial-reset abuse hole) and any comp plan carries
  // over. COALESCE keeps an earlier real trial start over a later NULL (e.g. re-wiped while pending).
  // Run AFTER the wipe transaction commits: it uses the values captured before the delete, never needs
  // to be atomic with the wipe, and (being a novel ON CONFLICT statement) must not be able to poison
  // the destructive wipe tx if it ever errored. Privacy-safe (keyed hash only); NOT purged.
  if (emailHmac && (user.trial_started_at || user.comp_plan)) {
    try {
      (await db.prepare(
        `INSERT INTO account_continuity (email_hmac, trial_started_at, comp_plan, comp_expires_at, updated_at)
         VALUES (?,?,?,?,?)
         ON CONFLICT(email_hmac) DO UPDATE SET
           trial_started_at = COALESCE(excluded.trial_started_at, account_continuity.trial_started_at),
           comp_plan        = excluded.comp_plan,
           comp_expires_at  = excluded.comp_expires_at,
           updated_at       = excluded.updated_at`
      ).run(emailHmac, user.trial_started_at || null, user.comp_plan || null, user.comp_expires_at || null, Date.now()));
    } catch (e) { log('warn', 'account_continuity stash failed', { userId, error: e.message }); }
  }

  // Keep each device PRIVATE on its live socket (ownerIsPublicUser=true) so plaintext is still
  // dropped after the owner is gone — the admin must NEVER gain access to a wiped device. The stale
  // ZK key is cleared (zkPubKey=null); the device stays welded to its email lineage until a
  // same-email account reclaims it. (Agent goes fully dormant in the Phase-3 APK.)
  for (const devId of devIds) {
    updateDeviceOwner(devId, true, null, null);
    emitToDevice(devId, 'device_locked', { reason: 'account_wiped' });   // agent → go dormant + un-hide launcher (Phase 3)
  }
  // Best-effort: drop the deleted demo device's cached status/battery snapshots.
  for (const devId of demoIds) {
    deviceStatus.delete(devId);
    kv.del('battery:' + devId).catch(() => {});
    kv.del('devstate:' + devId).catch(() => {});
  }
  io.emit('devices_updated');
  return { ok: true, devicesReleased: devIds.length, username: user.username, lineageEmail };
}

  return {
    wipeUserAccount,
  };
};
