// helpers/device-bind.js - bind (or rebind) a device to a public user + arm the permanent lock,
// then grant full per-device permissions/features. Caller MUST have already validated the ticket,
// the lock lineage, and the device's proof-of-possession; this is the ONLY routine that creates a
// public-user device binding — there is deliberately no admin/HTTP path.
//
// A HELPER module, not a route module: it registers nothing.
//
//   bindDeviceToOwner   export   bind device + arm permanent lock + grant per-device perms/features
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 4 of the 8 deps are `function` declarations and hoist (decryptText L167, encryptText L158,
// log L447, userIdentityEmail L3647). The lowest non-hoisted binding is `stmts`,
// destructured at L2220 — but sha256hex (L3302) is the last non-hoisted dep to initialise,
// so the call must sit at or after L3303; the earliest consumer of the export is L5295,
// so at or before L5294. L3669 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ db, decryptText, encryptText, log, removeDemoDeviceForUser, sha256hex, stmts, userIdentityEmail }) => {
// Bind (or rebind) a device to a public user + arm the permanent lock, then grant full per-device
// permissions/features. Caller MUST have already validated the ticket, the lock lineage, and the
// device's proof-of-possession (signed handshake / TOFU public key). This is the ONLY routine that
// creates a public-user device binding — there is deliberately no admin/HTTP path.
async function bindDeviceToOwner(deviceId, userRow, publicKey) {
  const ownerId = userRow.id;
  // Windows Remote Assist devices are NEVER lineage-locked (explicit product decision 2026-07-19).
  // The permanent-email-welding anti-theft model exists for the family-safety/monitored-phone use
  // case (stops a child swapping/wiping a phone to evade monitoring) — it has no equivalent
  // rationale for a Windows IT-support tool, where "re-link to a different account" is a normal,
  // benign action, not theft. Skipping the lock does NOT weaken ZK-privacy for public owners:
  // deviceOwnerInfo()'s isZk already keys off account_type==='public' first, independent of the
  // lock. Found live: old E2E-test Windows devices ended up permanently unremovable (locked, owner
  // cleared, row stuck forever with no admin path to purge) — see DELETE /api/devices/:id's
  // locked-release branch, which now simply never triggers for platform='windows'.
  const deviceRow = (await db.prepare('SELECT platform FROM devices WHERE id=?').get(deviceId));
  const isWindowsDevice = deviceRow?.platform === 'windows';
  (await db.transaction(async () => {
    (await db.prepare('UPDATE devices SET owner_user_id=? WHERE id=?').run(ownerId, deviceId));
    try { (await db.prepare('UPDATE device_telemetry SET owner_user_id=? WHERE device_id=?').run(ownerId, deviceId)); } catch {}
    if (!isWindowsDevice) {
      (await stmts.setDeviceLock.run(
        encryptText(userIdentityEmail(userRow)),
        publicKey ? sha256hex(publicKey) : null,
        deviceId
      ));
    }
    // Lock KIND: a public claimer makes a ZK-private FamilySafe device; an admin/sub claimer makes an
    // admin-fleet device — lineage-locked (anti-theft) but admin-VISIBLE (non-ZK). See lineage_kind decouple.
    (await db.prepare('UPDATE devices SET lineage_kind=? WHERE id=?')
      .run(userRow.account_type === 'public' ? 'public' : 'admin', deviceId));
    const urow = (await stmts.getUserById.get(ownerId));
    if (urow) {
      const perms = JSON.parse(decryptText(urow.permissions) || '{}');
      perms[deviceId] = {
        location: true, photos: true, audio: true, screenshots: true, stream: true,
        network: true, files: true, calls: true, sms: true, apps: true,
        contacts: true, notifications: true, keylogs: true,
        screentext: true, geofences: true, schedules: true, timeline: true,
        shell: false, logcat: false, commands: true,
      };
      (await stmts.updateUserPerms.run(encryptText(JSON.stringify(perms)), ownerId));
      const features = JSON.parse(decryptText(urow.enabled_features || '{}') || '{}');
      Object.assign(features, {
        location: true, photos: true, audio: true, screenshots: true, stream: true,
        network: true, files: true, calls: true, sms: true, apps: true,
        contacts: true, notifications: true, keylogs: true,
        screentext: true, geofences: true, schedules: true, timeline: true,
        commands: true,
      });
      (await db.prepare('UPDATE users SET enabled_features=? WHERE id=?').run(encryptText(JSON.stringify(features)), ownerId));
    }
  })());
  // The synthetic demo device has served its purpose the moment a REAL device is bound.
  if (userRow.account_type === 'public') {
    try { (await removeDemoDeviceForUser(ownerId)); }
    catch (e) { log('warn', 'Demo device cleanup failed', { ownerId, err: e.message }); }
  }
}

  return {
    bindDeviceToOwner,
  };
};
