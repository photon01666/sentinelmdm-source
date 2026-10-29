// helpers/enrollment-ticket.js - the single-use enrollment ticket validator.
//
// A HELPER module, not a route module: it registers nothing. It exists to serve the socket
// handshake in sockets/connection.js, which receives it as a ctx dep.
//
//   consumeEnrollmentTicket  export   validates a ticket, atomically consumes it, and
//                                     binds + locks the device to the ticket's owner.
//                                     This is the SOLE path that creates or moves a
//                                     public-user device binding; it only runs from the
//                                     socket handshake, so it requires the physical device.
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 7 of the 8 deps are `function` declarations and so hoist (usable from any line);
// the eighth, `stmts`, is a destructure at L2271, above L5590.
//
// The require must sit in L2272..L5762 -- after `stmts` is initialised, and before L5763
// where the handshake calls it. L5583 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ bindDeviceToOwner, db, deviceLimitForUser, deviceLockState, encryptText, log, stmts, userIdentityEmail }) => {
// Validate + atomically consume a single-use enrollment ticket, then bind+lock the device to the
// ticket's owner. This is the SOLE path that creates/moves a public-user device binding, and it
// only runs from the socket handshake — i.e. it requires the physical device (TOFU public key on
// first bind, verified signature on rebind). A stolen admin session has no way to reach it.
// Returns { ok, userId?, username?, violation, reason? }:
//   violation:true  → cross-account / cross-identity attempt → caller Signal-alerts + rejects
//   violation:false → benign failure (expired / replayed / consumed) → caller may fall through
async function consumeEnrollmentTicket(deviceId, ticketStr, { publicKey, model, androidVersion, platform, agentKind } = /** @type {{ publicKey?: any, model?: any, androidVersion?: any, platform?: any, agentKind?: any }} */ ({})) {
  const t = (await stmts.getEnrollTicket.get(ticketStr));
  if (!t || t.expires_at < Date.now()) return { ok: false, violation: false, reason: 'invalid/expired ticket' };
  // kind='installer' (2.0.3): bind-any (device_id='' sentinel) + multi-use quota — consumed via
  // uses_remaining decrement (consumed_at stays NULL across uses — it is the REVOKED marker for
  // this kind, so the guard below means "revoked", not "already used once"; see the statement's
  // comment). kind='login': exact old semantics (single-use, device-bound).
  const isInstaller = t.kind === 'installer';
  if (isInstaller) {
    if (t.consumed_at) return { ok: false, violation: false, reason: 'ticket revoked/exhausted' };
    if (t.uses_remaining <= 0) return { ok: false, violation: false, reason: 'ticket use quota exhausted' };
  } else {
    if (t.consumed_at) return { ok: false, violation: false, reason: 'ticket already consumed' };
    if (t.device_id !== deviceId) return { ok: false, violation: false, reason: 'invalid/expired/mismatched ticket' };
  }
  const user = (await db.prepare("SELECT id, username, email, account_type, role, status FROM users WHERE id=?").get(t.user_id));
  const isPublicClaimer = user?.account_type === 'public';
  const isBizClaimer    = user?.account_type === 'business_sub';
  const isAdminClaimer  = user?.role === 'admin' || user?.account_type === 'admin_created';
  if (!user || (!isPublicClaimer && !isBizClaimer && !isAdminClaimer) || user.status !== 'active')
    return { ok: false, violation: false, reason: 'ticket account not eligible/active' };
  const userEmail = userIdentityEmail(user);

  // Authoritative lock re-check at consumption time (state can change during the ticket lifetime).
  const lock = (await deviceLockState(deviceId));
  if (lock.state === 'ACTIVE' && lock.ownerUserId !== user.id)
    return { ok: false, violation: true, reason: `device permanently locked to another account (owner #${lock.ownerUserId})` };
  if (lock.state === 'RELEASED_PENDING_IDENTITY' && lock.identityEmail !== userEmail)
    return { ok: false, violation: true, reason: `lineage mismatch (locked to ${lock.identityEmail}, ticket ${userEmail})` };

  // Plan device-count limit (public accounts; installer enrollments count like any other — the
  // account holder's decision, 2026-08-02). Re-checked at CONSUME time too (a multi-use installer
  // ticket can be shared beyond the plan limit between mint and use).
  if (isPublicClaimer) {
    const deviceLimit = (await deviceLimitForUser(user));
    if (Number.isFinite(deviceLimit)) {
      const owned = (await db.prepare('SELECT COUNT(*) AS n FROM devices WHERE owner_user_id=? AND COALESCE(is_demo,0)=0').get(user.id)).n;
      if (owned >= deviceLimit) {
        log('info', 'Enrollment ticket consume blocked — plan device limit reached', { userId: user.id, deviceId, limit: deviceLimit, owned });
        return { ok: false, violation: false, reason: `plan device limit reached (${deviceLimit})` };
      }
    }
  }

  // ⚠️ Idempotent re-consume guard for installer tickets — the multi-use quota protector.
  // Once a device is ALREADY bound to the ticket's account, re-presenting the same ticket
  // must be a NO-OP, never a fresh seat spent. Found live 2026-08-17 on Linux agents: the
  // sentineld daemon reused a pre-built auth payload that still carried the spent ticket on
  // EVERY control-channel reconnect (a routine xray/bastion bounce), and the key-auth rebind
  // path re-consumed it each time — silently draining a 25-use ticket to 0 on one flapping
  // device, so the next real device hit "ticket use quota exhausted". This is also the
  // correct semantic: a device already owned by the ticket's account needs no seat to "re-bind"
  // to that same account. Must run BEFORE the plan device-limit check below — a re-bind is not
  // a new device.
  if (isInstaller) {
    const existingOwner = (await stmts.getDevice.get(deviceId))?.owner_user_id;
    if (existingOwner === t.user_id) {
      return { ok: true, violation: false, userId: user.id, username: user.username, reused: true };
    }
  }

  // Atomically consume — guards against replay / double-spend across concurrent handshakes.
  const consumed = isInstaller
    ? (await stmts.consumeInstallerTicketUse.run(ticketStr, Date.now())).changes
    : (await stmts.consumeEnrollTicket.run(Date.now(), ticketStr)).changes;
  if (!consumed)
    return { ok: false, violation: false, reason: 'ticket already consumed' };

  // First-bind: ensure the device row exists with this public key so key-auth works next connect.
  if (publicKey) {
    if (!(await stmts.getDevice.get(deviceId))) {
      // agentKind is self-reported at the same trust level as platform/model/androidVersion
      // (device-supplied handshake metadata, not a security boundary) — whitelisted to the one
      // known value so garbage input can't land in the column.
      const safeAgentKind = agentKind === 'remote_assist' ? 'remote_assist' : null;
      (await db.prepare(`INSERT INTO devices
        (id, name, model, android_version, battery, last_seen, online, platform, public_key, agent_kind)
        VALUES (?,?,?,?,NULL,?,0,?,?,?) ON CONFLICT DO NOTHING`).run(
        deviceId, encryptText(model || deviceId), encryptText(model || ''),
        encryptText(androidVersion || ''), Date.now(), platform || 'android', publicKey, safeAgentKind));
    } else {
      (await stmts.setDeviceKey.run(publicKey, deviceId));
    }
    (await stmts.deletePendingKey.run(deviceId));   // clear any stale pending-approval entry for this device
  }
  (await bindDeviceToOwner(deviceId, user, publicKey || (await stmts.getDeviceKey.get(deviceId))?.public_key));
  return { ok: true, violation: false, userId: user.id, username: user.username };
}

  return {
    consumeEnrollmentTicket,
  };
};
