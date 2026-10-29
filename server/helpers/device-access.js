// helpers/device-access.js - the authorization gates every device-facing route sits behind.
//
// A HELPER module, not a route module: it registers nothing. It exports the two middleware
// factories that the route modules below receive as ctx deps — 30 wiring lines take
// `requireDeviceAccess` and 7 take `requirePerm`.
//
//   requireDeviceAccess   export   admin always passes; otherwise the caller must be the
//                                  owning public user (or one of their scoped sub-users)
//   requirePerm(perm)     export   factory: require a named permission to proceed
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// Of the 2 deps, `trialLockState` is a `function` declaration at L5130 and HOISTS, so despite
// sitting below this block it is usable from any line; the only binding that constrains the
// position is `db` at L723. So the call must sit at or after L724 — and the earliest consumer
// of the exports is L3862, so at or before L3861. L3265 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ db, trialLockState }) => {
async function requireDeviceAccess(req, res, next) {
  // Operator API token (request-scoped, see operator-token-auth): device-scoped tokens may
  // ONLY touch their one bound device — this is NOT the admin blanket pass. An unbound token
  // (admin-fleet) is limited to the shell/sessions routes the token already matched, so treat
  // it as fleet access here.
  if (req.operatorTokenAuth) {
    const d = req.operatorTokenAuth.deviceId;
    if (d && d !== req.params.id) return res.status(403).json({ error: 'Token is scoped to a different device' });
    return next();
  }
  if (req.session?.role === 'admin') return next();
  // Public users access devices they own (ownership model, not permissions model)
  if (req.session?.account_type === 'public') {
    try {
      const device = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(req.params.id));
      if (device?.owner_user_id === req.session.userId) {
        // Free trial expired with no subscription → pause device data (402) until they subscribe.
        // The dashboard catches this and shows the "subscribe or be wiped" lock screen.
        const lock = (await trialLockState(req.session.userId));
        if (lock.locked) return res.status(402).json({ error: 'Free trial ended', trial_locked: true, wipe_at: lock.wipe_at });
        return next();
      }
      return res.status(403).json({ error: 'No access to this device' });
    } catch (e) { return next(e); }  // async middleware: surface DB errors instead of hanging the request
  }
  // Business sub-users: scoped to their parent owner's devices AND a truthy permission-map entry
  // (cryptographically an extension of the owner, but still permission-gated per device, mirroring
  // admin_created sub-users). The trial-lock is billed to the OWNER, not the sub-user.
  if (req.session?.account_type === 'business_sub') {
    try {
      const device = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(req.params.id));
      if (device?.owner_user_id !== req.session.parent_owner_id)
        return res.status(403).json({ error: 'No access to this device' });
      const lock = (await trialLockState(req.session.parent_owner_id));
      if (lock.locked) return res.status(402).json({ error: 'Free trial ended', trial_locked: true, wipe_at: lock.wipe_at });
      const devicePerms = (req.session?.permissions || {})[req.params.id] || {};
      if (Object.values(devicePerms).some(Boolean)) return next();
      return res.status(403).json({ error: 'No access to this device' });
    } catch (e) { return next(e); }
  }
  const devicePerms = (req.session?.permissions || {})[req.params.id] || {};
  if (Object.values(devicePerms).some(Boolean)) return next();
  res.status(403).json({ error: 'No access to this device' });
}

function requirePerm(perm) {
  return async (req, res, next) => {
    // Operator API token (request-scoped): the token already matched OPERATOR_TOKEN_ROUTES
    // (a shell/sessions-only, device-scoped allowlist), so its device access is established by
    // requireDeviceAccess. Do NOT fall through to the session permission map — there is no
    // session for these requests.
    if (req.operatorTokenAuth) {
      const d = req.operatorTokenAuth.deviceId;
      if (d && d !== req.params.id) return res.status(403).json({ error: `Permission denied: ${perm}` });
      return next();
    }
    if (req.session?.role === 'admin') return next();
    // Public users own their device via owner_user_id, NOT the session permissions map
    // (ZK ownership model — mirrors requireDeviceAccess). The session perms snapshot is loaded
    // once at login, so a device claimed AFTER login (bindDeviceToOwner grants network:true into
    // users.permissions, but the live session predates it) would 403 the OWNER here before the
    // route's maybeRespondWithZkPayloads can return their ZK ciphertext. Trial-lock (402) is
    // already enforced by requireDeviceAccess earlier in the chain.
    if (req.session?.account_type === 'public') {
      try {
        const device = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(req.params.id));
        if (device?.owner_user_id === req.session.userId) return next();
      } catch (e) { return next(e); }
    }
    // Business sub-users: parent-ownership match is required before the specific perm is even
    // consulted — a mismatch is a hard 403 regardless of what's in their permission map.
    if (req.session?.account_type === 'business_sub') {
      try {
        const device = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(req.params.id));
        if (device?.owner_user_id !== req.session.parent_owner_id)
          return res.status(403).json({ error: `Permission denied: ${perm}` });
      } catch (e) { return next(e); }
    }
    const devicePerms = (req.session?.permissions || {})[req.params.id] || {};
    if (devicePerms[perm] || devicePerms.commands) return next();
    res.status(403).json({ error: `Permission denied: ${perm}` });
  };
}

  return {
    requireDeviceAccess,
    requirePerm,
  };
};
