// helpers/require-device-controller.js — middleware to require device controller.
//
// A HELPER module, not a route module: it registers nothing.
//
//   requireDeviceController   export   middleware that enforces device ownership
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: deviceOwnerInfo (function L2943, hoisted).  The call must sit at or after L1; the earliest consumer of
// the export is L3441, so at or before L3440.  L2961 satisfies both.
//
// relative requires: none

module.exports = ({ deviceOwnerInfo }) => {
// Middleware for control/command endpoints: on a ZK-owned device, require the session to be
// the owning public user OR one of their business sub-users. Non-ZK (admin-fleet) devices fall
// through unchanged (admin / perms). Kept boolean/coarse here (like the owner's own check) —
// fine-grained COMMAND_PERMS gating for business_sub happens solely at POST /command.
function requireDeviceController() {
  return async (req, res, next) => {
    try {
      // Operator API token (request-scoped, see operator-token-auth): a device-scoped token is a
      // capability minted by the device's controller (requireDeviceController on the shell-token
      // route), scoped to its one bound device. Enforce the binding here; the route's own
      // command allowlist + remote_shell_enabled kill switch decide what it may run. (This branch
      // is defense-in-depth: req.operatorTokenAuth is only ever set for OPERATOR_TOKEN_ROUTES.)
      if (req.operatorTokenAuth) {
        const d = req.operatorTokenAuth.deviceId;
        if (d && d !== req.params.id) return res.status(403).json({ error: 'Token is scoped to a different device' });
        return next();
      }
      const { isZk, ownerUserId } = (await deviceOwnerInfo(req.params.id));
      if (!isZk) return next();
      if (req.session?.account_type === 'public' && req.session.userId === ownerUserId) return next();
      if (req.session?.account_type === 'business_sub' && req.session.parent_owner_id === ownerUserId) return next();
      return res.status(403).json({ error: 'Only the device owner can control this device', zk_owned: true });
    } catch (e) { return next(e); }
  };
}

  return {
    requireDeviceController,
  };
};