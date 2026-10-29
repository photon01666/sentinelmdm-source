// helpers/require-fleet-access.js — fleet access middleware.
//
// A HELPER module, not a route module: it registers nothing.
//
//   requireFleetAccess   export   middleware requiring fleet-level access
//
// RELOCATE: wiring line must sit at/after L1 and at/before L3459 — placed at L3459.
// 0 deps.
//
// relative requires: none

module.exports = () => {
// ── Support service -> server ownership gate (service-authenticated, fail-closed) ──────────────
// The support service has no ownership concept — labels are opaque IDs, and a standing support
// key would let an operator reach ANY device with zero server interaction. This internal route
// lets the support service ask the server "can this caller access this device?" before any
// operator-plane action (Hop-2, powershell, forensics, winupdate, appcontrol, edr, bitlocker,
// telemetry, sentry, usblock, arp-scan, IT audit, SRP, screenview, file-backup, agent-update,
// create_session/rebuild/remint). Autonomous jobs and server-bridge calls are exempt — they're
// the trusted path the owner's dashboard already gates.
//
// Decision: ZK (public-owned) devices are HARD-BLOCKED — no operator action, no IT Mode Audit
// exemption. The sole admin path to full access on a ZK device is impersonation (Hybrid
// Managed support delegate) via the dashboard, which rides the trusted service bridge.
// Non-ZK (admin-fleet, unowned) devices are allowed through.
// ── Windows Fleet — global controls across every remote_assist device the CALLER controls ─────
// Powers the dashboard's top-nav "Windows Fleet" menu: apply one action to every device at once
// instead of clicking through each one's Reverse SSH tab. Available to admins (their own
// admin-fleet devices) AND public/business_sub users (their own ZK-owned devices) — same audience
// as the per-device Reverse SSH tab itself. Every underlying primitive already exists per-device
// (srp/deploy, srp/install-mode-events, runAudit, winUpdate, and the new runPowerShell) — this
// only adds the fan-out. Access control is NOT relaxed for the fleet case: each candidate device
// is filtered through the same deviceOwnerInfo()-based rule requireDeviceController() already
// enforces per-device, so a ZK-owned device the caller doesn't own is just as untouchable here as
// it is one at a time — a fleet action silently skips it rather than 403ing the whole call. Routes
// use requireFleetAccess (not requireDeviceAccess/requireDeviceController — there's no single :id
// to check; the per-device filter below does the equivalent work across the whole set).
function requireFleetAccess(req, res, next) {
  // Operator API token (request-scoped): fleet routes are not in OPERATOR_TOKEN_ROUTES, but
  // handle the identity explicitly so it can never fall through to the session-role check.
  if (req.operatorTokenAuth) return res.status(403).json({ error: 'Operator tokens cannot use fleet routes' });
  const t = req.session?.account_type;
  if (req.session?.role === 'admin' || t === 'public' || t === 'business_sub') return next();
  res.status(403).json({ error: 'Fleet access requires an admin, device-owner, or business sub-user session' });
}

  return {
    requireFleetAccess,
  };
};