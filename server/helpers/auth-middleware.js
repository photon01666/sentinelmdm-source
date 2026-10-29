// helpers/auth-middleware.js — auth middleware: requireAuth + requireAdmin,
// with the isRealAppPath noise gate.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the app.use() calls. Only the middleware functions move.
//
//   requireAuth    export   Express middleware: session auth + unauth alerts
//   requireAdmin   export   Express middleware: admin-role gate
//   isRealAppPath  helper   (not exported) — noise gate for unauth alerts
//
// ctx is available at this module's own position in server.js (X >= L2621,
// X <= L2697) — nothing had to move (IN-PLACE splice).
//
// 11 ctx deps: STATIC_EXT_RE, applySupportDelegatePerms, isLoopbackPeer, log,
// reqClientIp, signalAlert, unauthAlertDue — all STABLE (const/function/
// destructure above the wiring line, never reassigned).
// getRealPathRegexes / setRealPathRegexes and getServerGeneration /
// setServerGeneration — LIVE read+write pairs.
//
// getRealPathRegexes/setRealPathRegexes are a LIVE dep pair:
// _realPathRegexes (L2620) is runtime-reassigned at 1 site (L2623 — the lazy
// array initialisation inside isRealAppPath). A by-value capture would see
// `null` on every call and rebuild the route table each request. The getter
// reads the top-level `let _realPathRegexes` at call time; the setter writes
// it back.
//
// getServerGeneration/setServerGeneration are a LIVE dep pair:
// serverGeneration (L115) is runtime-reassigned at 2 sites (startup-restore
// L560, rotate-session-generation L2706). A by-value capture would never
// invalidate sessions after a rotation. The getter reads the top-level
// `let serverGeneration` at call time.
//   — R5: live vs stable documented here; R3: get/set are called ONLY inside
//     the function bodies, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ STATIC_EXT_RE, applySupportDelegatePerms, getRealPathRegexes, getServerGeneration, isLoopbackPeer, log, reqClientIp, setRealPathRegexes, setServerGeneration, signalAlert, unauthAlertDue }) => {

function isRealAppPath(app, p) {
  if (!getRealPathRegexes()) {
    setRealPathRegexes([]);
    try {
      for (const layer of (app._router?.stack || [])) {
        if (layer.route && layer.regexp) getRealPathRegexes().push(layer.regexp);
      }
    } catch (_) {}
  }
  return getRealPathRegexes().some(re => { try { return re.test(p); } catch (_) { return false; } });
}

async function requireAuth(req, res, next) {
  // Operator API token (sentinel-adb CLI) — request-scoped identity set by operatorTokenAuth.
  // It is NOT a session: no cookie, no stored row, nothing replayable (see that module's
  // SECURITY note). accepted here so the device-scoped routes behind it authenticate, but the
  // identity only ever exists for the OPERATOR_TOKEN_ROUTES this request already matched.
  if (req.operatorTokenAuth) {
    if (req.operatorTokenAuth.serverGeneration !== getServerGeneration()) {
      return res.status(401).json({ error: 'Session expired — server restarted' });
    }
    return next();
  }
  if (req.session?.authenticated) {
    // Server restarted since this session was created → force re-login.
    // Prevents the half-authenticated state where SW-served cached pages appear
    // logged in but ZK / API calls fail because the session is orphaned.
    if (req.session.serverGeneration !== getServerGeneration()) {
      req.session.destroy(() => {});
      if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Session expired — server restarted' });
      return res.redirect('/login');
    }
    // Best-effort: a DB hiccup here must fall back to the stored map, never 500 the request.
    // But LOG it — falling back silently restores the exact stale-snapshot bug this fixes, and
    // that failure is otherwise invisible (the dashboard just quietly shows too few devices).
    try {
      await applySupportDelegatePerms(req);
    } catch (e) {
      log('warn', 'Support-delegate live permission refresh failed — using stored (possibly stale) map',
        { userId: req.session.userId, err: e.message });
    }
    return next();
  }
  // Alert on real access attempts; skip static-asset noise AND internal loopback probes so
  // in-container health/route checks don't fire false-positive "Unauthorized Access" alerts.
  // UNAUTH-ALERT COOLDOWN: orphaned-session WebViews (server restarts destroy sessions, so the
  // phone app's dashboard polls keep 401ing every 10s until the user re-logs in) would otherwise
  // page on EVERY poll. Cap at one alert per (path, IP) per 30 min — real probes still alert
  // once per path. Redis-backed, shared across replicas.
  // NOISE GATE: only paths that map to a registered route page. Internet background scanners
  // get a log line instead — see isRealAppPath above.
  if (!STATIC_EXT_RE.test(req.path) && !isLoopbackPeer(req) && req.path !== '/') {
    const ip = reqClientIp(req) || 'unknown';
    if (isRealAppPath(req.app, req.path)) {
      if (await unauthAlertDue(req.path, ip)) {
        const target = req.path.startsWith('/api/') ? 'API' : 'WebUI';
        await signalAlert(
          `🔴 Unauthorized ${target} Access`,
          `Unauthenticated request: \`${req.method} ${req.path}\``,
          req
        );
      }
    } else {
      log('warn', 'Unauthenticated probe on unknown path (not paged)', {
        method: req.method, path: req.path, ip, ua: (req.get('user-agent') || '').slice(0, 200)
      });
    }
  }
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'Unauthorized' });
  if (req.path.startsWith('/admin/subusers')) return res.redirect('/admin/subusers/login');
  if (req.path.startsWith('/admin')) return res.redirect('/admin/login');
  res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (req.session?.role === 'admin') return next();
  res.status(403).json({ error: 'Admin access required' });
}

return { requireAuth, requireAdmin };

};