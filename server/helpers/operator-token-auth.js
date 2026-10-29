// helpers/operator-token-auth.js — Bearer-token middleware for operator tokens.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the app.use() call. Only the middleware function moves.
//
//   operatorTokenAuth   export   Express middleware: Bearer-token → request-scoped auth
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 4 ctx deps: OPERATOR_TOKEN_ROUTES, db, log (all STABLE — declared above the
// wiring line, never reassigned), and getServerGeneration (LIVE getter).
//
// getServerGeneration is a LIVE dep (getter): serverGeneration (L115) is
// runtime-reassigned at 2 sites (startup-restore L958, rotate-session-generation
// L2734). A by-value capture would stamp sessions with a stale generation after
// a rotation, breaking the global-logout mechanism. The getter reads the
// top-level `let serverGeneration` at call time.
//   — R5: live vs stable documented here; R3: getServerGeneration() is called
//     ONLY inside operatorTokenAuth's body, never at factory/module scope.
//   — Precedent: routes/login.js + device-login.js + preauth-public all wire
//     `getServerGeneration: () => serverGeneration` the same way.
//
// SECURITY (scope escape, 2026-10-13): this middleware used to write a full
// `role:'admin'` identity into req.session. express-session PERSISTS req.session at
// res.end and issues a Set-Cookie, so a token scoped to ONE device + shell-only
// produced a 7-day, replayable ADMIN session cookie that then passed requireAuth /
// requireAdmin on EVERY route (no scope check once req.session.authenticated is set —
// the OPERATOR_TOKEN_ROUTES gate only runs when a Bearer header is present). A shell
// token became full dashboard admin. Fix: the operator identity is now REQUEST-SCOPED
// (`req.operatorTokenAuth`), the real session is never mutated, and the downstream
// gates (requireAuth / requireDeviceAccess / the /command + /shell-sessions + /api/devices
// handlers) honor the request-scoped identity instead. No session row is written and no
// cookie is issued, so there is nothing to replay.
//
// No relative require to rebase: the block contains none (measured, not assumed).

const crypto = require('crypto');

module.exports = ({ OPERATOR_TOKEN_ROUTES, db, getServerGeneration, log }) => {

async function operatorTokenAuth(req, res, next) {
  try {
    // A real signed-in session wins — an operator token never augments/replaces one.
    if (req.session?.authenticated) return next();
    const m = /^Bearer\s+(.+)$/i.exec(req.get('authorization') || '');
    if (!m) return next();
    const rule = OPERATOR_TOKEN_ROUTES.find(r =>
      r.re.test(req.path) &&
      (!r.methods || r.methods.includes(req.method)) &&
      (!r.commands || (req.body && r.commands.includes(req.body.command))));
    if (!rule) return next();
    const hash = crypto.createHash('sha256').update(m[1].trim()).digest('hex');
    const row = (await db.prepare('SELECT id,name,scopes,device_id,revoked FROM operator_tokens WHERE token_hash=?').get(hash));
    if (!row || row.revoked) return next();
    const scopes = String(row.scopes || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!scopes.includes(rule.scope)) return res.status(403).json({ error: 'Token lacks required scope' });
    // Device-scoped tokens (per-device connect commands) only work on their own device.
    // NOTE: this middleware runs via app.use() BEFORE route matching, so req.params is
    // still empty here — the device ID is parsed out of the path instead. Unambiguous
    // ID prefixes are resolved to the full UUID so short pasted commands work.
    let boundDeviceId = null;
    if (row.device_id) {
      // The token is ALWAYS bound to its device — carry that onto the request identity so every
      // handler can scope to it (esp. LIST routes like GET /api/devices, which have no :id and so
      // would otherwise see the whole fleet). Path-based enforcement happens separately below.
      boundDeviceId = row.device_id;
      const pm = /^\/api\/devices\/([^/]+)/.exec(req.path || '');
      let rid = pm ? decodeURIComponent(pm[1]) : '';
      if (rid) {
        if (rid !== row.device_id) {
          if (rid.length >= 4 && row.device_id.startsWith(rid)) rid = row.device_id;
          else return res.status(403).json({ error: 'Token is scoped to a different device' });
        }
        // Normalize short pastes to the full UUID for downstream handlers (Express
        // re-parses req.params at route match time, so patching params alone would
        // not stick — rewriting the URL keeps the same route shape).
        if (pm && pm[1] !== rid) req.url = req.url.replace(/^(\/api\/devices\/)[^/]+/, '$1' + rid);
        try { req.params.id = rid; } catch (_) {}
      }
      // else: a LIST route (e.g. GET /api/devices) with no :id — a device-bound token is
      // still allowed to LIST, and the handler scopes the result to its bound device (boundDeviceId
      // above). Do NOT 403 here (that broke the CLI's "resolve device IDs" step).
    }
    // Request-scoped identity — NEVER written to req.session (see SECURITY note above).
    // boundDeviceId: null = token is not device-scoped (admin-fleet); a string = this token
    // may only ever act on that one device. serverGeneration is stamped for parity with the
    // session flow so a rotate-session-generation global logout invalidates live operator use.
    req.operatorTokenAuth = {
      tokenId:        row.id,
      name:           row.name,
      scopes,
      deviceId:       boundDeviceId,
      serverGeneration: getServerGeneration(),
    };
    (await db.prepare('UPDATE operator_tokens SET last_used_at=? WHERE id=?').run(Date.now(), row.id)).catch(() => {});
    log('info', 'Operator token used', { tokenId: row.id, name: row.name, method: req.method, path: req.path });
    return next();
  } catch (e) { return next(); }
}

return { operatorTokenAuth };

};
