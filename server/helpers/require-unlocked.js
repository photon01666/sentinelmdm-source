// helpers/require-unlocked.js — unlock middleware: gates requests until the
// server is unlocked.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the app.use() call. Only the middleware function moves.
//
//   requireUnlocked   export   Express middleware: 503/redirect until unlocked
//
// ctx is available at this module's own position in server.js (X >= L2396,
// X <= L2407) — nothing had to move (IN-PLACE splice).
//
// 2 ctx deps: STATIC_EXT_RE — STABLE (const L2395, never reassigned).
// getServerUnlocked — LIVE read (getter only; this block never writes it).
//
// getServerUnlocked is a LIVE dep (getter): serverUnlocked (L107) is
// runtime-reassigned at 2 sites (the unlock handler L2446, the auto-unlock
// bootstrap L5907). A by-value capture would gate requests on the startup
// value forever — the middleware would never see the unlock. The getter reads
// the top-level `let serverUnlocked` at call time.
//   — R5: live vs stable documented here; R3: getServerUnlocked() is called
//     ONLY inside requireUnlocked's body, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ STATIC_EXT_RE, getServerUnlocked }) => {

function requireUnlocked(req, res, next) {
  if (getServerUnlocked()) return next();
  if (req.path === '/unlock' || req.path === '/api/unlock' || req.path === '/api/unlock-pubkey') return next();
  if (STATIC_EXT_RE.test(req.path)) return next();
  if (req.path.startsWith('/api/')) return res.status(503).json({ error: 'Server locked', locked: true });
  res.redirect('/unlock');
}

return { requireUnlocked };

};