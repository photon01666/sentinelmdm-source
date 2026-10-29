// helpers/regen-session.js — session-fixation defense.
//
// A HELPER module, not a route module: it registers nothing. Consumers: routes/login.js,
// routes/device-login.js, routes/passkeys.js, routes/preauth-public.js (the login flows).
//
//   regenSession   export   rotate the session ID on privilege escalation, preserving
//                           a chosen set of keys across the rotation
//
// WHY: express-session keeps the same session ID across the anonymous → authenticated
// transition. An attacker who plants a session cookie before the victim logs in (subdomain
// XSS, COOKIE_INSECURE=1 HTTP MITM on a local debug box, physical access) retains a known
// session ID after authentication — classic session fixation. The fix is to rotate the ID
// at every privilege boundary while carrying forward only the intended post-login fields.
//
// express-session's req.session.regenerate(cb) destroys the current session and issues a NEW
// ID; we copy the requested keys onto the fresh session before invoking the caller's done().
// If regenerate is unavailable (custom store / test double), we fail OPEN to the old behavior
// rather than breaking login — never do worse than no fix.
//
// No relative require to rebase: the block contains none.

module.exports = () => {

/**
 * Rotate the session ID, preserving `keep` keys (post-login identity + any still-pending
 * state the caller needs). Calls done() with no arguments when complete.
 * @param {any} req
 * @param {Record<string, any>} keep  keys to carry onto the fresh session
 * @param {() => void} done
 */
function regenSession(req, keep, done) {
  const sess = req.session;
  const finish = () => { try { done(); } catch (_) {} };
  if (!sess || typeof sess.regenerate !== 'function') return finish();
  // Capture the desired post-rotation state BEFORE regenerate wipes the session.
  const carry = {};
  for (const k of Object.keys(keep || {})) carry[k] = keep[k];
  try {
    sess.regenerate((err) => {
      if (err) return finish();
      try { for (const k of Object.keys(carry)) req.session[k] = carry[k]; } catch (_) {}
      finish();
    });
  } catch (_) { finish(); }
}

return { regenSession };

};
