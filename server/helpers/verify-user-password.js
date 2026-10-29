// helpers/verify-user-password.js — single verification point for password checks.
//
// A HELPER module, not a route module: it registers nothing.
//
//   verifyUserPassword   export   verify a user password against stored hash
//
// RELOCATE: wiring line must sit at/after L647 and at/before L2965 — placed at L647.
// 7 deps: AUTH_SCHEME_PREHASH (binding L412), bcrypt (binding L8), computeAuthPrehash (function L422, hoisted),
// db (binding L646), ensureAuthSalt (function L433, hoisted), log (destructure L399),
// looksLikeAuthHash (function L427, hoisted).
//
// relative requires: none

module.exports = ({ AUTH_SCHEME_PREHASH, bcrypt, computeAuthPrehash, db, ensureAuthSalt, log, looksLikeAuthHash }) => {
// Single verification point for every password check. Accepts { authHash } (new clients),
// { password } (legacy clients / not-yet-migrated rows), or both — authHash wins when valid.
// A successful plaintext login on a legacy 'plain' row upgrades it in place to bcrypt(prehash),
// so the plaintext never needs to ride the wire for that account again.
// Timing: an unknown identifier (or a row with no hash) returns BEFORE any bcrypt work, so it is
// measurably faster than a wrong password on an EXISTING account — a user-enumeration oracle via
// response latency. Burn an equivalent bcrypt compare on that path so both outcomes cost the same.
const DUMMY_HASH = '$2a$10$CwTycUXWue0Thq9StjUM0uJ8.6l7cM0RQ8G1r1r2r3r4r5r6r7r8u';
async function verifyUserPassword(user, creds) {
  const { password, authHash } = creds || {};
  if (!user || !user.password_hash) {
    try { bcrypt.compareSync(authHash || password || 'x', DUMMY_HASH); } catch {}
    return false;
  }
  if (user.pw_scheme === AUTH_SCHEME_PREHASH) {
    if (looksLikeAuthHash(authHash)) return bcrypt.compareSync(authHash, user.password_hash);
    if (password && user.auth_salt)   // legacy client → derive the prehash server-side
      return bcrypt.compareSync((await computeAuthPrehash(password, user.auth_salt)), user.password_hash);
    return false;
  }
  // Legacy plaintext-bcrypt row
  if (!password || !bcrypt.compareSync(password, user.password_hash)) return false;
  try {                               // transparent one-time upgrade to the prehash scheme
    const salt = (await ensureAuthSalt(user));
    const hash = bcrypt.hashSync((await computeAuthPrehash(password, salt)), 10);
    (await db.prepare("UPDATE users SET password_hash=?, pw_scheme=? WHERE id=? AND pw_scheme='plain'")
      .run(hash, AUTH_SCHEME_PREHASH, user.id));
  } catch (e) { log('warn', 'prehash upgrade failed', { userId: user.id, error: e.message }); }
  return true;
}

  return {
    verifyUserPassword,
  };
};