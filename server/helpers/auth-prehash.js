// helpers/auth-prehash.js — client-side password pre-hashing ("prehash-v1") + auth-salt helpers.
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// verify-user-password wiring (L464), routes/login, routes/account-security,
// routes/user-management, and bootstrapDb's boot-time seeding (runtime-only).
//
//   computeAuthPrehashSync  export   sync PBKDF2 (boot-time seeding only)
//   computeAuthPrehash      export   async PBKDF2 (600k rounds on the libuv pool)
//   ensureAuthSalt          export   guarded auth_salt read/insert
//   looksLikeAuthHash       export   base64 32-byte hash shape check
//   looksLikeAuthSalt       export   base64 salt shape check
//   newAuthSalt             export   fresh 16-byte salt
//   _authPrehashSalt        private  domain-prefixed salt (used by both PBKDF2 fns)
//
// IN-PLACE splice at the block position (X = L265). Resolution (B): `db`
// (const L463) is initialised BELOW the block, so it travels as the LIVE getter
// `getDb: () => db` (LIVE_READS pair) and every read is rewritten to
// `getDb().prepare(...)` — called only inside ensureAuthSalt's body (request
// time, post-boot). The earliest consumer (verify-user-password wiring L464)
// sits below the wiring line, and db is ordering-exempt as a live dep.
//
// crypto (L15) is ctx-injected by value (scanner blind spot — server.js binding,
// not WebCrypto). AUTH_PREHASH_DOMAIN/ITER are stable consts above the block.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ AUTH_PREHASH_DOMAIN, AUTH_PREHASH_ITER, crypto, getDb }) => {

function _authPrehashSalt(authSaltB64) {
  return Buffer.concat([Buffer.from(AUTH_PREHASH_DOMAIN, 'utf8'), Buffer.from(String(authSaltB64), 'base64')]);
}
function computeAuthPrehashSync(password, authSaltB64) {   // boot-time seeding only
  return crypto.pbkdf2Sync(Buffer.from(String(password), 'utf8'), _authPrehashSalt(authSaltB64),
    AUTH_PREHASH_ITER, 32, 'sha256').toString('base64');
}
function computeAuthPrehash(password, authSaltB64) {       // async — 600k rounds run on the libuv pool, not the event loop
  return new Promise((resolve, reject) =>
    crypto.pbkdf2(Buffer.from(String(password), 'utf8'), _authPrehashSalt(authSaltB64),
      AUTH_PREHASH_ITER, 32, 'sha256', (err, key) => err ? reject(err) : resolve(key.toString('base64'))));
}
function looksLikeAuthHash(s) { return typeof s === 'string' && /^[A-Za-z0-9+/]{43}=$/.test(s); }
function looksLikeAuthSalt(s) {
  if (typeof s !== 'string' || s.length > 128 || !/^[A-Za-z0-9+/]+=*$/.test(s)) return false;
  try { const n = Buffer.from(s, 'base64').length; return n >= 8 && n <= 64; } catch { return false; }
}
function newAuthSalt() { return crypto.randomBytes(16).toString('base64'); }
async function ensureAuthSalt(user) {
  if (user.auth_salt) return user.auth_salt;
  const fresh = newAuthSalt();
  // Guarded write + re-read so concurrent callers (3 replicas) converge on a single salt.
  (await getDb().prepare('UPDATE users SET auth_salt=? WHERE id=? AND auth_salt IS NULL').run(fresh, user.id));
  const row = (await getDb().prepare('SELECT auth_salt FROM users WHERE id=?').get(user.id));
  return (row && row.auth_salt) || fresh;
}

return { computeAuthPrehash, computeAuthPrehashSync, ensureAuthSalt, looksLikeAuthHash, looksLikeAuthSalt, newAuthSalt };

};
