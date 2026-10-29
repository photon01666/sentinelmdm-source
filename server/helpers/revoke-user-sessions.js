// helpers/revoke-user-sessions.js — revoke all server sessions for a user.
//
// A HELPER module, not a route module: it registers nothing.
//
//   revokeUserSessions   export   destroy every server session belonging to a user
//
// RELOCATE: wiring line must sit at/after L401 and at/before L3929 — placed at L3929.
// 3 deps: log (destructure L400), redisClient (destructure L21), redisEnabled (destructure L21).
//
// relative requires: none

module.exports = ({ log, redisClient, redisEnabled, db }) => {
// Destroy every server session belonging to a user. The Redis (ioredis) store keys sessions as
// `sess:<sid>` with a JSON body; SCAN them, match userId, DEL the hits. Best-effort, never throws.
// Revokes every server-side session for a user. Pass `exceptSid` (a session ID) to KEEP that one
// alive — used by "change password", which signs out the user's OTHER devices/tabs but leaves the
// tab that just re-authenticated logged in. Callers that omit it (secure-account, delete) revoke ALL.
//
// SQLite (single-instance / offline) store fallback: WITHOUT this, the function returned 0 and did
// NOTHING — so "change password" / "secure my account" / subuser-delete told the user their other
// sessions were revoked while a stolen session cookie kept working (MEDIUM-4). The
// better-sqlite3-session-store keeps rows as `sessions(sid, sess JSON, expire)`; scan those and
// DELETE the matching sids. `db` is the better-sqlite3 (or pg-shim) handle — its prepare().all()
// is used directly (not the request-scoped stmts), since this runs from many call sites.
async function revokeUserSessions(userId, exceptSid = null) {
  const keepKey = exceptSid ? `sess:${exceptSid}` : null;
  if (redisEnabled && redisClient) {
    let cursor = '0', removed = 0;
    try {
      do {
        const [next, keys] = (await redisClient.scan(cursor, 'MATCH', 'sess:*', 'COUNT', 200));
        cursor = next;
        if (keys.length) {
          const vals = (await redisClient.mget(keys));
          const doomed = [];
          for (let i = 0; i < keys.length; i++) {
            if (keepKey && keys[i] === keepKey) continue;
            try { if (vals[i] && JSON.parse(vals[i]).userId === userId) doomed.push(keys[i]); } catch {}
          }
          if (doomed.length) { (await redisClient.del(doomed)); removed += doomed.length; }
        }
      } while (cursor !== '0');
    } catch (e) { log('warn', 'revokeUserSessions error', { userId, error: e.message }); }
    return removed;
  }
  // SQLite fallback — a session whose sess JSON has this userId is destroyed, except exceptSid.
  if (!db) return 0;
  let removed = 0;
  try {
    const rows = (await db.prepare('SELECT sid, sess FROM sessions').all());
    const doomed = [];
    for (const r of rows) {
      if (keepKey && r.sid === exceptSid) continue;
      try { if (r.sess && JSON.parse(r.sess).userId === userId) doomed.push(r.sid); } catch {}
    }
    for (const sid of doomed) { (await db.prepare('DELETE FROM sessions WHERE sid=?').run(sid)); removed++; }
  } catch (e) { log('warn', 'revokeUserSessions (sqlite) error', { userId, error: e.message }); }
  return removed;
}

  return {
    revokeUserSessions,
  };
};