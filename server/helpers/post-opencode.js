// helpers/post-opencode.js — POST to the OpenCode API with primary/fallback
// key failover and a dead-window circuit breaker.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the consumers. Only the POST function moves.
//
//   postOpencode   export   POST a body to the OpenCode API (with failover)
//
// ctx is available at this module's own position in server.js (X >= L3117,
// X <= L4283) — nothing had to move (IN-PLACE splice).
//
// 6 ctx deps: OPENCODE_API_URL, OPENCODE_PRIMARY_DEAD_TTL_MS, log,
// opencodeFallbackKey, opencodePrimaryKey — all STABLE (const/destructure
// above the wiring line, never reassigned). getOpencodePrimaryDeadUntil /
// setOpencodePrimaryDeadUntil — LIVE read+write pair.
//
// getOpencodePrimaryDeadUntil/setOpencodePrimaryDeadUntil are a LIVE dep pair:
// _opencodePrimaryDeadUntil (L3112) is runtime-reassigned at 3 sites (this
// block's own write L3146, the probe reset L3193, the probe set L3195). A
// by-value capture would freeze the dead-window at 0 and never fail over. The
// getter reads the top-level `let _opencodePrimaryDeadUntil` at call time; the
// setter writes it back.
//   — R5: live vs stable documented here; R3: get/set are called ONLY inside
//     postOpencode's body, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ OPENCODE_API_URL, OPENCODE_PRIMARY_DEAD_TTL_MS, getOpencodePrimaryDeadUntil, log, opencodeFallbackKey, opencodePrimaryKey, setOpencodePrimaryDeadUntil }) => {

async function postOpencode(bodyObj, timeoutMs = 60000, sessionId = crypto.randomUUID()) {
  const primary = opencodePrimaryKey();
  const fallback = opencodeFallbackKey();
  const keys = [];
  if (primary && !(fallback && Date.now() < getOpencodePrimaryDeadUntil())) {
    if (getOpencodePrimaryDeadUntil() > 0) {
      log('info', 'OpenCode primary dead-window expired — re-checking primary key', { ttlMs: OPENCODE_PRIMARY_DEAD_TTL_MS });
    }
    keys.push(['primary', primary]);
  }
  if (fallback && fallback !== primary) keys.push(['fallback', fallback]);
  if (!keys.length) throw new Error('no OpenCode key configured');
  let lastErr = null;
  for (const [which, key] of keys) {
    try {
      const resp = await fetch(OPENCODE_API_URL, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${key}`,
          'x-opencode-session': sessionId,
          // Cloudflare 403s (error 1010) the default fetch User-Agent on this endpoint —
          // same requirement the support service already had.
          'User-Agent': 'SentinelMDM/2.26',
        },
        body: JSON.stringify(bodyObj),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if ((resp.status === 401 || resp.status === 403) && which === 'primary' && fallback && fallback !== primary) {
        setOpencodePrimaryDeadUntil(Date.now() + OPENCODE_PRIMARY_DEAD_TTL_MS);
        log('warn', 'OpenCode primary key rejected — failing over to fallback key', { status: resp.status });
        continue;
      }
      return resp;
    } catch (e) {
      lastErr = e;
      log('warn', 'OpenCode call failed', { which, err: e.message });
    }
  }
  throw lastErr || new Error('OpenCode call failed');
}

return { postOpencode };

};