// helpers/opencode-probe.js — primary OpenCode key balance probe (worker-only).
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the setInterval scheduling. Only the probe function moves.
//
//   probeOpenCodePrimary   export   one balance probe of the primary OpenCode key
//
// ctx is available at this module's own position in server.js (X >= L3129,
// X <= L3170) — nothing had to move (IN-PLACE splice).
//
// 7 ctx deps: OPENCODE_API_URL, OPENCODE_MODEL, OPENCODE_PRIMARY_DEAD_TTL_MS,
// log, opencodePrimaryKey — all STABLE (const/destructure above the wiring
// line, never reassigned). getOpencodePrimaryDeadUntil /
// setOpencodePrimaryDeadUntil and getOpencodeProbeInFlight /
// setOpencodeProbeInFlight — LIVE read+write pairs.
//
// getOpencodePrimaryDeadUntil/setOpencodePrimaryDeadUntil are a LIVE dep pair:
// _opencodePrimaryDeadUntil (L3112) is runtime-reassigned at 3 sites (this
// block's own writes L3153/L3155, and postOpencode's write). A by-value
// capture would freeze the dead-window and never recover the primary key. The
// getter reads the top-level `let _opencodePrimaryDeadUntil` at call time; the
// setter writes it back.
//
// getOpencodeProbeInFlight/setOpencodeProbeInFlight are a LIVE dep pair:
// _opencodeProbeInFlight (L3128) is runtime-reassigned at 2 sites (this
// block's own writes L3132/L3163). A by-value capture would leave the in-flight
// flag stuck true and block all future probes. The getter reads the top-level
// `let _opencodeProbeInFlight` at call time; the setter writes it back.
//   — R5: live vs stable documented here; R3: get/set are called ONLY inside
//     probeOpenCodePrimary's body, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ OPENCODE_API_URL, OPENCODE_MODEL, OPENCODE_PRIMARY_DEAD_TTL_MS, getOpencodePrimaryDeadUntil, getOpencodeProbeInFlight, log, opencodePrimaryKey, setOpencodePrimaryDeadUntil, setOpencodeProbeInFlight }) => {

async function probeOpenCodePrimary() {
  const key = opencodePrimaryKey();
  if (!key) return;
  setOpencodeProbeInFlight(true);
  try {
    const resp = await fetch(OPENCODE_API_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${key}`,
        'x-opencode-session': 'primary-balance-probe',
        'User-Agent': 'SentinelMDM/2.26',
      },
      body: JSON.stringify({
        model: OPENCODE_MODEL,
        messages: [{ role: 'user', content: 'ping' }],
        max_tokens: 1,
      }),
      signal: AbortSignal.timeout(30000),
    });
    if (resp.ok) {
      if (getOpencodePrimaryDeadUntil() > 0) {
        log('info', 'OpenCode primary key recovered — balance ok, primary back in rotation');
      }
      setOpencodePrimaryDeadUntil(0);
    } else if (resp.status === 401 || resp.status === 403) {
      setOpencodePrimaryDeadUntil(Date.now() + OPENCODE_PRIMARY_DEAD_TTL_MS);
      log('warn', 'OpenCode primary balance probe: still no balance', { status: resp.status });
    } else {
      log('warn', 'OpenCode primary balance probe: unexpected status (transient?)', { status: resp.status });
    }
  } catch (e) {
    log('warn', 'OpenCode primary balance probe failed', { err: e.message });
  } finally {
    setOpencodeProbeInFlight(false);
  }
}

return { probeOpenCodePrimary };

};