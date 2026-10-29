// helpers/ai-rate-allow.js — AI rate limiting with Redis window counter.
//
// A HELPER module, not a route module: it registers nothing.
//
//   aiRateAllow   export   check AI rate limit with shared window counter
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 3 deps: AI_RATE_MAX (binding L5283), AI_RATE_WINDOW_MS (binding L5284), kv (destructure L21).  The call must sit at or after L5285; the earliest consumer of
// the export is L5381, so at or before L5380.  L5285 satisfies both.
//
// relative requires: none

module.exports = ({ AI_RATE_MAX, AI_RATE_WINDOW_MS, kv }) => {
async function aiRateAllow(key) {
  // Fixed-window counter shared across replicas (Redis), so the 5-per-15-min budget is
  // global, not per-replica. Fail-closed on a Redis error (the AI key is billable).
  const n = await kv.incrWindow('airate:' + key, Math.ceil(AI_RATE_WINDOW_MS / 1000)).catch(() => Infinity);
  return n <= AI_RATE_MAX;
}

  return {
    aiRateAllow,
  };
};