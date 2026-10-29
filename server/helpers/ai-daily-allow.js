// helpers/ai-daily-allow.js — AI daily quota limiting.
//
// A HELPER module, not a route module: it registers nothing.
//
//   aiDailyAllow   export   check AI daily quota per kind and user
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 4 deps: AI_DAY_SEC (binding L5295), AI_PUBLIC_FOLLOWUP_MAX (binding L5294), AI_PUBLIC_SUBMIT_MAX (binding L5293), kv (destructure L21).  The call must sit at or after L5296; the earliest consumer of
// the export is L5387, so at or before L5386.  L5296 satisfies both.
//
// relative requires: none

module.exports = ({ AI_DAY_SEC, AI_PUBLIC_FOLLOWUP_MAX, AI_PUBLIC_SUBMIT_MAX, kv }) => {
async function aiDailyAllow(kind, uid) {
  const max = kind === 'submit' ? AI_PUBLIC_SUBMIT_MAX : AI_PUBLIC_FOLLOWUP_MAX;
  const n = await kv.incrWindow(`aiday:${kind}:${uid}`, AI_DAY_SEC).catch(() => Infinity);
  return n <= max;
}

  return {
    aiDailyAllow,
  };
};