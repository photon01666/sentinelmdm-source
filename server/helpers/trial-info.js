// helpers/trial-info.js — trial state/deadline summary for a user row.
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// checkout (L2554) / admin-support-access (below) route wirings, the
// trial-sweep wiring, and trialLockState's body — all at/after the wiring line.
//
//   trialInfo   export   { state, started_at, deadline, ms_remaining, days_remaining }
//
// Wiring RELOCATED above its earliest eager consumer (checkout route wiring,
// L2554) via D1b R2 (dep-first: helpers/trial-len-ms.js) + R1.
// Stable dep by value: TRIAL_LEN_MS — const from helpers/trial-len-ms.js, wired
// above this line. Pure function of its argument otherwise.
//
// No relative require to rebase: the block contains none.

module.exports = ({ TRIAL_LEN_MS }) => {

function trialInfo(u) {
  if (!u.trial_enabled) return null;
  if (!u.trial_started_at) return { state: 'pending', started_at: null, deadline: null, ms_remaining: null, days_remaining: null };
  const deadline = u.trial_started_at + TRIAL_LEN_MS;
  const ms = deadline - Date.now();
  return { state: ms > 0 ? 'active' : 'expired', started_at: u.trial_started_at, deadline,
           ms_remaining: Math.max(0, ms), days_remaining: Math.max(0, Math.ceil(ms / 86400000)) };
}

return { trialInfo };

};
