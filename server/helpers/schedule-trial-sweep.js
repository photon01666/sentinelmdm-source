// helpers/schedule-trial-sweep.js — schedule the free-trial lifecycle sweep
// (worker-only, run-once + hourly).
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the call site (scheduleCleanup). Only the scheduler function moves.
//
//   scheduleTrialSweep   export   schedule the trial sweep (run-once + hourly)
//
// ctx is available at this module's own position in server.js (X >= L4007,
// X <= L4021) — nothing had to move (IN-PLACE splice).
//
// 3 ctx deps: IS_WORKER, runTrialSweep — STABLE (const/destructure above the
// wiring line, never reassigned). getTrialSweepScheduled /
// setTrialSweepScheduled — LIVE read+write pair.
//
// getTrialSweepScheduled/setTrialSweepScheduled are a LIVE dep pair:
// trialSweepScheduled (L4006) is runtime-reassigned at 1 site (L4009 — the
// guard flip inside scheduleTrialSweep). A by-value capture would see `false`
// on every call and schedule duplicate sweeps. The getter reads the top-level
// `let trialSweepScheduled` at call time; the setter writes it back.
//   — R5: live vs stable documented here; R3: get/set are called ONLY inside
//     scheduleTrialSweep's body, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ IS_WORKER, getTrialSweepScheduled, log, runTrialSweep, setTrialSweepScheduled }) => {

function scheduleTrialSweep() {
  if (getTrialSweepScheduled() || !IS_WORKER) return;
  setTrialSweepScheduled(true);
  setTimeout(() => {
    runTrialSweep().catch(e => log('error', 'trial sweep error', { err: e.message }));
    setInterval(() => runTrialSweep().catch(e => log('error', 'trial sweep error', { err: e.message })), 60 * 60 * 1000).unref();
  }, 2 * 60 * 1000).unref();
}

return { scheduleTrialSweep };

};