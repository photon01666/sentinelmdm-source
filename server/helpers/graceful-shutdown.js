// helpers/graceful-shutdown.js — graceful shutdown: flush telemetry buffers
// then exit.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the process.on('SIGTERM'/'SIGINT') registrations. Only the shutdown
// function moves.
//
//   gracefulShutdown   export   flush telemetry then process.exit(0)
//
// ctx is available at this module's own position in server.js (X >= L3745,
// X <= L3751) — nothing had to move (IN-PLACE splice).
//
// 4 ctx deps: _telemetryFlushTimer, flushTelemetry, log — all STABLE (const/
// function/destructure above the wiring line, never reassigned).
// getShuttingDown / setShuttingDown — LIVE read+write pair.
//
// getShuttingDown/setShuttingDown are a LIVE dep pair:
// _shuttingDown (L3744) is runtime-reassigned at 1 site (L3746 — the guard
// flip inside gracefulShutdown). A by-value capture would see `false` on every
// call and allow concurrent shutdowns. The getter reads the top-level
// `let _shuttingDown` at call time; the setter writes it back.
//   — R5: live vs stable documented here; R3: get/set are called ONLY inside
//     gracefulShutdown's body, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ _telemetryFlushTimer, flushTelemetry, getShuttingDown, log, setShuttingDown }) => {

async function gracefulShutdown(sig) {
  if (getShuttingDown()) return; setShuttingDown(true);
  clearInterval(_telemetryFlushTimer);
  try { await flushTelemetry(); } catch {}
  log('info', `Flushed telemetry buffers on ${sig}; exiting`);
  process.exit(0);
}

return { gracefulShutdown };

};