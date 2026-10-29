// helpers/flush-telemetry.js — the buffered-telemetry flush coordinator.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the flush timer and the graceful-shutdown hook. Only the coordinator moves.
//
//   flushTelemetry   export   never-overlap wrapper around the two sub-flushes
//
// Wiring line sits just ABOVE its earliest consumer (the telemetry-enqueue
// wiring line's `flushTelemetry` shorthand is evaluated EAGERLY at require
// time), and just below the telemetry-flush wiring line whose
// flushLocations/flushZkPayloads exports this body calls — so both sides of the
// TDZ rule hold: every ctx dep is initialised above the wiring line, and the
// wiring line is at or above every consumer (telemetry-enqueue, the flush
// timer, graceful-shutdown). The telemetry-enqueue wiring line was relocated
// one block DOWN to sit after this one (verbatim line, only its position
// changes) — at the block's original position the TDZ window was empty (eager
// consumer above, non-hoisted deps between), exactly the shape the plan selftest
// calls BLOCKED, resolved the way the `canary-ips`/`ingestArpScanResult`
// relocation resolved it.
// Window: L3732-L3737 (small run — below the plan's 40-line registration
// threshold; deps/exports hand-verified).
//
// 2 ctx deps: flushLocations, flushZkPayloads — STABLE (const from the
// telemetry-flush wiring line above, never reassigned). getTelemetryFlushing /
// setTelemetryFlushing — LIVE read+write pair.
//
// getTelemetryFlushing/setTelemetryFlushing are a LIVE dep pair:
// _telemetryFlushing is runtime-reassigned at 2 sites (the flag set at the top
// of flushTelemetry, the flag clear in its `finally`). A by-value capture would
// see `false` on every call and overlap concurrent flushes (the buffers are
// swapped at the start of each sub-flush, so overlapping flushes would double-
// insert or drop rows). The getter reads the top-level `let _telemetryFlushing`
// at call time; the setter writes it back.
//   — R5: live vs stable documented here; R3: get/set are called ONLY inside
//     flushTelemetry's body, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ flushLocations, flushZkPayloads, getTelemetryFlushing, setTelemetryFlushing }) => {

async function flushTelemetry() {
  if (getTelemetryFlushing()) return;          // never overlap flushes (buffers are swapped at the start of each sub-flush)
  setTelemetryFlushing(true);
  try { await flushLocations(); await flushZkPayloads(); }
  finally { setTelemetryFlushing(false); }
}

return { flushTelemetry };

};
