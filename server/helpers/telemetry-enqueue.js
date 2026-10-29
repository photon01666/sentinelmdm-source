// helpers/telemetry-enqueue.js — enqueue location + ZK-payload telemetry into
// the in-memory flush buffers.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the flush scheduling. Only the enqueue functions move.
//
//   enqueueLocation   export   push a location row into the flush buffer
//   enqueueZkPayload  export   push a ZK-payload row into the flush buffer
//
// ctx is available at this module's own position in server.js (X >= L3709,
// X <= L4038) — nothing had to move (IN-PLACE splice).
//
// 5 ctx deps: TELEMETRY_FLUSH_MAX, deviceLocLatest, flushTelemetry — all
// STABLE (const/function above the wiring line, never reassigned).
// getLocationBuffer / getZkPayloadBuffer — LIVE reads (getters only; this
// block mutates the buffers via .push but never reassigns them).
//
// getLocationBuffer and getZkPayloadBuffer are LIVE deps (getters):
// locationBuffer (L3706) and zkPayloadBuffer (L3707) are runtime-reassigned
// at 1 site each (L3750/L3770 — the flush-and-clear in flushLocations/
// flushZkPayloads). A by-value capture would push into a STALE array after
// every flush — rows would be silently lost. The getters read the top-level
// `let` at call time; the mutation (.push) applies to the current object.
//   — R5: live vs stable documented here; R3: getX() is called ONLY inside
//     the function bodies, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ TELEMETRY_FLUSH_MAX, deviceLocLatest, flushTelemetry, getLocationBuffer, getZkPayloadBuffer }) => {

function enqueueLocation(deviceId, encData, encLat, encLng, ts, battery) {
  getLocationBuffer().push({ device_id: deviceId, data: encData, timestamp: ts });
  deviceLocLatest.set(deviceId, [encLat, encLng, ts, battery]);   // last-write-wins within the window
  if (getLocationBuffer().length >= TELEMETRY_FLUSH_MAX) flushTelemetry().catch(() => {});
}

function enqueueZkPayload(deviceId, eventType, payload, dekWrapped, ts) {
  getZkPayloadBuffer().push({ device_id: deviceId, event_type: eventType, payload, dek_wrapped: dekWrapped, timestamp: ts });
  if (getZkPayloadBuffer().length >= TELEMETRY_FLUSH_MAX) flushTelemetry().catch(() => {});
}

return { enqueueLocation, enqueueZkPayload };

};