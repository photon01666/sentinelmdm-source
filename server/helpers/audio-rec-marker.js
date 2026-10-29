// helpers/audio-rec-marker.js — audio recording in-progress marker.
//
// A HELPER module, not a route module: it registers nothing.
//
//   audiorecCmdKey, setAudioRecActive, clearAudioRecActive   members
//
// RELOCATE: wiring line must sit at/after L545 and at/before L3883 — placed at L3883.
// 2 deps: io (binding L544), kv (destructure L21).
//
// relative requires: none

module.exports = ({ io, kv }) => {
// ── record_audio "recording in progress" marker (drives the WebUI indicator + Cancel) ──────────
// A fixed-duration record_audio can run up to 3h. We mark the device as actively recording when the
// command is issued and clear it when the recording finalizes or is cancelled, so every browser
// watching the device can render a live countdown + a Cancel button. Keyed by DEVICE (the agent runs
// one record_audio at a time). Driven by the COMMAND, not the data path, so it works identically for
// ZK and non-ZK devices — a ZK session (whose segments the server never sees in plaintext) simply
// relies on the TTL / an explicit stop_record_audio to clear the marker.
function audiorecCmdKey(deviceId) { return `audiorec:cmd:${deviceId}`; }
async function setAudioRecActive(deviceId, durationSec) {
  const startedAt = Date.now();
  await kv.setJSON(audiorecCmdKey(deviceId), { startedAt, duration: durationSec }, durationSec + 120);
  io.to(`monitor:${deviceId}`).emit('audio_record_state', { deviceId, active: true, startedAt, duration: durationSec });
}
async function clearAudioRecActive(deviceId) {
  if (!deviceId) return;
  await kv.del(audiorecCmdKey(deviceId));
  io.to(`monitor:${deviceId}`).emit('audio_record_state', { deviceId, active: false });
}

  return {
    audiorecCmdKey,
    setAudioRecActive,
    clearAudioRecActive,
  };
};