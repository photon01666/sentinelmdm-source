// helpers/fleet-fan-out.js — fleet fan-out helper.
//
// A HELPER module, not a route module: it registers nothing.
//
//   fleetFanOut   export   run a function concurrently across all controllable devices
//
// RELOCATE: wiring line must sit at/after L3461 and at/before L3836 — placed at L3836.
// 2 deps: decryptText (function L163, hoisted), fleetControllableRemoteAssistDeviceIds (destructure L3460).
//
// relative requires: none

module.exports = ({ decryptText, fleetControllableRemoteAssistDeviceIds }) => {
// Runs fn(deviceId) concurrently across every controllable device, tolerating individual
// failures (one unreachable box must never fail the whole fleet action). Every device's `name`
// column is encrypted-at-rest server-side (ENC:...) regardless of ZK ownership — that's just the
// general encrypt-everything-at-rest scheme, decryptable here via decryptText() since the server
// holds the passphrase-derived key. (A TRUE ZK device's name would still be opaque, but those are
// already filtered out by fleetControllableRemoteAssistDeviceIds() above, so every row reaching
// here is safe to decrypt.) Falls back to the bare id only if decryption fails or the name is empty.
async function fleetFanOut(req, fn, groupId) {
  const devices = await fleetControllableRemoteAssistDeviceIds(req, groupId);
  const settled = await Promise.allSettled(devices.map(d => fn(d.id)));
  return settled.map((r, i) => {
    const d = devices[i];
    const deviceName = decryptText(d.name) || d.id;
    return r.status === 'fulfilled'
      ? { deviceId: d.id, deviceName, ok: true, data: r.value }
      : { deviceId: d.id, deviceName, ok: false, error: r.reason?.bastionError || r.reason?.message || 'failed' };
  });
}

  return {
    fleetFanOut,
  };
};