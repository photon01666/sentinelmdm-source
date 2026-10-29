// helpers/wu-dedupe.js — Windows Update force-alerted deduplication.
//
// A HELPER module, not a route module: it registers nothing.
//
//   _wuGetDedupe, _wuSetDedupe, _wuDelDedupe   members
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 4 deps: WU_FORCE_ALERTED_KEY (binding L6851), WU_FORCE_ALERTED_TTL (binding L6855), _winUpdateForceAlerted (binding L6848), kv (destructure L21).  The call must sit at or after L6856; the earliest consumer of
// the export is L6888, so at or before L6887.  L6857 satisfies both.
//
// relative requires: none

module.exports = ({ WU_FORCE_ALERTED_KEY, WU_FORCE_ALERTED_TTL, _winUpdateForceAlerted, kv }) => {
// Persist across worker restarts: write-through on set/delete, lazy-load from Redis
// when the in-memory Map doesn't already hold an entry for this device.
async function _wuGetDedupe(deviceId) {
  if (_winUpdateForceAlerted.has(deviceId)) return _winUpdateForceAlerted.get(deviceId);
  try {
    const stored = await kv.getJSON(WU_FORCE_ALERTED_KEY(deviceId));
    if (stored && (typeof stored.terminal === 'boolean' || typeof stored.stuck === 'boolean')) {
      _winUpdateForceAlerted.set(deviceId, stored);
      return stored;
    }
  } catch (_) { /* Redis read failure → fall through to empty dedupe */ }
  return {};
}
async function _wuSetDedupe(deviceId, dedupe) {
  _winUpdateForceAlerted.set(deviceId, dedupe);
  kv.setJSON(WU_FORCE_ALERTED_KEY(deviceId), dedupe, WU_FORCE_ALERTED_TTL).catch(() => {});
}
async function _wuDelDedupe(deviceId) {
  _winUpdateForceAlerted.delete(deviceId);
  kv.del(WU_FORCE_ALERTED_KEY(deviceId)).catch(() => {});
}

  return {
    _wuGetDedupe,
    _wuSetDedupe,
    _wuDelDedupe,
  };
};