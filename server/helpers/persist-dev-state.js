// helpers/persist-dev-state.js — cross-replica device live-state to Redis.
//
// A HELPER module, not a route module: it registers nothing.
//
//   persistDevState   export   mirror device live-state to Redis
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 4 deps: deviceStatus (binding L758), encryptedDevices (binding L757), kv (destructure L21), redisEnabled (destructure L21).  The call must sit at or after L759; the earliest consumer of
// the export is L4899, so at or before L4898.  L4469 satisfies both.
//
// relative requires: none

module.exports = ({ deviceStatus, encryptedDevices, kv, redisEnabled }) => {
// Cross-replica device live-state (status + DPI/transport + encrypted flag). The device
// socket lives on ONE web replica, but the dashboard is served by any replica — so mirror
// the live state to Redis and read it there. TTL refreshes on register/upgrade/device_status
// and expires shortly after the device drops. No-op (local maps only) when Redis is unset.
function persistDevState(id, socket) {
  if (!redisEnabled || !id) return;
  kv.setJSON('devstate:' + id, {
    status:    deviceStatus.get(id) || null,
    dpi:       socket?.dpi || null,
    encrypted: encryptedDevices.has(id),
  }, 900).catch(() => {});
}

  return {
    persistDevState,
  };
};