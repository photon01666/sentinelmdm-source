// helpers/cached-device-owner-info.js — cached device owner info lookup.
//
// A HELPER module, not a route module: it registers nothing.
//
//   cachedDeviceOwnerInfo   export   cache-aside wrapper around deviceOwnerInfo
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 2 deps: _devinfoCache (binding L2958), deviceOwnerInfo (function L2943, hoisted).  The call must sit at or after L2959; the earliest consumer of
// the export is L4459, so at or before L4458.  L2959 satisfies both.
//
// relative requires: none

module.exports = ({ _devinfoCache, deviceOwnerInfo }) => {
function cachedDeviceOwnerInfo(deviceId) {
  const entry = _devinfoCache.get(deviceId);
  if (entry && Date.now() - entry.ts < 1000) return entry.value;
  const p = deviceOwnerInfo(deviceId).then(val => {
    _devinfoCache.set(deviceId, { ts: Date.now(), value: val });
    return val;
  });
  _devinfoCache.set(deviceId, { ts: Date.now(), value: p });
  return p;
}

  return {
    cachedDeviceOwnerInfo,
  };
};