// helpers/mark-alert-processed.js — alert retry tracking and mark-processed.
//
// A HELPER module, not a route module: it registers nothing.
//
//   _alertRetryMap, markAlertProcessed   members
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 2 deps: ALERT_SEEN_CACHE_MAX (binding L6826), _alertSeenCacheConfig (binding L6827).  The call must sit at or after L6827; the earliest consumer of
// the export is L6839, so at or before L6838.  L6829 satisfies both.
//
// relative requires: none

module.exports = ({ ALERT_SEEN_CACHE_MAX, _alertSeenCacheConfig }) => {
// Track stale-data retry attempts per alertId so we only notify the user after
// the final attempt, not on every 30s poll tick while the tunnel is down.
let _alertRetryMap = /** @type {Map<number, number>} */ (new Map());
function markAlertProcessed(alertId) {
  const ids = _alertSeenCacheConfig.ids;
  ids.delete(alertId); ids.set(alertId, Date.now()); // re-insert = refresh LRU position
  // Map preserves insertion order, so the first key is always the oldest.
  while (ids.size > ALERT_SEEN_CACHE_MAX) ids.delete(ids.keys().next().value);
}

  return {
    _alertRetryMap,
    markAlertProcessed,
  };
};