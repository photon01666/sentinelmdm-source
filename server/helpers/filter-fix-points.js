// helpers/filter-fix-points.js — drop fix points contradicting the recent GPS position.
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// cell-fix / rf-fix wirings and the wifi-aps route wiring (all below the wiring
// line; earliest consumer L3762).
//
//   filterFixPoints   export   keep the strongest cluster when no fresh reference
//
// IN-PLACE splice at the block position (X = L3666, comment absorbed from L3663).
// Resolution (A): READY run — all deps above (RF_REF_MAX_AGE_MS / RF_REF_MAX_ACC_M
// / RF_ANCHOR_MAX_DIST_M / RF_CLUSTER_SPAN_M L3655-L3658, approxDistM from the
// wifi-location wiring L3661), no eager consumer above.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ RF_ANCHOR_MAX_DIST_M, RF_CLUSTER_SPAN_M, RF_REF_MAX_ACC_M, RF_REF_MAX_AGE_MS, approxDistM }) => {

// Drop matched fix points that contradict the device's recent GPS position — a stale or
// mis-calibrated anchor saved in another town must not be used or drawn. Without a usable
// reference, keep only the cluster around the strongest (lowest estimated distance) reading.
function filterFixPoints(pts, ref) {
  if (!pts || !pts.length) return pts || [];
  const fresh = ref && Number.isFinite(ref.lat) &&
    (Date.now() - ref.ts) <= RF_REF_MAX_AGE_MS &&
    (!ref.accuracy || ref.accuracy <= RF_REF_MAX_ACC_M);
  if (fresh) return pts.filter(p => approxDistM(p.lat, p.lng, ref.lat, ref.lng) <= RF_ANCHOR_MAX_DIST_M);
  if (pts.length < 2) return pts;   // lone anchor without a reference still gives a coarse fix
  const seed = pts.reduce((a, b) => (b.d < a.d ? b : a));
  return pts.filter(p => approxDistM(p.lat, p.lng, seed.lat, seed.lng) <= RF_CLUSTER_SPAN_M);
}

return { filterFixPoints };

};
