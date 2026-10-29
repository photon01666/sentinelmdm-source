// helpers/cell-dist-m.js — macrocell RSSI to distance conversion.
//
// A HELPER module, not a route module: it registers nothing.
//
//   cellDistM   export   convert cell RSSI to estimated distance in meters
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 0 deps.  The call must sit at or after L1; the earliest consumer of
// the export is L6498, so at or before L6497.  L6468 satisfies both.
//
// relative requires: none

module.exports = () => {
// Macrocell RSSI→distance: -70 dBm ≈ 100 m reference, exponent 3.0.
// (OCID ref_dbm is a crowdsourced *average observed signal*, NOT a 1 m reference
// level — feeding it to the log-distance formula collapses every tower to ~50 m
// and pins the fix onto the tower. Do not use it here.)
function cellDistM(rssi) {
  const r = Number.isFinite(rssi) ? rssi : -100;
  return Math.min(15000, Math.max(100, 100 * Math.pow(10, (-70 - r) / 30)));
}

  return {
    cellDistM,
  };
};