// helpers/wifi-rssi.js — WiFi RSSI validation and extraction.
//
// A HELPER module, not a route module: it registers nothing.
//
//   isValidRssi, wifiRssi   members
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 0 deps.  The call must sit at or after L1; the earliest consumer of
// the export is L6031, so at or before L6030.  L6017 satisfies both.
//
// relative requires: none

module.exports = () => {
// RSSI sanity: real BT/WiFi readings live in roughly [-100,-20] dBm. Anything above
// -5 dBm (notably 127 = Android's 0x7F "unknown signal" sentinel) is a bogus modem
// report — letting it vote poisons the centroid (weight ~1e7) and persists ref 127,
// which then breaks every later distance computation for that anchor.
function isValidRssi(r) { return Number.isFinite(r) && r <= -5 && r >= -110; }
// WiFi scan entries carry dBm under `rssi` (Android payload); accept `level` too for
// tolerance — but only when it's a plausible dBm value, never the 0-5 signal_level scale
// (isValidRssi rejects 0-5 outright, so the bar-scale can never sneak in as "−3 dBm").
function wifiRssi(w) {
  if (!w) return null;
  if (isValidRssi(w.rssi)) return w.rssi;
  if (isValidRssi(w.level)) return w.level;
  return null;
}

  return {
    isValidRssi,
    wifiRssi,
  };
};