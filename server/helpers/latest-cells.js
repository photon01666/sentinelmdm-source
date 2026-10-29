// helpers/latest-cells.js - read the latest cellular snapshot for a device (serving +
// neighbour cells with identity + signal strength).
//
// A HELPER module, not a route module: it registers nothing.
//
//   latestCells   export   parse the latest network_events row into a cell list
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 of the 2 deps is a hoisted `function` declaration (decryptText L167); 1 is a
// non-hoisted binding (stmts L2220).  The lowest and only non-hoisted binding is
// `stmts` at L2220 — so the call must sit at or after L2221; the earliest consumer
// of the export is L7247, so at or before L7246.  L7065 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ decryptText, stmts }) => {
// Read the latest cellular snapshot (serving + neighbour cells with identity + signal).
// NB: the Android payload nests the cell list under `cellular.cells` (cellularInfo() returns
// {carrier, network_type, roaming, cells:[...]}); the WiFi list is top-level (`wifi_networks`).
async function latestCells(deviceId) {
  try {
    const row = (await stmts.latestNetwork.get(deviceId));
    if (!row?.data) return [];
    const nd = JSON.parse(decryptText(row.data));
    const cellList = (nd.cellular && Array.isArray(nd.cellular.cells)) ? nd.cellular.cells : (nd.cells || []);
    const out = [];
    for (const c of cellList) {
      if (c == null || c.mcc == null || c.cid == null) continue;
      const mcc = Number(c.mcc), mnc = Number(c.mnc || 0), tac = Number(c.tac || 0), cid = Number(c.cid);
      // Drop UNAVAILABLE sentinel identities: modems report signal but no CGI for
      // non-serving cells (mcc/mnc = -1, tac/cid = MAX_VALUE). Without this they
      // masquerade as a fake shared tower and can never resolve. NOTE: valid 5G NR
      // cell IDs run to 36 bits, so only the exact int sentinel and ~Long.MAX count.
      if (!(mcc >= 0 && mcc <= 999) || !(mnc >= 0 && mnc <= 999)) continue;
      if (tac >= 2147483647 || cid === 2147483647 || cid >= 9223372036854775000) continue;
      // rssi_dbm may be absent when the serving cell was reported via the identity fallback
      // (e.g. VoWiFi/IWLAN, where the modem is camped but reports no signal strength) — default
      // to a neutral -100 dBm so the cell still votes / renders.
      out.push({
        mcc, mnc, tac, cid,
        rssi: Number.isFinite(c.rssi_dbm) ? c.rssi_dbm : -100,
        registered: !!c.registered
      });
    }
    return { cells: out, nSeen: cellList.length };
  } catch { return { cells: [], nSeen: 0 }; }
}

  return {
    latestCells,
  };
};