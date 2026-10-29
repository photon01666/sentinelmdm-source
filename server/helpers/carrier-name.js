// helpers/carrier-name.js — US carrier name lookup from MCC-MNC.
//
// A HELPER module, not a route module: it registers nothing.
//
//   carrierName   export   resolve carrier name from MCC-MNC pair
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 0 deps.  The call must sit at or after L1; the earliest consumer of
// the export is L6366, so at or before L6365.  L6344 satisfies both.
//
// relative requires: none

module.exports = () => {
// US carrier names from MCC-MNC. The phone reports these with every cell, so the
// provider on a tower is read from the data — never guessed from the steel (OSM
// `operator=` names the tower COMPANY: American Tower, Crown Castle…, who lease
// the same mast to all three carriers). Unknown pairs fall back to "MCC-MNC".
function carrierName(mcc, mnc) {
  const k = `${Number(mcc)}-${Number(mnc)}`;
  return {
    '310-260': 'T-Mobile', '310-240': 'T-Mobile',
    '310-410': 'AT&T', '310-150': 'AT&T', '310-170': 'AT&T', '310-380': 'AT&T',
    '311-480': 'Verizon', '311-481': 'Verizon', '310-004': 'Verizon', '310-012': 'Verizon',
    '310-120': 'Sprint (T-Mobile)', '311-490': 'FirstNet', '313-100': 'FirstNet'
  }[k] || k;
}

  return {
    carrierName,
  };
};