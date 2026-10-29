// helpers/apply-bt-safelist.js — apply Bluetooth safelist to device list.
//
// A HELPER module, not a route module: it registers nothing.
//
//   applyBtSafelist   export   neutralize tracker flags for safelisted MACs
//
// RELOCATE: wiring line must sit at/after L1 and at/before L4340 — placed at L4340.
// 0 deps.
//
// relative requires: none

module.exports = () => {
// Neutralize any device whose MAC is on the safelist: clear the THREAT flags (isTracker +
// severity) but KEEP the diagnostic manufacturer data (trackerBrand/trackerType/trackerDetail)
// so the nearby list still shows what the device advertises — just without the "threat" badge
// or alerts. Returns a new array; leaves {address} intact so it still shows in the nearby list.
function applyBtSafelist(devices, safeSet) {
  if (!Array.isArray(devices) || !safeSet || !safeSet.size) return devices;
  return devices.map(d => {
    if (!d || !d.address || !safeSet.has(String(d.address).toUpperCase())) return d;
    const nn = Object.assign({}, d);
    delete nn.isTracker; delete nn.trackerSeverity;
    nn.isSafe = true;
    return nn;
  });
}

  return {
    applyBtSafelist,
  };
};