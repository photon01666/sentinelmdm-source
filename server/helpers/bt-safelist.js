// helpers/bt-safelist.js — Bluetooth tracker safelist.
//
// A HELPER module, not a route module: it registers nothing.
//
//   getBtSafelist, setBtSafelist   members
//
// RELOCATE: wiring line must sit at/after L626 and at/before L4339 — placed at L4339.
// 1 dep: db (binding L625).
//
// relative requires: none

module.exports = ({ db }) => {
// ── Bluetooth tracker safelist (module scope; used by REST routes + socket handlers) ──
// The owner can mark a nearby device's MAC address "safe" so its tracker flags are suppressed
// and it stops triggering tracker alerts. Stored per-device on device_telemetry.bt_safelist as a
// JSON array of {address,name,ts}. Listed here at module scope so both the REST endpoints and the
// socket handlers can share them.
async function getBtSafelist(devId) {
  try {
    const row = await db.prepare('SELECT bt_safelist FROM device_telemetry WHERE device_id=?').get(devId);
    if (row?.bt_safelist) {
      const arr = JSON.parse(row.bt_safelist);
      return Array.isArray(arr) ? arr.filter(x => x && x.address) : [];
    }
    return [];
  } catch { return []; }
}

async function setBtSafelist(devId, list) {
  await db.prepare(`INSERT INTO device_telemetry (device_id, bt_safelist, updated_at)
    VALUES (?,?,?)
    ON CONFLICT(device_id) DO UPDATE SET bt_safelist=excluded.bt_safelist, updated_at=excluded.updated_at`)
    .run(devId, JSON.stringify(list), Date.now());
}

  return {
    getBtSafelist,
    setBtSafelist,
  };
};