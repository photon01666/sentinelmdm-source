// helpers/load-known-towers.js — resolve cell identities against cell_towers.
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// cell-history (L4404) and cell-fix (L4443) wirings — both eager, both BELOW the
// wiring line (D1b R2 cascade hoisted the wirings this module needs).
//
//   loadKnownTowers   export   Map(key -> tower row), OpenCellID fallback
//
// Wiring RELOCATED above its earliest eager consumer (cell-history wiring,
// L4404) via the D1b R2 cascade: helpers/ocid-miss-cache.js +
// helpers/wigle-miss-cache.js hoisted the miss caches, and the wigle-ocid-lookup
// wiring (which creates `lookupOcidTower`) was moved above this point. Deps:
//   * _ocidMissCache — from helpers/ocid-miss-cache.js, wired above.
//   * getCellKey — LIVE getter over cellKey (L~4401, above): the value usage
//     `cells.map(cellKey)` is rewritten to `cells.map(getCellKey())` (canon
//     rewrites bare non-call reads to the getter form).
//   * lookupOcidTower — stable const from the wigle-ocid-lookup wiring, moved
//     above this line; the call sites stay bare (calls are not rewritten).
//   * db travels as the LIVE getter `getDb: () => db` (reads rewritten).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ _ocidMissCache, getCellKey, getDb, lookupOcidTower }) => {

async function loadKnownTowers(cells) {
  if (!cells.length) return new Map();
  const keys = [...new Set(cells.map(getCellKey()))];
  const towers = new Map();
  try {
    for (const k of keys) {
      const [mcc, mnc, tac, cid] = k.split('-').map(Number);
      let row = (await getDb().prepare('SELECT * FROM cell_towers WHERE mcc=? AND mnc=? AND tac=? AND cid=?').get(mcc, mnc, tac, cid));
      if (!row && process.env.OCID_API_KEY && (_ocidMissCache.get(k) || 0) <= Date.now()) {
        row = await lookupOcidTower(mcc, mnc, tac, cid);
      }
      if (row) towers.set(k, row);
    }
  } catch {}
  return towers;
}

return { loadKnownTowers };

};
