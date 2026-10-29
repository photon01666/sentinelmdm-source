// helpers/backfill-tower-votes.js — one-shot correlation of STORED network
// snapshots with STORED GPS fixes, seeding learned tower votes.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the one-shot kickoff timer. Only the backfill function (and its private
// retry counter) move.
//
//   backfillTowerVotes   export   bounded, silent, single-replica backfill
//
// Wiring line sits IN-PLACE at the old block head (L5030) — every ctx dep is
// initialised above it (servingCellsFromSnapshot L4940, addTowerVote L4948),
// and the sole export consumer (the 45s setTimeout at L5079) is DEFERRED.
// Window: L5029-L5078 — the window INCLUDES `let _towerBackfillTries = 0;`
// (the plan run starts at L5030 and lists it as a dep, but the counter's only
// reader/writer is this block: `++_towerBackfillTries` inside the module would
// be a silent no-op write-through to a by-value ctx copy (check-ctx fatals
// "ASSIGNS TO A CTX DEP"), so the declaration travels with its sole consumer —
// hand-verified per the known `let`-cluster scanner blind spot.
//
// 8 ctx deps: AUTO_CALIB_MAX_GPS_ACC_M, addTowerVote, db, decryptText, kv, log,
// servingCellsFromSnapshot — all STABLE (const/function/destructure above the
// wiring line, never reassigned). getTowerBackfillDone / setTowerBackfillDone
// — LIVE read+write pair.
//
// getTowerBackfillDone/setTowerBackfillDone are a LIVE dep pair:
// _towerBackfillDone (L5028) is runtime-reassigned at 2 sites (L5034 — the
// retry-exhaustion flip, L5037 — the done flip). A by-value capture would see
// `false` forever and re-run the backfill on every retry tick. The getter reads
// the top-level `let _towerBackfillDone` at call time; the setter writes it
// back.
//   — R5: live vs stable documented here; R3: get/set are called ONLY inside
//     backfillTowerVotes's body, never at factory/module scope.
//
// Relative require REBASED: `require('./state')` -> `require('../state')`
// (one directory deeper from helpers/; measured, not assumed).

module.exports = ({ AUTO_CALIB_MAX_GPS_ACC_M, addTowerVote, db, decryptText, getTowerBackfillDone, kv, log, servingCellsFromSnapshot, setTowerBackfillDone }) => {

let _towerBackfillTries = 0;
async function backfillTowerVotes() {
  if (getTowerBackfillDone()) return;
  if (!require('../state').ENC_KEY) {
    if (++_towerBackfillTries < 30) setTimeout(() => backfillTowerVotes().catch(() => {}), 120000);
    else setTowerBackfillDone(true);
    return;
  }
  setTowerBackfillDone(true);
  // One replica only: all replicas share Redis and would triple-vote.
  try { if (!(await kv.setNX('towerbackfill:lock', 3600))) { log('info', 'Tower backfill skipped (claimed by another replica)'); return; } } catch {}
  try {
    const devs = (await db.prepare('SELECT id FROM devices').all()).map(r => r.id).filter(Boolean);
    let votes = 0;
    for (const devId of devs) {
      try {
        const nets = (await db.prepare('SELECT data, timestamp FROM network_events WHERE device_id=? ORDER BY timestamp DESC LIMIT 500').all(devId));
        if (!nets.length) continue;
        const t0 = Number(nets[nets.length - 1].timestamp) - 120000, t1 = Number(nets[0].timestamp) + 120000;
        const locRows = (await db.prepare('SELECT data, timestamp FROM locations WHERE device_id=? AND timestamp BETWEEN ? AND ? ORDER BY timestamp').all(devId, t0, t1));
        const locs = [];
        for (const lr of locRows) {
          try {
            const L = JSON.parse(decryptText(lr.data));
            if (Number.isFinite(L.lat) && Number.isFinite(L.lng) && Number.isFinite(L.accuracy) && L.accuracy <= AUTO_CALIB_MAX_GPS_ACC_M)
              locs.push({ t: Number(lr.timestamp), lat: L.lat, lng: L.lng, acc: L.accuracy });
          } catch {}
        }
        if (!locs.length) continue;
        for (const nr of nets) {
          const nt = Number(nr.timestamp);
          let best = null, bestDt = 90000;
          for (const L of locs) {
            const dt = Math.abs(L.t - nt);
            if (dt < bestDt) { bestDt = dt; best = L; }
            if (L.t > nt && dt > bestDt) break;
          }
          if (!best) continue;
          let nd = null;
          try { nd = JSON.parse(decryptText(nr.data)); } catch { continue; }
          const serving = servingCellsFromSnapshot(nd);
          if (!serving.length) continue;
          const w = Math.max(0.2, 1 - best.acc / (AUTO_CALIB_MAX_GPS_ACC_M * 2));
          for (const s of serving) { try { await addTowerVote(s, best.lat, best.lng, w, s.rssi); votes++; } catch {} }
        }
      } catch (e) { log('warn', 'tower backfill device failed', { deviceId: devId, error: e.message }); }
    }
    log('info', 'Tower backfill complete', { votes });
  } catch (e) { log('warn', 'tower backfill failed', { error: e.message }); }
}

return { backfillTowerVotes };

};
