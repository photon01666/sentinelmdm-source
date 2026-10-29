// helpers/telemetry-flush.js — flush the location + ZK-payload telemetry
// buffers to the DB, and append audio segments onto finalized media rows.
//
// A HELPER module, not a route module: it registers nothing. server.js owns
// the scheduling (flushTelemetry + the shutdown hook). Only the flush/append
// functions move.
//
//   appendToAudioMedia   export   append a segment onto a finalized media row
//   flushLocations       export   flush locationBuffer + deviceLocLatest to DB
//   flushZkPayloads      export   flush zkPayloadBuffer to DB
//
// ctx is available at this module's own position in server.js (X >= L3713,
// X <= L3773) — nothing had to move (IN-PLACE splice).
//
// 15 ctx deps: db, decryptText, deviceLocLatest, encryptText, isPg, locColSet,
// log, pgConn, pgp, stmts, zkColSet — all STABLE (const/function/destructure
// above the wiring line, never reassigned). getLocationBuffer /
// setLocationBuffer and getZkPayloadBuffer / setZkPayloadBuffer — LIVE
// read+write pairs.
//
// getLocationBuffer/setLocationBuffer are a LIVE dep pair:
// locationBuffer (L3706) is runtime-reassigned at 1 site (L3741 — the
// flush-and-clear in flushLocations). A by-value capture would clear the WRONG
// array after the first flush (the by-value copy) and silently drop every
// subsequent row. The getter reads the top-level `let locationBuffer` at call
// time; the setter writes it back.
//
// getZkPayloadBuffer/setZkPayloadBuffer are a LIVE dep pair:
// zkPayloadBuffer (L3707) is runtime-reassigned at 1 site (L3761 — the
// flush-and-clear in flushZkPayloads). Same stale-snapshot failure mode. The
// getter reads the top-level `let zkPayloadBuffer` at call time; the setter
// writes it back.
//   — R5: live vs stable documented here; R3: get/set are called ONLY inside
//     the function bodies, never at factory/module scope.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ db, decryptText, deviceLocLatest, encryptText, getLocationBuffer, getZkPayloadBuffer, isPg, locColSet, log, pgConn, pgp, setLocationBuffer, setZkPayloadBuffer, stmts, zkColSet }) => {

async function appendToAudioMedia(mediaId, newB64) {
  const row = (await db.prepare('SELECT data FROM media WHERE id=?').get(mediaId));
  if (!row) return;   // clip was deleted (by the user, or 30-day TTL) in the meantime — nothing to append to
  const combined = Buffer.concat([
    Buffer.from(decryptText(row.data), 'base64'),
    Buffer.from(newB64, 'base64'),
  ]).toString('base64');
  (await db.prepare('UPDATE media SET data=? WHERE id=?').run(encryptText(combined), mediaId));
}

async function flushLocations() {
  if (getLocationBuffer().length) {
    const rows = getLocationBuffer(); setLocationBuffer([]);
    try {
      if (isPg) await pgConn.none(pgp.helpers.insert(rows, locColSet));        // one multi-row INSERT
      else await db.transaction(async () => {
        for (const r of rows) await stmts.insertLocation.run(r.device_id, r.data, r.timestamp);
      })();
    } catch (e) { log('error', 'flushLocations failed — dropped batch', { error: e.message, rows: rows.length }); }
  }
  if (deviceLocLatest.size) {
    const updates = [...deviceLocLatest]; deviceLocLatest.clear();             // [[deviceId, [lat,lng,seen,batt]]]
    try {
      await db.transaction(async () => {                                       // coalesced UPDATEs, one commit
        for (const [id, v] of updates) await stmts.updateDeviceLoc.run(v[0], v[1], v[2], v[3], id);
      })();
    } catch (e) { log('error', 'flushLocations (current-loc) failed', { error: e.message, n: updates.length }); }
  }
}

async function flushZkPayloads() {
  if (!getZkPayloadBuffer().length) return;
  const rows = getZkPayloadBuffer(); setZkPayloadBuffer([]);
  try {
    if (isPg) await pgConn.none(pgp.helpers.insert(rows, zkColSet));           // one multi-row INSERT
    else await db.transaction(async () => {
      for (const r of rows) await stmts.insertZkPayload.run(r.device_id, r.event_type, r.payload, r.dek_wrapped, r.timestamp);
    })();
  } catch (e) { log('error', 'flushZkPayloads failed — dropped batch', { error: e.message, rows: rows.length }); }
}

return { appendToAudioMedia, flushLocations, flushZkPayloads };

};