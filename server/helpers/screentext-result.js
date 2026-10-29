// helpers/screentext-result.js — scheduled screen-text analysis result (WebUI follow-up).
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// screentext core (setScreentextResult, runtime call) and the
// routes/screentext-schedule-and-history wiring (getScreentextResult).
//
// IN-PLACE splice at the block position (X = L4225). Resolution (A): the only
// consumer above the block is a runtime call inside the screentext core's body
// (executes at request time, long after this wiring line); the route wiring that
// consumes getScreentextResult sits BELOW the block.
//
// Stable deps by value: SCREENTEXT_RESULT_KEY (L4224), decryptText / encryptText
// (L133). db travels as the LIVE getter `getDb: () => db` (LIVE_READS pair; the
// canon rewrites every bare `db` read, so `getDb().prepare(...)`), called only
// inside the member bodies.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ SCREENTEXT_RESULT_KEY, decryptText, encryptText, getDb }) => {

async function getScreentextResult(deviceId) {
  const row = (await getDb().prepare('SELECT value FROM settings WHERE key=?').get(SCREENTEXT_RESULT_KEY + deviceId));
  if (!row) return null;
  try { const p = JSON.parse(row.value); if (p.reply) p.reply = decryptText(p.reply); return p; } catch { return null; }
}
async function setScreentextResult(deviceId, result) {
  const enc = { ...result, reply: encryptText(result.reply) };
  (await getDb().prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
    .run(SCREENTEXT_RESULT_KEY + deviceId, JSON.stringify(enc)));
}

return { getScreentextResult, setScreentextResult };

};
