// helpers/screentext-memory.js — rolling per-device screentext AI memory.
//
// A HELPER module, not a route module: it registers nothing. All consumers are
// runtime calls inside the screentext core's body (getScreentextMemory /
// buildScreentextMemoryContext / pushScreentextMemory at L4067/L4068/L4116) —
// the core executes at request time, long after this wiring line.
//
// IN-PLACE splice at the block position (X = L4233). Resolution (A): every
// consumer above the block is inside a function body (runtime-only); no
// load-time ctx capture references these members.
//
// Stable deps by value: SCREENTEXT_MEMORY_KEY (L4231), SCREENTEXT_MEMORY_MAX
// (L4232), decryptText / encryptText (L133). db travels as the LIVE getter
// `getDb: () => db` (LIVE_READS pair; reads are rewritten to `getDb().prepare`),
// called only inside the member bodies.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ SCREENTEXT_MEMORY_KEY, SCREENTEXT_MEMORY_MAX, decryptText, encryptText, getDb }) => {

async function getScreentextMemory(deviceId) {
  const row = (await getDb().prepare('SELECT value FROM settings WHERE key=?').get(SCREENTEXT_MEMORY_KEY + deviceId));
  if (!row) return [];
  try {
    const arr = JSON.parse(row.value);
    return (Array.isArray(arr) ? arr : []).map(e => {
      try { if (e && e.reply) e.reply = decryptText(e.reply); } catch {}
      return e;
    }).filter(e => e && e.date);
  } catch { return []; }
}
async function pushScreentextMemory(deviceId, entry) {
  const mem = await getScreentextMemory(deviceId);
  mem.push(entry);
  while (mem.length > SCREENTEXT_MEMORY_MAX) mem.shift();
  const enc = mem.map(e => ({ ...e, reply: encryptText(e.reply) }));
  (await getDb().prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
    .run(SCREENTEXT_MEMORY_KEY + deviceId, JSON.stringify(enc)));
}
// Build the continuity context block from past reports. Each prior report is truncated so the
// memory never dominates the current day's log context.
function buildScreentextMemoryContext(memory) {
  if (!memory.length) return '';
  const parts = memory.map((m, i) => {
    const body = typeof m.reply === 'string' ? m.reply.slice(0, 3000) : '';
    return `--- Prior daily report ${m.date} ---\n${body}`;
  });
  return '\n\n=== PRIOR DAILY REPORTS (for continuity) ===\n' + parts.join('\n\n');
}

return { buildScreentextMemoryContext, getScreentextMemory, pushScreentextMemory };

};
