// ── Timezone-aware recurrence for per-app 'weekly_set' pause/unpause schedules ──
//
// A HELPER module, not a route module: nothing here registers a route or a socket
// handler. It exists to group seven timezone/DST helpers that were contiguous in
// server.js, and it exports the two that the scheduled-command worker calls.
//
// Note the factory shape: no ctx parameter, because these helpers depend on nothing
// in server.js. Zero deps is a legitimate dependency set, not a parse error.
module.exports = () => {
// tzOffsetMs: ms to ADD to a UTC instant to obtain the wall-clock in `tz` at that instant.
function tzOffsetMs(instant, tz) {
  const dtf = new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23',
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const p = {};
  for (const part of dtf.formatToParts(new Date(instant))) p[part.type] = part.value;
  return Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second) - instant;
}
// Convert a wall-clock (Y, M[0-based], D, H, Min in `tz`) to a UTC instant (DST-safe double offset).
function zonedWallToUtc(y, mo, d, h, mi, tz) {
  const guess = Date.UTC(y, mo, d, h, mi, 0);
  const o1 = tzOffsetMs(guess, tz);
  let result = guess - o1;
  const o2 = tzOffsetMs(result, tz);
  if (o2 !== o1) result = guess - o2;   // crossed a DST boundary — re-derive with the correct offset
  return result;
}
const _WEEKDAY = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
function weekdayInTz(instant, tz) {
  return _WEEKDAY[new Intl.DateTimeFormat('en-US', { timeZone: tz, weekday: 'short' }).format(new Date(instant))];
}
function ymdInTz(instant, tz) {
  const dtf = new Intl.DateTimeFormat('en-US', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' });
  const p = {};
  for (const part of dtf.formatToParts(new Date(instant))) p[part.type] = part.value;
  return { y: +p.year, mo: +p.month - 1, d: +p.day };
}
function wallTimeInTz(instant, tz) {
  const p = {};
  for (const part of new Intl.DateTimeFormat('en-US', { timeZone: tz, hourCycle: 'h23', hour: '2-digit', minute: '2-digit' }).formatToParts(new Date(instant))) p[part.type] = part.value;
  return { hour: +p.hour, minute: +p.minute };
}
// Next instant strictly after fromMs whose weekday ∈ daysArr at local hour:minute in tz.
function nextWeeklySetRun(fromMs, hour, minute, daysArr, tz) {
  const base = ymdInTz(fromMs, tz);
  for (let i = 0; i <= 8; i++) {                 // scan ~a week + slack (Date.UTC normalizes day overflow)
    const cand = zonedWallToUtc(base.y, base.mo, base.d + i, hour, minute, tz);
    if (cand > fromMs && daysArr.includes(weekdayInTz(cand, tz))) return cand;
  }
  return null;
}
// The five internal helpers (tzOffsetMs, zonedWallToUtc, _WEEKDAY, weekdayInTz,
// ymdInTz) have no caller outside this file, so they stay private -- returning them
// would widen the module's surface for no reason.
return { wallTimeInTz, nextWeeklySetRun };
};
