// workers/scheduled-commands.js - worker poller: dispatch due scheduled commands every 30 s.
//
// A WORKER module: it registers a timer, not a route. It only does anything when IS_WORKER is
// set, so replicas that are not workers load it and register nothing.
//
// Replaces one `if (IS_WORKER) setInterval(...)` block from server.js. The replacement call
// sits at the block's OWN first line, which is what preserves registration ORDER relative to
// the ~1,400 lines of server.js that sit between this and the other pollers.
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 6 of the 14 deps are `function` declarations and hoist; `nextWeeklySetRun` and
// `wallTimeInTz` are destructured at L8019; the rest are bindings at L28, L723, L789-L799.
// The binding furthest down is `wallTimeInTz`/`nextWeeklySetRun` at L8019, so the call must
// sit at or after L8020. L8297 does.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ IS_WORKER, SURVEIL_START_CMDS, SURVEIL_STOP_CMDS, db, decryptDevice, emitToDevice, isDeviceOnline, log, nextWeeklySetRun, notifyOwnerForCommand, stmts, surveilStart, surveilStop, wallTimeInTz }) => {
if (IS_WORKER) setInterval(async () => {
  const now = Date.now();
  const due = (await db.prepare('SELECT * FROM scheduled_commands WHERE enabled=1 AND next_run<=?').all(now));
  for (const sched of due) {
    try {
      if (await isDeviceOnline(sched.device_id)) {
        const params = JSON.parse(sched.params || '{}');
        emitToDevice(sched.device_id, 'command', { command: sched.command, ...params });
        const schedDev = decryptDevice((await stmts.getDevice.get(sched.device_id)));
        (await notifyOwnerForCommand(sched.device_id, sched.command, schedDev?.name));
        if (SURVEIL_START_CMDS[sched.command])     surveilStart(sched.device_id, SURVEIL_START_CMDS[sched.command]).catch(() => {});
        else if (SURVEIL_STOP_CMDS[sched.command]) surveilStop(sched.device_id,  SURVEIL_STOP_CMDS[sched.command]).catch(() => {});
        log('info', 'Scheduled command executed', { deviceId: sched.device_id, command: sched.command });
      }
      let nextRun = null;
      if (sched.repeat_type === 'daily')   nextRun = now + 86400000;
      if (sched.repeat_type === 'hourly')  nextRun = now + 3600000;
      if (sched.repeat_type === 'weekly')  nextRun = now + 7 * 86400000;
      if (sched.repeat_type === 'weekly_set') {
        // Per-app pause/unpause window on a fixed weekday set, anchored to the wall-clock
        // time of run_at in the schedule's tz (correct across DST; no fixed-interval drift).
        const tz = sched.tz || 'UTC';
        const daysArr = String(sched.days || '').split(',').map(s => parseInt(s, 10)).filter(n => !isNaN(n));
        if (daysArr.length) {
          const { hour, minute } = wallTimeInTz(sched.run_at, tz);
          nextRun = nextWeeklySetRun(now, hour, minute, daysArr, tz);
        }
      }
      if (nextRun) {
        (await db.prepare('UPDATE scheduled_commands SET last_ran=?,next_run=? WHERE id=?').run(now, nextRun, sched.id));
      } else {
        (await db.prepare('UPDATE scheduled_commands SET last_ran=?,enabled=0 WHERE id=?').run(now, sched.id));
      }
    } catch (e) { log('error', 'Scheduled command error', { id: sched.id, error: e.message }); }
  }
}, 30000);  // check every 30 s
  // Nothing to return: registering the interval IS the side effect.
};
