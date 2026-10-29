// helpers/get-file-backup-schedule.js — get file backup schedule for a device.
//
// A HELPER module, not a route module: it registers nothing.
//
//   getFileBackupSchedule   export   get file backup schedule with defaults
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: db (binding L646).  The call must sit at or after L647; the earliest consumer of
// the export is L3963, so at or before L3962.  L3951 satisfies both.
//
// relative requires: none

module.exports = ({ db }) => {
async function getFileBackupSchedule(deviceId) {
  const defaults = { fullScheduleMinutes: 0, incrementalScheduleMinutes: 0, retentionDays: 30, retentionCount: 10 };
  const row = (await db.prepare("SELECT value FROM settings WHERE key=?").get('file_backup_schedule:' + deviceId));
  if (!row) return defaults;
  let parsed = {};
  try { parsed = JSON.parse(row.value) || {}; } catch { return defaults; }
  if (parsed.fullScheduleMinutes === undefined && parsed.scheduleHours !== undefined) {
    parsed.fullScheduleMinutes = Math.round(Number(parsed.scheduleHours) * 60) || 0;
  }
  return { ...defaults, ...parsed };
}

  return {
    getFileBackupSchedule,
  };
};