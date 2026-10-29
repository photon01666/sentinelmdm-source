// routes/file-backup-schedule.js — per-device File Backup schedule (GET/POST
// /api/devices/:id/file-backup/schedule) + the setFileBackupSchedule helper, extracted VERBATIM
// from server.js L5205-L5225 and registered in place via
// require('./routes/file-backup-schedule')({ ...deps }) — route-registration order is unchanged.
//
// The rest of the schedule section deliberately STAYS in server.js (Rule A — a helper with ANY
// caller outside the block must not move): getFileBackupSchedule is also called by
// pruneFileBackups (server.js, right below the block) and by the scheduled-run setInterval
// poller (~L12518), so it is injected as a ctx dep below — exactly one implementation.
// FILE_BACKUP_MIN_SCHEDULE_MINUTES is used ONLY by this block's setFileBackupSchedule, but it
// sits directly above the shared getFileBackupSchedule in server.js, so no contiguous range can
// include it without also moving the shared getter (the contiguity wall) — it too is left in
// server.js and injected; it is a const defined above the require site, so TDZ-clean.
//
// No relative-require or __dirname rebases were needed: the block contains neither.
module.exports = ({ FILE_BACKUP_MIN_SCHEDULE_MINUTES, app, db, getFileBackupSchedule, log, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked }) => {
async function setFileBackupSchedule(deviceId, partial) {
  const merged = (await getFileBackupSchedule(deviceId));
  for (const field of ['fullScheduleMinutes', 'incrementalScheduleMinutes', 'retentionDays', 'retentionCount']) {
    if (partial[field] === undefined) continue;
    const n = Number(partial[field]);
    if (Number.isFinite(n) && n >= 0) merged[field] = Math.round(n);
  }
  if (merged.incrementalScheduleMinutes > 0) merged.incrementalScheduleMinutes = Math.max(FILE_BACKUP_MIN_SCHEDULE_MINUTES, merged.incrementalScheduleMinutes);
  delete merged.scheduleHours; // fully migrated to fullScheduleMinutes on first write
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run('file_backup_schedule:' + deviceId, JSON.stringify(merged)));
}

app.get('/api/devices/:id/file-backup/schedule', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  res.json((await getFileBackupSchedule(req.params.id)));
});
app.post('/api/devices/:id/file-backup/schedule', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), requireRemoteAssistDevice, async (req, res) => {
  (await setFileBackupSchedule(req.params.id, req.body || {}));
  log('info', 'File Backup schedule updated', { deviceId: req.params.id, schedule: req.body });
  res.json({ ok: true });
});
};
