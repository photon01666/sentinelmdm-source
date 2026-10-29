// routes/screentext-schedule-and-history.js — per-device scheduled screen-text analysis:
// schedule get/set, stored daily-report result, and AI-history purge. Extracted from
// server.js L10180-10227. 4 routes.
module.exports = ({ SCREENTEXT_MEMORY_KEY, SCREENTEXT_RESULT_KEY, app, db, emitToDevice, getScreentextResult, getScreentextSchedule, log, requireAuth, requireDeviceAccess, requireDeviceController, requireUnlocked, setScreentextSchedule }) => {
app.get('/api/devices/:id/screentext-schedule', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  res.json(await getScreentextSchedule(req.params.id));
});

app.get('/api/devices/:id/screentext-schedule-result', requireUnlocked, requireAuth, requireDeviceAccess, async (req, res) => {
  const result = await getScreentextResult(req.params.id);
  if (!result) return res.json({ result: null });
  res.json({ result });
});

app.post('/api/devices/:id/screentext-schedule', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  const { enabled, hour, minute, quietHoursStart, quietHoursEnd, timeZoneOffsetMinutes } = req.body || {};
  const existing = await getScreentextSchedule(req.params.id);
  // Fall back to the current values when the body omits fields — otherwise a bare
  // enable/disable toggle would silently reset the schedule to 20:00 (the set* default).
  const h = Number.isFinite(Number(hour)) ? Math.max(0, Math.min(23, Math.round(Number(hour)))) : (existing.hour ?? 20);
  const m = Number.isFinite(Number(minute)) ? Math.max(0, Math.min(59, Math.round(Number(minute)))) : (existing.minute ?? 0);
  const qs = Number.isFinite(Number(quietHoursStart)) ? Math.max(0, Math.min(23, Math.round(Number(quietHoursStart)))) : (existing.quietHoursStart ?? 23);
  const qe = Number.isFinite(Number(quietHoursEnd)) ? Math.max(0, Math.min(23, Math.round(Number(quietHoursEnd)))) : (existing.quietHoursEnd ?? 7);
  // Capture the browser's local timezone offset so the safety net fires at the correct
  // *local* time.  Android agents push this via the socket event; Windows has no agent,
  // so the WebUI is the only source.
  const tz = Number.isFinite(Number(timeZoneOffsetMinutes))
    ? Math.max(-840, Math.min(840, Math.round(Number(timeZoneOffsetMinutes))))
    : (existing.timeZoneOffsetMinutes ?? 0);
  const timeChanged = h !== (existing.hour ?? 20) || m !== (existing.minute ?? 0);
  // Reset ONLY lastAnalyzedAt/lastAnalyzedDate when the time changes so the analysis can run
  // again today. lastAnalyzedTs is deliberately PRESERVED: a re-run must be incremental
  // (analyze only data captured since the last successful analysis).
  const resetFields = timeChanged ? { lastAnalyzedDate: null, lastAnalyzedAt: null } : {};
  await setScreentextSchedule(req.params.id, { enabled: !!enabled, hour: h, minute: m, quietHoursStart: qs, quietHoursEnd: qe, timeZoneOffsetMinutes: tz, ...resetFields });
  log('info', `Screen-text schedule ${enabled ? 'ENABLED' : 'disabled'} (hour=${h}, minute=${m}, quiet=${qs}-${qe}${timeChanged ? ', reset analysis cursor' : ''})`, { deviceId: req.params.id });
  // Push schedule state to live agent so it takes effect immediately
  emitToDevice(req.params.id, 'command', { command: 'set_screentext_schedule', enabled: !!enabled, hour: h, minute: m, quietHoursStart: qs, quietHoursEnd: qe });
  res.json({ ok: true, ...(await getScreentextSchedule(req.params.id)) });
});

// Purge a device's saved AI state: the stored daily report (screentext_schedule_result)
// and the rolling AI memory (screentext_ai_memory). The schedule itself and the screen-text
// capture data are untouched — only the AI artifacts are removed. The client also clears its
// browser-side chat/dedup keys on success.
app.delete('/api/devices/:id/screentext-ai-history', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  const deviceId = req.params.id;
  await db.prepare('DELETE FROM settings WHERE key IN (?,?)')
    .run(SCREENTEXT_RESULT_KEY + deviceId, SCREENTEXT_MEMORY_KEY + deviceId);
  log('info', 'Screen-text AI history purged', { deviceId });
  res.json({ ok: true });
});
};
