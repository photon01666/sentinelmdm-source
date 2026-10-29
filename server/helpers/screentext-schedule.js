// helpers/screentext-schedule.js - the per-device scheduled screen-text analysis window.
//
// A HELPER module, not a route module: it registers nothing. It serves the socket handler
// (which schedules and reports), the AI screen-text routes, and
// routes/screentext-schedule-and-history.js.
//
//   getScreentextSchedule   export   the device's current schedule window, if any
//   setScreentextSchedule   export   install/replace that window
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 2 deps, both `const` bindings: SCREENTEXT_SCHEDULE_KEY (L5575) and db (L723).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ SCREENTEXT_SCHEDULE_KEY, db }) => {
// ── Scheduled Screen-text Analysis (agent-triggered; DeepSeek via OpenCode) ──
// The AGENT fires a scheduled_screentext_analysis event at the device-local scheduled
// time. For NON-ZK devices the server analyzes its OWN stored screen_text_entries since
async function getScreentextSchedule(deviceId) {
  const row = (await db.prepare('SELECT value FROM settings WHERE key=?').get(SCREENTEXT_SCHEDULE_KEY + deviceId));
  if (!row) return { enabled: false, hour: 20, minute: 0, lastAnalyzedDate: null, lastAnalyzedAt: null, lastAnalyzedTs: null, timeZoneOffsetMinutes: 0 };
  try {
    const v = JSON.parse(row.value);
    v.minute = v.minute ?? 0;
    v.lastAnalyzedTs = v.lastAnalyzedTs ?? null;
    v.lastAnalyzedAt = v.lastAnalyzedAt ?? null;
    v.quietHoursStart = v.quietHoursStart ?? 23;
    v.quietHoursEnd = v.quietHoursEnd ?? 7;
    // Device-local UTC offset (minutes) reported by the agent so report timestamps render in
    // the device's own timezone. 0 until the agent first reports it.
    v.timeZoneOffsetMinutes = v.timeZoneOffsetMinutes ?? 0;
    return v;
  } catch { return { enabled: false, hour: 20, minute: 0, lastAnalyzedDate: null, lastAnalyzedAt: null, lastAnalyzedTs: null, timeZoneOffsetMinutes: 0 }; }
}
async function setScreentextSchedule(deviceId, cfg) {
  const hour = Math.max(0, Math.min(23, Number(cfg.hour) ?? 20));
  const minute = Math.max(0, Math.min(59, Number(cfg.minute) ?? 0));
  // Explicitly pass null to reset; omit to preserve existing
  let lastAnalyzedDate;
  if ('lastAnalyzedDate' in cfg) {
    lastAnalyzedDate = cfg.lastAnalyzedDate || null;
  } else {
    const existing = await getScreentextSchedule(deviceId);
    lastAnalyzedDate = existing.lastAnalyzedDate || null;
  }
  let lastAnalyzedAt;
  if ('lastAnalyzedAt' in cfg) {
    lastAnalyzedAt = cfg.lastAnalyzedAt || null;
  } else {
    const existing = await getScreentextSchedule(deviceId);
    lastAnalyzedAt = existing.lastAnalyzedAt || null;
  }
  // lastAnalyzedTs is the incremental epoch-ms cursor the server uses to pull stored
  // screen text for non-ZK reports. Preserve unless explicitly reset/advanced.
  let lastAnalyzedTs;
  if ('lastAnalyzedTs' in cfg) {
    lastAnalyzedTs = cfg.lastAnalyzedTs ?? null;
  } else {
    const existing = await getScreentextSchedule(deviceId);
    lastAnalyzedTs = existing.lastAnalyzedTs ?? null;
  }
  // Device-local UTC offset (minutes). Preserve unless explicitly provided/cleared.
  let timeZoneOffsetMinutes;
  if ('timeZoneOffsetMinutes' in cfg) {
    timeZoneOffsetMinutes = Math.max(-840, Math.min(840, Math.round(Number(cfg.timeZoneOffsetMinutes) || 0)));
  } else {
    const existing = await getScreentextSchedule(deviceId);
    timeZoneOffsetMinutes = existing.timeZoneOffsetMinutes ?? 0;
  }
  // Quiet hours window (configurable from WebUI). Preserve unless explicitly provided.
  let quietHoursStart;
  if ('quietHoursStart' in cfg) {
    quietHoursStart = Math.max(0, Math.min(23, Math.round(Number(cfg.quietHoursStart) || 0)));
  } else {
    const existing = await getScreentextSchedule(deviceId);
    quietHoursStart = existing.quietHoursStart ?? 23;
  }
  let quietHoursEnd;
  if ('quietHoursEnd' in cfg) {
    quietHoursEnd = Math.max(0, Math.min(23, Math.round(Number(cfg.quietHoursEnd) || 0)));
  } else {
    const existing = await getScreentextSchedule(deviceId);
    quietHoursEnd = existing.quietHoursEnd ?? 7;
  }
  const val = JSON.stringify({ enabled: !!cfg.enabled, hour, minute, lastAnalyzedDate, lastAnalyzedAt, lastAnalyzedTs, timeZoneOffsetMinutes, quietHoursStart, quietHoursEnd });
  (await db.prepare('INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value')
    .run(SCREENTEXT_SCHEDULE_KEY + deviceId, val));
}

  return {
    getScreentextSchedule,
    setScreentextSchedule,
  };
};
