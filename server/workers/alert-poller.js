// workers/alert-poller.js - worker-only poller: process unhandled alerts every 30 s.
//
// Picks up security alerts that nothing has handled yet and drives them through the AI
// auto-audit pipeline (helpers/alert-ai.js), bounded by the backlog-age and per-tick limits
// declared in server.js.
//
// Grouped by CONTIGUITY: the banner above it documents this poller, so it travels with it.
// `extraction-plan.py --pollers` computes that — a gap splits a group only when it holds code.
//
// A WORKER module: it registers a timer, not a route, and registers nothing when IS_WORKER is unset.
//
// The replacement call sits at the block's OWN first line (L8427), preserving registration
// order against the server.js lines around it.
//
// ctx: 8 deps. `log` and `triggerAutoAuditForAlert` are the only non-bindings that matter for
// position — `triggerAutoAuditForAlert` is destructured from the alert-ai require at L8425, so
// the call must sit at or after L8426. L8427 does. The AUDIT_* / AUTO_AUDIT_* constants are at
// L8386-L8408, all above. No upper bound: a poller registers a timer and nothing consumes it.
//
// No relative require to rebase — this block contains none.

module.exports = ({ AUDIT_BACKLOG_MAX_AGE_MS, AUDIT_POLL_LIMIT, AUDIT_STALE_MS, AUTO_AUDIT_REPORT_TAG, IS_WORKER, db, log, triggerAutoAuditForAlert }) => {
// ── Worker poller: process unhandled alerts every 30s ──
if (IS_WORKER) setInterval(async () => {
  try {
    // Fetch genuinely UNAUDITED alerts with a device_id, exclude agent-update noise.
    //
    // ⚠️ The NOT EXISTS is deliberately `NOT (stale running)`, not a plain "has any row". A plain
    // one would also hide the orphaned 'running' rows that isAlertUnprocessed()'s reaper exists to
    // clean up — the alert would never be re-selected, so the reaper would never see it and the
    // orphan fix would be silently dead. Only a row that is BOTH 'running' AND older than
    // AUDIT_STALE_MS lets its alert back through here; the reaper then deletes it and the alert
    // gets its audit. Keep these two predicates in sync.
    const staleCutoff = Date.now() - AUDIT_STALE_MS;
    const backlogCutoff = Date.now() - AUDIT_BACKLOG_MAX_AGE_MS;
    // Routine/informational categories are never auto-audited (mirrors ALERT_CAT_NO_AI in
    // app.js) — every geofence ENTER/EXIT, offline flap, or screenshot would otherwise each
    // burn a full bastion IT audit + AI analysis for no security value.
    const rows = (await db.prepare(
      "SELECT ua.id, ua.device_id, ua.user_id, ua.category, ua.message, ua.created_at " +
      "FROM user_alerts ua " +
      "WHERE ua.device_id IS NOT NULL " +
      "AND ua.category NOT IN ('ra_agent_update','geofence','offline','capture','winupdate_force','learn_mode','screentext') " +
      "AND ua.message NOT LIKE ? " +
      "AND ua.created_at > ? " +
      "AND NOT EXISTS (SELECT 1 FROM alert_auto_audits a WHERE a.alert_id = ua.id " +
      "AND NOT (a.status = 'running' AND a.created_at < ?)) " +
      `ORDER BY ua.created_at DESC LIMIT ${AUDIT_POLL_LIMIT}`
    ).all(`%${AUTO_AUDIT_REPORT_TAG}%`, backlogCutoff, staleCutoff)) || [];
    for (const row of rows) {
      try { (await triggerAutoAuditForAlert(row)); } catch (_) { /* one alert must never block others */ }
    }
  } catch (e) { log('warn', 'Auto-audit poller tick failed', { err: e.message }); }
}, 30 * 1000);

  // Nothing to return: registering the interval IS the side effect.
};
