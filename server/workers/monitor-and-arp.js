// workers/monitor-and-arp.js - two worker-only pollers: live-stream enforcement and ARP ingest.
//
// Grouped by CONTIGUITY, not by theme: these two sit back-to-back with nothing between them but
// their own banners, so moving them as one span keeps each poller's doc comment attached to it.
// `extraction-plan.py --pollers` computes the grouping — a gap splits them only when it holds
// real code.
//
//   live-monitoring loop (30 s)     enforce the 10-minute hard cap per active stream, and the
//                                   public-owner daily recording cap; alert on cap/auto-stop
//   ARP scan ingest (15 min)        ingest ARP scan results and emit the AI summary email
//
// A WORKER module: it registers timers, not routes, and registers nothing when IS_WORKER is unset.
//
// The replacement call sits at the group's OWN first line (L8310), preserving the relative
// registration order of both pollers against the server.js lines around them.
//
// ctx: 18 deps. 9 are `function` declarations and hoist. `PUBLIC_STREAM_REC_DAILY_CAP_SEC`
// (L5079) is the lowest non-hoisted binding, so the call must sit at or after L5080. L8310 does.
// No upper bound: a poller registers a timer and nothing consumes it.
//
// bastionClient is NOT a ctx dep and must not become one — its function-local lazy require at
// the old L8393 stays lazy and rebases to '../'.

module.exports = ({ IS_WORKER, PUBLIC_STREAM_REC_DAILY_CAP_SEC, SURVEIL_LABEL, SURVEIL_MAX_MS, SURVEIL_STOP_CMD_FOR, arpAiSummaryDue, db, decryptText, emitToDevice, fmtHm, generateArpAiSummary, getArpSweepWatchEnabled, ingestArpScanResult, ingestArpSweepEvents, io, kv, log, sendAiReportEmail, surveilNotify }) => {
// ── Live-monitoring loop (worker only — one instance, so no duplicate alerts) ─────
// Every 30s: enforce the 10-minute hard cap on each active live stream/track (force-stop
// + "auto-stopped, restart manually" alert) and the public-owner daily recording cap.
// Owners are alerted on ACTIVATION and on CAP/AUTO-STOP only — the former recurring 60s
// "still being monitored" pulse was removed 2026-08-21 (alert fatigue). Routing (public
// owner email/push vs admin Signal) and the can't-be-turned-off behaviour live in
// surveilNotify/notifyUser.
if (IS_WORKER) setInterval(async () => {
  let ids;
  try { ids = (await kv.smembers('surveil:active')); } catch { return; }
  const now = Date.now();
  for (const deviceId of ids) {
    try {
      const cur = (await kv.getJSON(`surveil:${deviceId}`));
      if (!cur?.types || !Object.keys(cur.types).length) {
        await kv.srem('surveil:active', deviceId); await kv.del(`surveil:${deviceId}`); continue;
      }
      // 1) 10-minute hard cap — force-stop any type that's been live for >= 10 min.
      for (const [type, startedAt] of Object.entries({ ...cur.types })) {
        if (now - startedAt >= SURVEIL_MAX_MS) {
          emitToDevice(deviceId, 'command', { command: SURVEIL_STOP_CMD_FOR[type] });
          // Tell any open monitor session too — the device stops sending frames, but without
          // this the browser's MediaRecorder (Stream/Screen Clips) has no signal to stop and
          // would keep re-encoding a frozen canvas indefinitely.
          io.to(`monitor:${deviceId}`).emit('surveil_cap_stopped', { deviceId, type, reason: '10min' });
          delete cur.types[type];
          await surveilNotify(cur, `${SURVEIL_LABEL[type]} AUTO-STOPPED — 10-minute limit reached. Restart it manually to continue.`);
          log('info', 'Surveillance 10-min cap — force-stopped', { deviceId, type });
        }
      }
      // 1.5) Daily 1-hour recording cap — camera/screen only, public-owned devices only.
      // Debits 30s per tick (this loop's own cadence) for whichever of those types is still
      // active, keyed per account+type (independent pools, not a shared budget), and
      // force-stops once the account's daily total is reached — same mechanism as the 10-min
      // cap above, just against a rolling-24h accumulator instead of a per-session clock.
      if (cur.ownerType === 'public' && cur.ownerUserId) {
        for (const type of Object.keys(cur.types)) {
          if (type !== 'camera' && type !== 'screen') continue;
          const key  = `streamrec:${type}:${cur.ownerUserId}`;
          const used = (await kv.incrByWindow(key, 30, 24 * 60 * 60));
          if (used >= PUBLIC_STREAM_REC_DAILY_CAP_SEC) {
            emitToDevice(deviceId, 'command', { command: SURVEIL_STOP_CMD_FOR[type] });
            io.to(`monitor:${deviceId}`).emit('surveil_cap_stopped', { deviceId, type, reason: 'daily' });
            delete cur.types[type];
            const ttl      = (await kv.ttl(key));
            const resetIn  = ttl > 0 ? fmtHm(ttl) : '24h';
            const capLabel = fmtHm(PUBLIC_STREAM_REC_DAILY_CAP_SEC);
            await surveilNotify(cur, `${SURVEIL_LABEL[type]} AUTO-STOPPED — daily ${capLabel} recording limit reached. Resets in ${resetIn}.`);
            log('info', 'Daily recording cap — force-stopped', { deviceId, type, used });
          }
        }
      }
      // 2) Bookkeeping only — NO recurring alert here. The 60s "still being monitored" pulse
      // was removed 2026-08-21; a session now alerts at START and when a cap stops it, nothing
      // in between. We still persist every tick because the caps above mutate cur.types in
      // memory (a cap-stopped type must not resurrect from the stale Redis copy next tick),
      // and clean the keys out entirely once nothing remains active.
      if (Object.keys(cur.types).length) {
        await kv.setJSON(`surveil:${deviceId}`, cur);
      } else {
        await kv.srem('surveil:active', deviceId); await kv.del(`surveil:${deviceId}`);
      }
    } catch (e) { log('warn', 'surveillance loop error', { deviceId, error: e.message }); }
  }
}, 30000);

// ── ARP scan ingest + AI-report email poller (worker only — one instance) ────────────────────
// Two independent jobs, same tick, both scoped to Remote Assist devices (Windows AND Linux —
// platform filter widened 2026-08-05: the Linux-parity feature makes Linux boxes scan on the
// same schedule, and excluding them meant their selfMacs never reached ingestArpScanResult →
// device_self_macs stayed empty → sweep-suppression by identity never matched) with a real
// PUBLIC owner (the "Notifications" modal these emails are configured from is a public-account-
// only surface — admin-fleet devices have no equivalent owner to email; see the AI_REPORT_
// CATEGORIES/ai_reports notif-prefs wiring). Every 15 min to match the bastion's own cron
// cadence (see arp-scan-tick.sh/daily-audit.sh) — no point polling faster than the underlying
// bastion-side data can actually change.
//   1) ARP scan: pull whatever the bastion's own schedule (or a manual click) most recently
//      cached, diff it into the persisted roster, and — rate-limited to once/day per device via
//      arpAiSummaryDue() — generate + optionally email an AI network summary.
//   2) IT Mode Audit: the summary already exists (bastion-side OpenCode/DeepSeek analysis, its
//      own cadence controlled by audit_schedule_hours) — this just notices when a NEWER one has
//      landed than what was last emailed and sends it, no separate AI call needed here.
if (IS_WORKER) setInterval(async () => {
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return;
  let devices;
  try {
    devices = (await db.prepare(
      "SELECT d.id, d.owner_user_id, d.name FROM devices d JOIN users u ON d.owner_user_id=u.id " +
      "WHERE d.platform IN ('windows','linux') AND d.agent_kind='remote_assist' AND u.account_type='public'"
    ).all());
  } catch (e) { log('warn', 'AI-report poller: device query failed', { err: e.message }); return; }
  for (const dev of devices) {
    const deviceId = dev.id;
    const ownerUserId = dev.owner_user_id;
    const deviceName = (dev.name && !String(dev.name).startsWith('ENC:')) ? dev.name : (decryptText(dev.name) || deviceId);
    // Hoisted out of the try so the AI-summary block below can reuse it: arp-scan-status now
    // reports the session's live `connected` flag, and the summary must never run for a device
    // that's offline (its persisted roster is only as fresh as the last scan that ran while the
    // Hop-1 tunnel was up -- generating from stale data burns the once/day budget AND emails the
    // owner a misleading "current devices on this network" summary).
    let scan = null;
    try {
      scan = (await bastionClient.arpScanStatus(deviceId));
      if (scan?.ok && scan?.scanned) (await ingestArpScanResult(deviceId, scan));
    } catch (e) { /* one unreachable box must never block the others */ }
    try {
      // Gated on the cheap stored flag -- draining is a LIVE hop2 SSH round trip (SCP + exec),
      // unlike the roster scan's cheap bastion-cached read above, so unconditionally attempting it
      // for every device every 15 min was hammering bastion (and every device's tunnel) for a
      // feature almost nobody has turned on. Found live 2026-07-18: this was the actual root cause
      // of a "bastion hangs, dashboard laggy" report -- BrokenPipeErrors and an SSH-level "Timeout,
      // client not responding" in bastion's logs, consistent with a struggling device's tunnel
      // getting hit on both the arp-scan AND (newly) arp-sweep-drain paths every single tick.
      if ((await getArpSweepWatchEnabled(deviceId))) {
        const sweep = (await bastionClient.arpSweepDrainEvents(deviceId));
        if (sweep?.ok && Array.isArray(sweep.events) && sweep.events.length) {
          (await ingestArpSweepEvents(deviceId, sweep.events));
        } else if (!sweep?.ok) {
          // Was a bare silent no-op before (matching the outer catch's own "one unreachable box
          // must never block the others" comment, which explains why a failure here shouldn't
          // THROW, but never justified making it invisible). Found live 2026-07-18: a real drain
          // failure and "nothing to drain" were indistinguishable from the logs alone, and the
          // former can persist indefinitely with zero visibility that anything is wrong.
          log('warn', 'ARP sweep drain returned non-ok', { deviceId, error: sweep?.error || 'unknown' });
        }
      }
    } catch (e) { log('warn', 'ARP sweep drain/ingest failed', { deviceId, err: e.message }); }
    try {
      // Never generate or email the network AI summary for an OFFLINE device. `scan.connected`
      // is the bastion's live Hop-1 tunnel probe from the call above (a fetch failure leaves
      // scan null → skipped too; the once/day due-check is timestamp-based, so it just retries
      // on a later tick once the device is back).
      if (scan && scan.connected === true && (await arpAiSummaryDue(deviceId))) {
        const result = (await generateArpAiSummary(deviceId));
        if (result) {
          const sent = (await sendAiReportEmail(ownerUserId, 'arp_summary', 'Daily Network Summary', deviceName, result.summary));
          if (sent) (await db.prepare(
            'INSERT INTO ai_report_email_state (device_id,last_arp_email_at) VALUES (?,?) ' +
            'ON CONFLICT(device_id) DO UPDATE SET last_arp_email_at=excluded.last_arp_email_at'
          ).run(deviceId, Date.now()));
        }
      }
    } catch (e) { log('warn', 'ARP AI summary/email failed', { deviceId, err: e.message }); }
    try {
      // Skip audit email when the device is offline — the cached result is stale and
      // emailing it would mislead the owner into thinking this is a current finding.
      // The watermark check means it retries on the next 15-min tick once back online.
      if (!scan || scan.connected !== true) continue;
      const audit = (await bastionClient.sessionAuditCached(deviceId));
      // audit_collected_at_epoch is a Python time.time() value — SECONDS, not ms.
      const collectedAtMs = (audit?.collectedAtEpoch || 0) * 1000;
      // Compromise-only emailing: a CLEAN audit is the normal, expected outcome of an IT Mode
      // Audit and emails nothing (the dashboard verdict + bastion's own ATTENTION-NEEDED Signal
      // alert already cover the clean/attention states). Only ATTENTION NEEDED (any non-CLEAN
      // collected verdict) gets emailed to the owner, deduped by the watermark as before.
      if (audit?.summary && collectedAtMs && audit.verdict !== 'CLEAN') {
        const watermark = (await db.prepare('SELECT last_audit_email_at FROM ai_report_email_state WHERE device_id=?').get(deviceId));
        if (collectedAtMs > (watermark?.last_audit_email_at || 0)) {
          const title = `IT Mode Audit — ${audit.verdict || 'PENDING'}`;
          const sent = (await sendAiReportEmail(ownerUserId, 'it_audit_summary', title, deviceName, audit.summary));
          if (sent) (await db.prepare(
            'INSERT INTO ai_report_email_state (device_id,last_audit_email_at) VALUES (?,?) ' +
            'ON CONFLICT(device_id) DO UPDATE SET last_audit_email_at=excluded.last_audit_email_at'
          ).run(deviceId, collectedAtMs));
        }
      }
    } catch (e) { log('warn', 'IT Audit summary email failed', { deviceId, err: e.message }); }
  }
}, 15 * 60 * 1000);

  // Nothing to return: registering the two intervals IS the side effect.
};
