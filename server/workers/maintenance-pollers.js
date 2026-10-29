// workers/maintenance-pollers.js - four worker-only pollers that drive scheduled maintenance.
//
// Grouped by CONTIGUITY, not by theme: these four sit back-to-back with nothing between them
// but their own banners and one shared flag, so moving them as one span keeps each poller's
// doc comment attached to it. `extraction-plan.py --pollers` computes the grouping — a gap splits
// them only when it contains real code.
//
//   Force Windows Update Now (60 s)   completion/stuck detection for forced updates
//   File Backup scheduled-run (5 min) start a file backup whose schedule has come due
//   AppLocker blocked-file (15 min)   upload newly-blocked executables, audit new ones
//   BitLocker status (15 min)         ingest recovery-password protector state
//
// `_applockerAuditBackfilled` moves WITH this module: every reference to it lives here, so it is
// a local, not a ctx dep.
//
// A WORKER module: it registers timers, not routes, and registers nothing when IS_WORKER is unset.
//
// The replacement call sits at the group's OWN first line (L8514), preserving the relative
// registration order of all four against the server.js lines around them.
//
// ctx: 20 deps. 15 are `function` declarations and hoist. The lowest non-hoisted binding is
// WU_FORCE_IN_PROGRESS_STATUSES (L8510), so the call must sit at or after L8511. L8514 does.
// No upper bound: a poller registers a timer and nothing consumes it.
//
// bastionClient is NOT a ctx dep and must not become one — four function-local lazy requires
// stay lazy and rebase to '../'.

module.exports = ({ IS_WORKER, WU_FORCE_IN_PROGRESS_STATUSES, _wuDelDedupe, _wuGetDedupe, _wuSetDedupe, db, decryptText, deviceOwnerEmail, deviceOwnerInfo, encryptText, getFileBackupSchedule, getWinUpdateForceActive, ingestBitlockerResult, log, notifySecurityAlert, notifyUser, setWinUpdateForceActive, sha256hex, startFileBackupRun, uploadBlockedFile }) => {
if (IS_WORKER) setInterval(async () => {
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return;
  let devices;
  try {
    devices = (await db.prepare(
      "SELECT d.id, d.name, d.owner_user_id FROM devices d " +
      "WHERE d.platform='windows' AND d.agent_kind='remote_assist'"
    ).all());
  } catch (e) { return; }
  for (const dev of devices) {
    try {
      if (!(await getWinUpdateForceActive(dev.id))) continue;
      const st = (await bastionClient.winUpdateForceStatus(dev.id));
      if (!st?.ok) continue;
      const deviceName = (dev.name && !String(dev.name).startsWith('ENC:')) ? dev.name : (decryptText(dev.name) || dev.id);
      const ownerEmail = (await deviceOwnerEmail(dev.id));
      const dedupe = await _wuGetDedupe(dev.id);
      const isSecurity = !!st.securityOnly;
      const cycleLabel = isSecurity ? 'Security Update' : 'Windows Update';
      const terminal = ['done', 'aborted_ceiling', 'cancelled', 'failed', 'reboot_deferred'].includes(st.status);
      const stuck = st.status === 'rebooting' && st.pendingRebootExpectedBy && st.reachable === false
        && Date.now() > new Date(st.pendingRebootExpectedBy).getTime();

      if (terminal && !dedupe.terminal) {
        const msg = st.status === 'done'
          ? `✅ Force ${cycleLabel} complete on ${deviceName} (relock ${st.finalRelockOk ? 'OK' : 'FAILED'})${ownerEmail ? `\nAccount: ${ownerEmail}` : ''}`
          : st.status === 'reboot_deferred'
          ? `⏳ Force ${cycleLabel} on ${deviceName}: updates installed, reboot deferred — daily restart reminder is active on the PC${ownerEmail ? `\nAccount: ${ownerEmail}` : ''}`
          : `⚠️ Force ${cycleLabel} ${st.status} on ${deviceName}${st.abortReason ? ': ' + st.abortReason : ''} — Windows Update was left ENABLED, needs manual attention${ownerEmail ? `\nAccount: ${ownerEmail}` : ''}`;
        log('info', 'Force Windows Update finished', { deviceId: dev.id, status: st.status, securityOnly: isSecurity });
        try { (await notifySecurityAlert(msg, dev.id, { hybridTarget: true })); } catch (_) {}
        try { if (dev.owner_user_id) (await notifyUser(dev.owner_user_id, msg, { category: 'winupdate_force', deviceId: dev.id })); } catch (_) {}
        _wuSetDedupe(dev.id, { terminal: true, stuck: false });
        // A scheduled security cycle's terminal state must NOT disarm the poller while the
        // schedule is still configured — tomorrow's run (kicked off entirely on-device, no POST)
        // needs the flag to stay armed or its stuck/completion alerts never fire. Manual cycles
        // (no schedule configured) disarm as before.
        if (!(isSecurity && st.securityScheduleConfigured)) (await setWinUpdateForceActive(dev.id, false));
      } else if (stuck && !dedupe.stuck) {
        const msg = `⚠️ Force ${cycleLabel}: ${deviceName} hasn't come back from a scheduled reboot ` +
          `(expected by ${st.pendingRebootExpectedBy}) — may be stuck.${ownerEmail ? `\nAccount: ${ownerEmail}` : ''}`;
        log('warn', 'Force Windows Update possibly stuck', { deviceId: dev.id, securityOnly: isSecurity });
        try { (await notifySecurityAlert(msg, dev.id, { hybridTarget: true })); } catch (_) {}
        try { if (dev.owner_user_id) (await notifyUser(dev.owner_user_id, msg, { category: 'winupdate_force', deviceId: dev.id })); } catch (_) {}
        _wuSetDedupe(dev.id, { terminal: false, stuck: true });
      } else if (!terminal && !stuck && WU_FORCE_IN_PROGRESS_STATUSES.has(st.status) && (dedupe.terminal || dedupe.stuck)) {
        // Only clear the dedupe when a genuinely NEW cycle is starting (status is one of
        // the in-progress set). An idle or empty/broken-live-read status must NOT wipe the
        // dedupe — doing so would let the next disconnect-served cached terminal state
        // re-alert a completed cycle (the false-alert loop found live 2026-08-09: the
        // bastion's broken compound read returned empty stdout → false idle → cleared the
        // dedupe → agent restart → cached done re-alerted). The gate still covers the
        // genuine use case: a completed cycle's `done` stays deduped, then a new cycle's
        // `starting`/`scanning` status clears it so THIS cycle's later `done` can alert.
        _wuDelDedupe(dev.id);
      }
    } catch (e) { /* one unreachable box must never block the others */ }
  }
}, 60 * 1000);

// ── File Backup scheduled-run poller (worker only — one instance) ─────────────────────────────
// 5-min tick (2026-07-22, down from hourly) — the hard floor on how often ANY configured interval
// can actually fire, same "tick's own cadence is the floor" principle as the ARP scan poller;
// FILE_BACKUP_MIN_SCHEDULE_MINUTES matches this. Only OWNED devices are eligible: an admin-fleet/
// unowned device has no single deterministic account whose S3 config + password a scheduled run
// (no live req.session to fall back on) could use, unlike a manual "Backup Now" click — admin can
// still trigger those by hand anytime. Skips a device whose tunnel isn't currently connected
// (retries next tick — no point alerting on "the PC was off", same reasoning as the AI-report
// poller elsewhere).
//
// Two independent cadences per device: fullScheduleMinutes checked against the last FULL backup's
// start time; incrementalScheduleMinutes checked against the last backup of EITHER kind (so a full
// that just ran also resets the incremental clock — no point running an incremental 30 seconds
// after a full just captured everything). A full takes priority when both are due in the same tick.
if (IS_WORKER) setInterval(async () => {
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return;
  let devices;
  try {
    devices = (await db.prepare(
      "SELECT id, owner_user_id FROM devices WHERE platform='windows' AND agent_kind='remote_assist' AND owner_user_id IS NOT NULL"
    ).all());
  } catch (e) { log('warn', 'File Backup schedule poller: device query failed', { err: e.message }); return; }
  for (const dev of devices) {
    try {
      const sched = (await getFileBackupSchedule(dev.id));
      if (!sched.fullScheduleMinutes && !sched.incrementalScheduleMinutes) continue;
      const lastFull = (await db.prepare("SELECT started_at FROM file_backup_runs WHERE device_id=? AND kind='backup' AND backup_kind='full' ORDER BY started_at DESC LIMIT 1").get(dev.id));
      const lastAny = (await db.prepare("SELECT started_at FROM file_backup_runs WHERE device_id=? AND kind='backup' ORDER BY started_at DESC LIMIT 1").get(dev.id));
      const now = Date.now();
      let runKind = null;
      if (sched.fullScheduleMinutes && now >= (lastFull?.started_at || 0) + sched.fullScheduleMinutes * 60 * 1000) {
        runKind = 'full';
      } else if (sched.incrementalScheduleMinutes && now >= (lastAny?.started_at || 0) + sched.incrementalScheduleMinutes * 60 * 1000) {
        runKind = 'incremental';
      }
      if (!runKind) continue;
      const status = (await bastionClient.sessionStatus(dev.id));
      if (!status?.connected) continue;
      const result = (await startFileBackupRun(dev.id, dev.owner_user_id, runKind));
      if (result.ok) log('info', 'Scheduled File Backup started', { deviceId: dev.id, runId: result.runId, kind: runKind });
      else if (!result.runId) log('warn', 'Scheduled File Backup could not start', { deviceId: dev.id, kind: runKind, error: result.error });
    } catch (e) { log('warn', 'File Backup schedule poller failed for device', { deviceId: dev.id, err: e.message }); }
  }
}, 5 * 60 * 1000);

// ── AppLocker blocked-file auto-upload poller (worker only — one instance) ────────────────────
// Every 5 min, for every RA device with App Control (AppLocker) actually enabled, reads the live
// blocked list (bastionClient.srpActivity() — same source the "Check Blocked & Ran" panel uses)
// and auto-uploads the binary for any path never captured before (dedup by path_hash — see
// uploadBlockedFile()'s doc comment; a file that's been retried 10 times only gets pulled once).
// Alerts the owner (or Signal for admin-fleet/unowned) once per newly-captured-or-skipped path —
// 'skipped_size' still alerts (so the user/admin knows to go force-upload it) but never re-fetches
// bytes on its own past APPLOCKER_AUTO_UPLOAD_MAX_BYTES.
// ALSO drains 8003 "would have been blocked" audit events for devices in permanent audit mode
// and creates user_alerts entries so the AI auto-audit pipeline reviews them.
let _applockerAuditBackfilled = false;
if (IS_WORKER) setInterval(async () => {
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return;
  // One-time backfill (runs post-unlock): prior applocker_audit alerts deduped against
  // user_alerts message text — copy their paths into the durable table so paths that alerted
  // before this change don't re-alert on the next poll (e.g. the live Signal.exe row).
  if (!_applockerAuditBackfilled) {
    try {
      const prior = db.prepare("SELECT device_id, message, created_at FROM user_alerts WHERE category='applocker_audit'").all();
      for (const row of prior) {
        const m = String(row.message || '');
        const pathMatch = m.match(/Path: (.+)/);
        if (!pathMatch) continue;
        const p = pathMatch[1].trim();
        if (!p) continue;
        const ph = sha256hex(p.toLowerCase());
        db.prepare(
          'INSERT INTO applocker_audit_seen (device_id, path_hash, path, first_seen) VALUES (?,?,?,?) ON CONFLICT(device_id, path_hash) DO NOTHING'
        ).run(row.device_id, ph, encryptText(p), row.created_at || Date.now());
      }
    } catch (e) { log('warn', 'applocker_audit_seen backfill failed', { err: e.message }); }
    _applockerAuditBackfilled = true;
  }
  let devices;
  try {
    devices = (await db.prepare(
      "SELECT id, name FROM devices WHERE platform='windows' AND agent_kind='remote_assist'"
    ).all());
  } catch (e) { log('warn', 'AppLocker upload poller: device query failed', { err: e.message }); return; }
  for (const dev of devices) {
    const deviceId = dev.id;
    try {
      // ⚠️ Do NOT gate on sessionStatus().appcontrol_enabled — that's bastion's own remembered
      // "did the dashboard Deploy button ever run for this session" flag, not a live read of
      // whether AppLocker is actually enforcing on the box. Found live 2026-07-20: a device with
      // 2 real blocked paths (confirmed via the SAME srpActivity() call the "Check Blocked & Ran"
      // panel uses — it doesn't check this flag at all) sat with appcontrol_enabled:false the
      // whole time, silently skipping this entire loop iteration every 5 min forever — no upload,
      // no notification, and no error logged (a clean `continue`, indistinguishable from "AppLocker
      // genuinely isn't deployed here"). The flag can desync from reality (e.g. after a session
      // remint resets bastion-side meta while the Windows-side AppLocker policy, once deployed,
      // persists independently) — srpActivity()'s own ok/logAvailable/blocked.length is the only
      // trustworthy live signal, so just call it directly and let the empty-result check below
      // handle the "nothing to do" case, exactly like the manual panel already does.
      const activity = (await bastionClient.srpActivity(deviceId));
      const blocked = Array.isArray(activity?.blocked) ? activity.blocked : [];
      if (!activity?.ok || !blocked.length) continue;
      const existingRows = (await db.prepare('SELECT path_hash FROM applocker_blocked_files WHERE device_id=?').all(deviceId));
      const known = new Set(existingRows.map(r => r.path_hash));
      // Audit-mode (8003) dedup lives in its OWN table, NOT user_alerts — the old approach parsed
      // `Path:` out of prior applocker_audit alert messages, so archiving/clearing history silently
      // wiped the dedup memory and the SAME executable re-alerted on its next run (found live
      // 2026-08-13: Signal.exe re-alerted after a VM reboot because the morning's alerts had been
      // archived). Table rows survive alert archival/clearing, like applocker_blocked_files does.
      const seenAuditRows = (await db.prepare('SELECT path_hash FROM applocker_audit_seen WHERE device_id=?').all(deviceId));
      const auditAlerted = new Set(seenAuditRows.map(r => r.path_hash));
      const deviceName = (dev.name && !String(dev.name).startsWith('ENC:')) ? dev.name : (decryptText(dev.name) || deviceId);
      const ownerEmail = (await deviceOwnerEmail(deviceId));
      for (const entry of blocked) {
        const p = String(entry?.path || '').trim();
        if (!p) continue;
        const pKey = sha256hex(p.toLowerCase());
        const wasBlocked = entry.wasBlocked !== false;
        if (wasBlocked) {
          // Enforce-mode block (8004) — upload binary + alert
          if (known.has(pKey)) continue;
          known.add(pKey);
          const blockedAt = Date.parse(entry.lastSeen || entry.firstSeen || '') || Date.now();
          let result;
          try { result = (await uploadBlockedFile(deviceId, p, blockedAt)); }
          catch (e) { log('warn', 'AppLocker auto-upload failed', { deviceId, path: p, err: e.message }); continue; }
          try {
            const { isZk, ownerUserId } = (await deviceOwnerInfo(deviceId));
            const msg = result.status === 'uploaded'
              ? `🚫 AppLocker blocked a program\nDevice: ${deviceName}${ownerEmail ? `\nAccount: ${ownerEmail}` : ''}\nPath: ${p}\nThe blocked file was captured and is available to download from its Reverse SSH tab.`
              : `🚫 AppLocker blocked a program\nDevice: ${deviceName}${ownerEmail ? `\nAccount: ${ownerEmail}` : ''}\nPath: ${p}\n${result.status === 'skipped_size' ? `File is ${Math.round((result.size || 0) / 1048576)}MB — over the 500MB auto-upload limit; an admin can force-upload it from the dashboard.` : 'Could not capture the file automatically.'}`;
            if (isZk && ownerUserId) {
              (await notifyUser(ownerUserId, msg, { category: 'applocker_blocked', deviceId }));
              (await notifySecurityAlert(msg, deviceId, { hybridTarget: true }));
            } else {
              (await notifySecurityAlert(msg, deviceId, { hybridTarget: true }));
            }
          } catch (e) { log('warn', 'AppLocker block alert failed', { deviceId, path: p, err: e.message }); }
        } else {
          // Audit-mode event (8003) — alert only, no binary upload
          if (auditAlerted.has(pKey)) continue;
          auditAlerted.add(pKey);
          try {
            const { isZk, ownerUserId } = (await deviceOwnerInfo(deviceId));
            const msg = `👁️ AppLocker audit: new executable observed\nDevice: ${deviceName}${ownerEmail ? `\nAccount: ${ownerEmail}` : ''}\nPath: ${p}\nThis executable was observed running in Audit Mode. Nothing was blocked — this is for visibility only.`;
            if (isZk && ownerUserId) {
              (await notifyUser(ownerUserId, msg, { category: 'applocker_audit', deviceId }));
            } else {
              (await notifySecurityAlert(msg, deviceId, { hybridTarget: true }));
            }
            // Persist the seen-hash BEFORE alerting completes so a re-alert can never race a crash.
            try {
              (await db.prepare(
                'INSERT INTO applocker_audit_seen (device_id, path_hash, path, first_seen) VALUES (?,?,?,?)'
              ).run(deviceId, pKey, encryptText(p), Date.now()));
            } catch (e2) { log('warn', 'AppLocker audit seen-row insert failed', { deviceId, path: p, err: e2.message }); }
          } catch (e) { log('warn', 'AppLocker audit alert failed', { deviceId, path: p, err: e.message }); }
        }
      }
    } catch (e) { log('warn', 'AppLocker upload poll failed', { deviceId, err: e.message }); }
  }
}, 5 * 60 * 1000);

// ── BitLocker status poller (worker only — one instance) ──────────────────────────────────────
// Every 15 min, for EVERY Windows RA device (not gated on any "enabled" flag — same lesson as the
// AppLocker poller above: BitLocker has no separate enable-toggle to desync from reality in the
// first place, it's either on or off on the box itself), pulls live Get-BitLockerVolume state so
// the WebUI's encryption-percentage progress bar advances without a manual click, and ingests any
// newly-seen RecoveryPassword key protector exactly like the manual enable/status routes do.
// bitlockerStatus() itself no-ops cheaply (no SSH round trip) for a disconnected session — see
// _session_is_connected() in bitlocker_status()/bastion-web.py — so skipping offline devices here
// needs no extra pre-check.
if (IS_WORKER) setInterval(async () => {
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return;
  let devices;
  try {
    devices = (await db.prepare(
      "SELECT id FROM devices WHERE platform='windows' AND agent_kind='remote_assist'"
    ).all());
  } catch (e) { log('warn', 'BitLocker status poller: device query failed', { err: e.message }); return; }
  for (const dev of devices) {
    try {
      const result = (await bastionClient.bitlockerStatus(dev.id));
      if (!result?.ok) continue;
      (await ingestBitlockerResult(dev.id, result));
    } catch (e) { log('warn', 'BitLocker status poll failed for device', { deviceId: dev.id, err: e.message }); }
  }
}, 15 * 60 * 1000);

  // Nothing to return: registering the four intervals IS the side effect.
};
