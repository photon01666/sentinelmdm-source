// workers/watch-pollers.js - five worker-only pollers that watch agent/platform state and act.
//
// Grouped by CONTIGUITY, not by theme: these five sit back-to-back in server.js with nothing
// between them but their own banners, so moving them as one span keeps each block's doc comment
// attached to its poller. `extraction-plan.py --pollers` computes the grouping — a gap splits
// them only when it contains real code.
//
//   Windows agent "update available" notifier   owner-facing, deduped by ra_update_notified_version
//   Sentry drain (60 s)                         pulls the Sentry issues JSONL outbox
//   Windows Screen-Text drain (60 s)            drains captured screen-text
//   Learn Mode window-expiry closer (60 s)      closes learn windows that have lapsed
//   USB Lockdown unauthorized-device alert      alerts when an unknown device is inserted
//
// A WORKER module: it registers timers, not routes, and registers nothing when IS_WORKER is unset.
//
// The replacement call sits at the group's OWN first line (L8632), which preserves the relative
// registration ORDER of all five with respect to the ~1,000 lines of server.js between them.
// Collecting every poller into one module called from one site would NOT be order-preserving.
//
// ctx: 18 deps. 10 are `function` declarations and hoist; `stmts` is a destructure at L2271,
// which is the lowest non-hoisted binding, so the call must sit at or after L2272. L8632 does.
// No upper bound: a poller registers a timer and nothing consumes it.
//
// bastionClient is NOT a ctx dep and must not become one — four function-local lazy requires
// stay lazy. They need rebasing to '../'; see the module header note in the extraction brief.

module.exports = ({ IS_WORKER, db, decryptText, deviceOwnerEmail, deviceOwnerInfo, encryptText, getScreenTextEnabled, getSentryEnabled, getUsbLockdownEnabled, io, isAlertAutoAuditSuppressed, isDeviceOnline, learnGate, learnInvalidate, learnNormalizeDetail, log, notifySecurityAlert, notifyUser, stmts }) => {
// ── Windows agent "update available" notifier (worker only — one instance) ───────────────────
// Public-owned RA devices are never force-pushed by admin (see the fleet route above) — this is
// the other half of that design: tell the owner an update exists (dashboard + email via the
// ordinary notifyUser() plumbing, category 'ra_agent_update') and let them decide when, via the
// per-device "Update Now" button. Admin-fleet/unowned devices are skipped — admin already sees
// the dedicated GET /api/admin/remote-assist-updates panel, no separate alert needed.
// devices.ra_update_notified_version is the dedup watermark: only fire once per NEWLY-available
// version, not every tick, mirroring the arp_spoof dedup principle in ingestArpScanResult().
if (IS_WORKER) setInterval(async () => {
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return;
  let devices;
  try {
    devices = (await db.prepare(
      "SELECT d.id, d.owner_user_id, d.name, d.ra_update_notified_version FROM devices d JOIN users u ON d.owner_user_id=u.id " +
      "WHERE d.platform='windows' AND d.agent_kind='remote_assist' AND u.account_type='public'"
    ).all());
  } catch (e) { log('warn', 'RA update-notifier: device query failed', { err: e.message }); return; }
  for (const dev of devices) {
    try {
      const status = (await bastionClient.sessionStatus(dev.id));
      const latest = status?.latest_agent_version;
      if (!status?.agent_update_available || !latest) continue;
      if (dev.ra_update_notified_version === latest) continue; // already notified for this version
      const deviceName = (dev.name && !String(dev.name).startsWith('ENC:')) ? dev.name : (decryptText(dev.name) || dev.id);
      const msg = `A new Windows Remote Assist agent update (v${latest}) is available for "${deviceName}". Update whenever you're ready from the device's Reverse SSH tab.`;
      (await notifyUser(dev.owner_user_id, msg, { category: 'ra_agent_update' }));
      (await db.prepare('UPDATE devices SET ra_update_notified_version=? WHERE id=?').run(latest, dev.id));
    } catch (e) { log('warn', 'RA update-notifier failed for device', { deviceId: dev.id, err: e.message }); }
  }
}, 15 * 60 * 1000);

// ── Sentry drain poller (worker only — fast 60s cadence) ────────────────────────────────
// Unlike the ARP/AI-report poller above (15-min), sentry findings are real-time security
// alerts. The on-device watcher runs every 5 min; this poller drains on a 60s tick so
// findings reach admin within ~1 min of the watcher writing them. Gated behind the cheap
// stored sentry_enabled flag — no Hop-2 round trip unless a device actually has it on.
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
      if (!(await getSentryEnabled(dev.id))) continue;
      const sentry = (await bastionClient.sentryDrain(dev.id));
      if (!sentry?.ok) continue;
      if (!Array.isArray(sentry.events) || !sentry.events.length) continue;
      const deviceName = (dev.name && !String(dev.name).startsWith('ENC:')) ? dev.name : (decryptText(dev.name) || dev.id);
      const ownerEmail = (await deviceOwnerEmail(dev.id));
      for (const evt of sentry.events) {
        const rule = String(evt.rule || 'unknown');
        const detail = String(evt.detail || '').slice(0, 400);
        const ts = evt.ts ? new Date(evt.ts).toLocaleString() : 'just now';
        const msg = `\u26A0\uFE0F Sentry alert: ${rule}\nDevice: ${deviceName}${ownerEmail ? `\nAccount: ${ownerEmail}` : ''}\n${detail}\nTime: ${ts}`;
        // The drained event is ALWAYS logged, Learn Mode or not \u2014 evidence is never hidden, only
        // the page. Signature is rule + the caller/target detail with volatile bits (timestamps,
        // PIDs, GUIDs, paths' numeric tails) stripped, so the same recurring finding collapses to
        // one reviewable row instead of one per occurrence.
        log('warn', 'Sentry event drained', { deviceId: dev.id, rule, detail: detail.slice(0, 200) });
        if (await learnGate(dev.id, 'sentry', rule, `${rule}:${learnNormalizeDetail(detail)}`, detail)) continue;
        // If this signature is already marked as a false positive, skip notifications.
        if (await isAlertAutoAuditSuppressed('sentry', dev.id, msg)) continue;
        try { (await notifySecurityAlert(msg, dev.id, { hybridTarget: true })); } catch (_) {}
        try { if (dev.owner_user_id) (await notifyUser(dev.owner_user_id, msg, { category: 'sentry', deviceId: dev.id })); } catch (_) {}
      }
    } catch (e) { /* one unreachable box must never block the others */ }
  }
}, 60 * 1000);

// ── Windows Screen-Text drain poller (worker only — 60s cadence) ────────────────────────────
// Drains UI Automation text-capture events from Windows devices and stores them in the
// screen_text_entries table — the same table Android uses. The existing scheduled analysis
// pipeline (safety net poller) then picks them up for AI analysis automatically.
// Gated behind the cheap stored screentext_win_enabled flag.
if (IS_WORKER) setInterval(async () => {
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return;
  let devices;
  try {
    devices = (await db.prepare(
      "SELECT d.id, d.name FROM devices d " +
      "WHERE d.platform='windows' AND d.agent_kind='remote_assist'"
    ).all());
  } catch (e) { return; }
  for (const dev of devices) {
    try {
      if (!(await getScreenTextEnabled(dev.id))) continue;
      // Skip offline devices — the bastion would fail the SSH tunnel check anyway,
      // but avoiding the round-trip saves a wasted HTTP call every 60s per offline device.
      if (!(await isDeviceOnline(dev.id))) continue;
      log('info', 'Screen-text drain: calling bastion', { deviceId: dev.id });
      const result = (await bastionClient.screenTextDrain(dev.id));
      if (!result?.ok) continue;
      if (!Array.isArray(result.events) || !result.events.length) continue;
      for (const evt of result.events) {
        const pkg = String(evt.pkg || 'unknown');
        const texts = Array.isArray(evt.texts) ? evt.texts : [];
        const ts = evt.ts ? new Date(evt.ts).getTime() : Date.now();
        if (!texts.length) continue;
        // Format texts the same way Android does: each entry is {t: "text"}
        const payload = { pkg, texts: texts.map(t => typeof t === 'string' ? { t } : t), ts };
        const encrypted = encryptText(JSON.stringify(payload));
        (await stmts.insertScreenText.run(dev.id, pkg, encrypted, ts));
        io.to(`monitor:${dev.id}`).emit('screen_text_update', { deviceId: dev.id, pkg, texts: payload.texts, ts });
      }
      log('info', 'Screen-text drain: stored', { deviceId: dev.id, events: result.events.length });
    } catch (e) { log('warn', 'Screen-text drain error', { deviceId: dev.id, error: e.message }); }
  }
}, 60 * 1000);

// ── Learn Mode — window-expiry closer (worker only — 60s cadence) ────────────────────────────
// Closes every window whose expires_at has passed and pages the owner ONCE to review what was
// learned. Worker-only + the notified_at stamp are what keep this to a single alert rather than
// one per replica per tick (same shape as the surveillance/winupdate-force pollers).
//
// The alert is the whole safety story for this feature: a learn window that quietly lapsed with
// nobody told would leave a pile of never-reviewed pending findings AND give the false impression
// the detectors had been clean all along. If there is genuinely nothing to review the device just
// goes quiet again — no alert for an empty window, that would be pure noise.
if (IS_WORKER) setInterval(async () => {
  try {
    const now = Date.now();
    const due = (await db.prepare(
      'SELECT device_id FROM learn_mode WHERE ended_at IS NULL AND expires_at <= ?').all(now));
    for (const row of due) {
      const deviceId = row.device_id;
      (await db.prepare('UPDATE learn_mode SET ended_at=? WHERE device_id=? AND ended_at IS NULL').run(now, deviceId));
      learnInvalidate(deviceId);
      const { n } = (await db.prepare(
        'SELECT COUNT(*) AS n FROM learn_observations WHERE device_id=? AND decision IS NULL').get(deviceId));
      const pending = Number(n) || 0;
      log('info', 'Learn Mode window closed', { deviceId, pending });
      if (!pending) continue;
      const already = (await db.prepare('SELECT notified_at FROM learn_mode WHERE device_id=?').get(deviceId));
      if (already?.notified_at) continue;
      (await db.prepare('UPDATE learn_mode SET notified_at=? WHERE device_id=?').run(now, deviceId));
      const { ownerUserId } = (await deviceOwnerInfo(deviceId));
      const devRow = (await db.prepare('SELECT name FROM devices WHERE id=?').get(deviceId));
      const deviceName = (devRow && decryptText(devRow.name)) || deviceId;
      const msg = `🎓 Learn Mode finished\nDevice: ${deviceName}\n\n${pending} finding${pending === 1 ? '' : 's'} recorded while alerts were paused. Review them and mark each as normal (stop alerting) or keep alerting — alerts are LIVE again either way.`;
      if (ownerUserId) { try { (await notifyUser(ownerUserId, msg, { category: 'learn_mode', deviceId })); } catch (_) {} }
      else { try { (await notifySecurityAlert(msg, deviceId, { hybridTarget: true })); } catch (_) {} }
    }
  } catch (e) { log('warn', 'Learn Mode expiry poll failed', { err: e.message }); }
}, 60 * 1000);

// ── USB Lockdown — unauthorized device insertion alert poller (worker only — 30s cadence) ────
// Gated behind the cheap usb_lockdown_enabled flag, same pattern as the Sentry poller above.
// The on-device watcher (SYSTEM AtStartup task) runs continuously and writes events for any
// USB device whose hardware IDs don't match the registry AllowDeviceIDs allowlist. This poller
// drains the JSONL outbox and fires push/email alerts to the device owner.
if (IS_WORKER) setInterval(async () => {
  const bastionClient = require('../bastionClient');
  if (!bastionClient.configured()) return;
  let devices;
  try {
    devices = (await db.prepare(
      "SELECT d.id, d.name, d.owner_user_id FROM devices d " +
      "WHERE d.platform IN ('windows','linux') AND d.agent_kind='remote_assist'"
    ).all());
  } catch (e) { return; }
  for (const dev of devices) {
    try {
      if (!(await getUsbLockdownEnabled(dev.id))) continue;
      const drained = (await bastionClient.usbLockdownDrain(dev.id));
      if (!drained?.ok) continue;
      if (!Array.isArray(drained.events) || !drained.events.length) continue;
      const deviceName = (dev.name && !String(dev.name).startsWith('ENC:')) ? dev.name : (decryptText(dev.name) || dev.id);
      const ownerEmail = (await deviceOwnerEmail(dev.id));
      for (const evt of drained.events) {
        const friendlyName = String(evt.friendlyName || 'Unknown device');
        const instanceId = String(evt.instanceId || '').slice(0, 80);
        const className = String(evt.class || 'Unknown');
        const ts = evt.ts ? new Date(evt.ts).toLocaleString() : 'just now';
        const msg = `\u{1F510} USB Lockdown: Unauthorized device blocked!\nDevice: ${friendlyName}\nClass: ${className}\nID: ${instanceId}\nMachine: ${deviceName}\nTime: ${ts}${ownerEmail ? `\nAccount: ${ownerEmail}` : ''}`;
        log('warn', 'USB lockdown event drained', { deviceId: dev.id, instanceId, friendlyName });
        try { if (dev.owner_user_id) (await notifyUser(dev.owner_user_id, msg, { category: 'usb_lockdown', deviceId: dev.id })); } catch (_) {}
        try { (await notifySecurityAlert(msg, dev.id, { hybridTarget: true })); } catch (_) {}
      }
    } catch (e) { /* one unreachable box must never block the others */ }
  }
}, 30 * 1000);

  // Nothing to return: registering the five intervals IS the side effect.
};
