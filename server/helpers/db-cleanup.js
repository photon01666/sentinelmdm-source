// helpers/db-cleanup.js — periodic DB cleanup: trim excess rows, purge stale
// telemetry, VACUUM, and garbage-collect orphaned R2 objects.
//
// A HELPER module, not a route module: it registers nothing. server.js owns the
// scheduling — `scheduleCleanup()` and `cleanupScheduled` stay put; only the
// work moves.
//
//   runDbCleanup   export   one full cleanup pass (trim + orphan + R2 GC + VACUUM)
//
// ctx is available at this module's own position in server.js (X >= L4359,
// X <= L4645) — nothing had to move (IN-PLACE splice).
//
// 19 ctx deps: 11 RETAIN_* constants, db, log, maybeAlertTrialLapse, r2Del,
// r2List, shopStmts, stmts — all STABLE (const/function/destructure above the
// wiring line, never reassigned).
//
// getENC_KEY is a LIVE dep (getter): ENC_KEY (L106) is runtime-reassigned at
// 5 sites (unlock-store L2534, rekey L2543/L2638, Phase-2 bootstrap L6356/
// L6365). A by-value capture would decrypt with the OLD key after every
// rotation. The getter reads the top-level `let ENC_KEY` at call time.
//   — R5: live vs stable documented here; R3: getENC_KEY() is called ONLY
//     inside runDbCleanup's body, never at factory/module scope.
//   — Precedent: dev-tools/known-behavior-losses.md #5 (serverUnlocked
//     stale-capture incident — same pattern, same fix shape).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ RETAIN_APP_LISTS, RETAIN_CALL_LOGS, RETAIN_KEYLOGS_DAYS, RETAIN_LOCATIONS_DAYS, RETAIN_LOGS_DAYS, RETAIN_MEDIA, RETAIN_NETWORK_DAYS, RETAIN_RECORDINGS, RETAIN_SMS, RETAIN_STATUS_EVENTS, RETAIN_UNLOCK_PHOTOS, db, getENC_KEY, log, maybeAlertTrialLapse, r2Del, r2List, shopStmts, stmts }) => {

async function runDbCleanup() {
  if (!getENC_KEY()) return; // don't touch encrypted data without the key
  const t0 = Date.now();
  const stats = { trimmed: {}, orphanRows: 0, orphanR2: 0, vacuumed: false };

  const deviceIds = (await db.prepare('SELECT id FROM devices').all()).map(r => r.id);

  // ── 1. Trim excess rows per device (keep N most recent) ───────────────────
  const trims = [
    { table: 'media',              col: 'timestamp', keep: RETAIN_MEDIA         },
    { table: 'call_logs',          col: 'timestamp', keep: RETAIN_CALL_LOGS     },
    { table: 'sms_messages',       col: 'timestamp', keep: RETAIN_SMS           },
    { table: 'app_lists',          col: 'timestamp', keep: RETAIN_APP_LISTS     },
    { table: 'device_status_events', col: 'timestamp', keep: RETAIN_STATUS_EVENTS },
    // File Backup runs live in the ADMIN'S OWN external S3 bucket, not server-managed R2 — this
    // is just an operational audit-log trim (hygiene), not a COPPA-retention concern.
    { table: 'file_backup_runs',    col: 'started_at', keep: 100 },
  ];

  for (const { table, col, keep } of trims) {
    let total = 0;
    for (const id of deviceIds) {
      const cutoff = (await db.prepare(
        `SELECT ${col} FROM ${table} WHERE device_id=? ORDER BY ${col} DESC LIMIT 1 OFFSET ?`
      ).get(id, keep - 1));
      if (!cutoff) continue;
      const { changes } = (await db.prepare(
        `DELETE FROM ${table} WHERE device_id=? AND ${col} < ?`
      ).run(id, cutoff[col]));
      total += changes;
    }
    if (total) stats.trimmed[table] = total;
  }

  // ── 1b. Locations: 30-day TTL (time-based, not count-based) ────────────────
  // "Save up to 1 month of location history" — a row cap starved the per-day history
  // view, so locations age out by time like zk_payloads' own 30-day COPPA purge
  // (keeps plaintext + ZK retention symmetric).
  {
    const cutoff = Date.now() - RETAIN_LOCATIONS_DAYS * 24 * 60 * 60 * 1000;
    const { changes } = (await db.prepare('DELETE FROM locations WHERE timestamp < ?').run(cutoff));
    if (changes) stats.trimmed['locations'] = changes;
  }

  // ── 1c. Network snapshots: 30-day TTL (time-based, not count-based) ───────────
  // Same lesson as locations: the old keep:50-rows cap starved the WiFi/BT
  // positioning memory (chatty devices wrote 50 snapshots in ~2h). 30 days like
  // the rest of telemetry; disk stays bounded by time, not rows.
  {
    const cutoff = Date.now() - RETAIN_NETWORK_DAYS * 24 * 60 * 60 * 1000;
    const { changes } = (await db.prepare('DELETE FROM network_events WHERE timestamp < ?').run(cutoff));
    if (changes) stats.trimmed['network_events'] = changes;
  }

  // ── 2. Trim network/security logs older than 30 days ─────────────────────────
  {
    const cutoff = Date.now() - RETAIN_LOGS_DAYS * 24 * 60 * 60 * 1000;
    for (const table of ['device_network_logs', 'device_security_logs']) {
      let total = 0;
      for (const id of deviceIds) {
        const { changes } = (await db.prepare(`DELETE FROM ${table} WHERE device_id=? AND timestamp < ?`).run(id, cutoff));
        total += changes;
      }
      if (total) stats.trimmed[table] = total;
    }
  }

  // ── 2b. Prune stale ARP neighbors + events (30-day TTL, matches every other table) ─
  {
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    let neighborTotal = 0, eventsTotal = 0;
    for (const id of deviceIds) {
      const nc = (await db.prepare('DELETE FROM arp_neighbors WHERE device_id=? AND last_seen < ?').run(id, cutoff));
      neighborTotal += nc.changes;
      const ec = (await db.prepare('DELETE FROM arp_events WHERE device_id=? AND timestamp < ?').run(id, cutoff));
      eventsTotal += ec.changes;
    }
    if (neighborTotal) stats.trimmed['arp_neighbors'] = neighborTotal;
    if (eventsTotal) stats.trimmed['arp_events'] = eventsTotal;
  }

  // ── 3. Trim keylog_entries older than 30 days ─────────────────────────────
  {
    const cutoff = Date.now() - RETAIN_KEYLOGS_DAYS * 24 * 60 * 60 * 1000;
    let total = 0;
    for (const id of deviceIds) {
      const { changes } = (await db.prepare('DELETE FROM keylog_entries WHERE device_id=? AND timestamp < ?').run(id, cutoff));
      total += changes;
    }
    if (total) stats.trimmed['keylog_entries'] = total;
  }

  // ── 3b. Trim screen_text_entries older than 30 days ───────────────────────
  {
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    let total = 0;
    for (const id of deviceIds) {
      const { changes } = (await db.prepare('DELETE FROM screen_text_entries WHERE device_id=? AND timestamp < ?').run(id, cutoff));
      total += changes;
    }
    if (total) stats.trimmed['screen_text_entries'] = total;
  }

  // ── 3b-2. Cap unlock photos at RETAIN_UNLOCK_PHOTOS per device ──────────────
  // Matches the Unlock Attempts tab's display limit. Covers BOTH plaintext storage
  // (media rows, stored inline so the delete frees the blob — no R2 orphan) AND
  // ZK-owned devices (zk_payloads, event_type='unlock_photo'). Catches any backlog
  // beyond what the per-insert trim already enforces, plus pre-existing rows.
  {
    let total = 0;
    for (const id of deviceIds) {
      const cut = (await db.prepare(
        "SELECT timestamp FROM media WHERE device_id=? AND type IN ('unlock_success','unlock_fail') ORDER BY timestamp DESC LIMIT 1 OFFSET ?"
      ).get(id, RETAIN_UNLOCK_PHOTOS - 1));
      if (cut) {
        const { changes } = (await db.prepare(
          "DELETE FROM media WHERE device_id=? AND type IN ('unlock_success','unlock_fail') AND timestamp < ?"
        ).run(id, cut.timestamp));
        total += changes;
      }
      const zcut = (await db.prepare(
        "SELECT timestamp FROM zk_payloads WHERE device_id=? AND event_type='unlock_photo' ORDER BY timestamp DESC LIMIT 1 OFFSET ?"
      ).get(id, RETAIN_UNLOCK_PHOTOS - 1));
      if (zcut) {
        const { changes } = (await db.prepare(
          "DELETE FROM zk_payloads WHERE device_id=? AND event_type='unlock_photo' AND timestamp < ?"
        ).run(id, zcut.timestamp));
        total += changes;
      }
    }
    if (total) stats.trimmed['unlock_photos'] = total;
  }

  // ── 4. Trim stream_recordings per device (delete R2 objects for pruned rows) ──
  for (const id of deviceIds) {
    const cutoff = (await db.prepare(
      'SELECT captured_at FROM stream_recordings WHERE device_id=? ORDER BY captured_at DESC LIMIT 1 OFFSET ?'
    ).get(id, RETAIN_RECORDINGS - 1));
    if (!cutoff) continue;
    const old = (await db.prepare(
      'SELECT id, filename FROM stream_recordings WHERE device_id=? AND captured_at < ?'
    ).all(id, cutoff.captured_at));
    for (const row of old) {
      await r2Del(`streams/${row.filename}`).catch(() => {});
      (await db.prepare('DELETE FROM stream_recordings WHERE id=?').run(row.id));
      stats.orphanR2++;
    }
    if (old.length) stats.trimmed['stream_recordings'] = (stats.trimmed['stream_recordings'] || 0) + old.length;
  }

  // ── 3b. Trim zk_payloads older than 30 days (COPPA TTL applies to ZK data too) ──
  {
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    const { changes } = (await db.prepare('DELETE FROM zk_payloads WHERE timestamp < ?').run(cutoff));
    if (changes) stats.trimmed['zk_payloads'] = changes;
  }

  // ── 3c. Trim applocker_blocked_files older than 7 days (delete R2 objects for uploaded rows) ──
  // Shorter than the standard 30-day retention elsewhere -- these are captured malware/test-file
  // binaries, not routine telemetry, so a tighter window was requested deliberately.
  {
    const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
    const old = (await db.prepare('SELECT id, r2_key FROM applocker_blocked_files WHERE blocked_at < ?').all(cutoff));
    for (const row of old) {
      if (row.r2_key) { await r2Del(row.r2_key).catch(() => {}); stats.orphanR2++; }
      (await db.prepare('DELETE FROM applocker_blocked_files WHERE id=?').run(row.id));
    }
    if (old.length) stats.trimmed['applocker_blocked_files'] = old.length;
  }

  // ── Trim web_analytics older than 30 days ─────────────────────────────────
  {
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    const { changes } = (await db.prepare('DELETE FROM web_analytics WHERE timestamp < ?').run(cutoff));
    if (changes) stats.trimmed['web_analytics'] = changes;
  }

  // ── Trim bot_traffic older than 30 days ───────────────────────────────────
  {
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    const { changes } = (await db.prepare('DELETE FROM bot_traffic WHERE timestamp < ?').run(cutoff));
    if (changes) stats.trimmed['bot_traffic'] = changes;
  }

  // ── Purge spent/expired enrollment tickets (short-lived single-use) ─────────
  {
    const { changes } = (await stmts.purgeEnrollTickets.run(Date.now()));
    if (changes) stats.trimmed['enrollment_tickets'] = changes;
  }

  // ── 3c. Trim zk_stream_sessions older than 30 days ──────────────────────────
  {
    const cutoff = Date.now() - 30 * 24 * 60 * 60 * 1000;
    const { changes } = (await db.prepare('DELETE FROM zk_stream_sessions WHERE started_at < ?').run(cutoff));
    if (changes) stats.trimmed['zk_stream_sessions'] = changes;
  }

  // ── 3d. Trial-lapse sweep — ALERT ONLY, never delete or disable ─────────────
  // Catches trials that lapsed without the device pinging in. NEVER auto-disables
  // (user policy 2026-05-30): the admin extends or expires. orders/entitlements/
  // tos/rma rows are intentionally NOT purged here (financial/legal records).
  try {
    const lapsed = (await shopStmts.lapsedCandidates.all('Active', Date.now()));
    for (const ent of lapsed) (await maybeAlertTrialLapse(ent));
    if (lapsed.length) stats.trimmed['trials_lapsed_alerted'] = lapsed.length;
  } catch (e) { log('warn', 'trial-lapse sweep failed', { err: e.message }); }

  // ── 4. Orphaned rows for deleted devices ─────────────────────────────────
  const orphanTables = [
    'locations', 'media', 'network_events', 'call_logs',
    'sms_messages', 'app_lists', 'keylog_entries', 'screen_text_entries', 'device_status_events',
    'zk_payloads', 'zk_stream_sessions',
  ];
  for (const table of orphanTables) {
    const { changes } = (await db.prepare(
      `DELETE FROM ${table} WHERE device_id NOT IN (SELECT id FROM devices)`
    ).run());
    stats.orphanRows += changes;
  }

  // Orphaned files rows + R2 objects
  const orphanFiles = (await db.prepare(
    'SELECT id, filename FROM files WHERE device_id NOT IN (SELECT id FROM devices)'
  ).all());
  for (const row of orphanFiles) {
    await r2Del(`uploads/${row.filename}`).catch(() => {});
    (await db.prepare('DELETE FROM files WHERE id=?').run(row.id));
    stats.orphanRows++;
    stats.orphanR2++;
  }

  // Orphaned stream_recordings rows + R2 objects
  const orphanRec = (await db.prepare(
    'SELECT id, filename FROM stream_recordings WHERE device_id NOT IN (SELECT id FROM devices)'
  ).all());
  for (const row of orphanRec) {
    await r2Del(`streams/${row.filename}`).catch(() => {});
    (await db.prepare('DELETE FROM stream_recordings WHERE id=?').run(row.id));
    stats.orphanRows++;
    stats.orphanR2++;
  }

  // ── 5. Delete all apks/ objects from R2 — they're always ephemeral (10-min token) ──
  const apkKeys = await r2List('apks/').catch(() => []);
  for (const key of apkKeys) {
    await r2Del(key).catch(() => {});
    stats.orphanR2++;
  }
  if (apkKeys.length) stats.trimmed['apks_r2'] = apkKeys.length;

  // ── 5. VACUUM to reclaim freed pages ─────────────────────────────────────
  const totalTrimmed = Object.values(stats.trimmed).reduce((a, b) => a + b, 0);
  if (totalTrimmed > 0 || stats.orphanRows > 0 || stats.orphanR2 > 0) {
    (await db.exec('VACUUM'));
    stats.vacuumed = true;
  }

  log('info', 'DB cleanup complete', {
    ms: Date.now() - t0,
    trimmed: stats.trimmed,
    orphanRows: stats.orphanRows,
    orphanR2: stats.orphanR2,
    vacuumed: stats.vacuumed,
  });
}

return { runDbCleanup };

};