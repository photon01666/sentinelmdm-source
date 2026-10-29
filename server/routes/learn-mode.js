const LEARN_MAX_DAYS = 30;   // moved with the block: its 5 uses are all here

module.exports = ({ app, db, express, fleetControllableRemoteAssistDeviceIds, learnInvalidate, log, requireAuth, requireDeviceAccess, requireDeviceController, requireFleetAccess, requireUnlocked }) => {
// ── Learn Mode routes ────────────────────────────────────────────────────────────────────────
// Entirely server-side: no bastion round trip, no agent version dependency — Learn Mode gates the
// SERVER's alert dispatch, the on-device detectors are untouched and keep reporting everything.
// Same auth chain as every other per-device RA control, so a public owner manages their own
// device's window and an admin can manage a fleet device's.
app.get('/api/devices/:id/learn-mode', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  try {
    const win = (await db.prepare('SELECT started_at, expires_at, started_by, ended_at FROM learn_mode WHERE device_id=?').get(req.params.id));
    // `(decision IS NULL) DESC` sorts still-to-review rows first and is valid on BOTH engines —
    // Postgres orders the boolean true-first, SQLite orders the 1/0 the same way. Deliberately not
    // `NULLS FIRST`, whose default differs between the two.
    const rows = (await db.prepare(
      `SELECT category, signature, detail, hits, first_seen, last_seen, decision
       FROM learn_observations WHERE device_id=?
       ORDER BY (decision IS NULL) DESC, hits DESC, last_seen DESC`
    ).all(req.params.id));
    const now = Date.now();
    const active = !!win && !win.ended_at && Number(win.expires_at) > now;
    res.json({
      active,
      started_at: win?.started_at ?? null,
      expires_at: win?.expires_at ?? null,
      started_by: win?.started_by ?? null,
      ended_at:   win?.ended_at ?? null,
      // A closed window with pending rows is the "please review" state the expiry alert points at.
      pending_review: rows.filter(r => !r.decision).length,
      observations: rows,
      max_days: LEARN_MAX_DAYS,
    });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/devices/:id/learn-mode', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), express.json(), async (req, res) => {
  const days = Number(req.body?.days);
  if (!Number.isFinite(days) || days < 1 || days > LEARN_MAX_DAYS)
    return res.status(400).json({ error: `days must be between 1 and ${LEARN_MAX_DAYS}` });
  const now = Date.now();
  const expires = now + Math.round(days * 24 * 60 * 60 * 1000);
  try {
    // Re-starting resets ended_at/notified_at so an expired window can be reopened in place;
    // observations are deliberately KEPT (a second window continues building the same baseline).
    (await db.prepare(`INSERT INTO learn_mode (device_id,started_at,expires_at,started_by,ended_at,notified_at)
      VALUES (?,?,?,?,NULL,NULL)
      ON CONFLICT(device_id) DO UPDATE SET started_at=excluded.started_at, expires_at=excluded.expires_at,
        started_by=excluded.started_by, ended_at=NULL, notified_at=NULL`)
      .run(req.params.id, now, expires, req.session?.username || null));
    learnInvalidate(req.params.id);
    log('info', 'Learn Mode started', { deviceId: req.params.id, days, by: req.session?.username });
    res.json({ ok: true, active: true, started_at: now, expires_at: expires });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Close the window early. Observations stay for review — this is "stop learning", not "discard".
app.delete('/api/devices/:id/learn-mode', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  try {
    (await db.prepare('UPDATE learn_mode SET ended_at=? WHERE device_id=? AND ended_at IS NULL').run(Date.now(), req.params.id));
    learnInvalidate(req.params.id);
    log('info', 'Learn Mode stopped early', { deviceId: req.params.id, by: req.session?.username });
    res.json({ ok: true, active: false });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Review decision. 'accepted' => permanent suppression for that exact signature; 'rejected' =>
// keep alerting (and never re-record it, so a rejected finding can't be silently re-learned by a
// later window). 'pending' clears a prior decision.
app.post('/api/devices/:id/learn-mode/decide', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), express.json(), async (req, res) => {
  const { category, signature, decision } = req.body || {};
  if (!['accepted', 'rejected', 'pending'].includes(decision))
    return res.status(400).json({ error: 'decision must be accepted, rejected or pending' });
  if (!category || !signature) return res.status(400).json({ error: 'category and signature required' });
  try {
    const r = (await db.prepare('UPDATE learn_observations SET decision=?, decided_at=? WHERE device_id=? AND category=? AND signature=?')
      .run(decision === 'pending' ? null : decision, decision === 'pending' ? null : Date.now(),
           req.params.id, String(category), String(signature)));
    if (!r.changes) return res.status(404).json({ error: 'Observation not found' });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Bulk "accept everything still pending" — the one-click end of a clean learn window.
app.post('/api/devices/:id/learn-mode/accept-all', requireUnlocked, requireAuth, requireDeviceAccess, requireDeviceController(), async (req, res) => {
  try {
    const r = (await db.prepare('UPDATE learn_observations SET decision=?, decided_at=? WHERE device_id=? AND decision IS NULL')
      .run('accepted', Date.now(), req.params.id));
    log('info', 'Learn Mode baseline accepted in bulk', { deviceId: req.params.id, count: r.changes, by: req.session?.username });
    res.json({ ok: true, accepted: r.changes });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Fleet-wide start/stop — mirrors the existing Windows Fleet fan-out scoping exactly.
app.post('/api/remote-assist/fleet/learn-mode', requireUnlocked, requireAuth, requireFleetAccess, express.json(), async (req, res) => {
  const stop = req.body?.stop === true;
  const days = Number(req.body?.days);
  if (!stop && (!Number.isFinite(days) || days < 1 || days > LEARN_MAX_DAYS))
    return res.status(400).json({ error: `days must be between 1 and ${LEARN_MAX_DAYS}` });
  try {
    const ids = (await fleetControllableRemoteAssistDeviceIds(req, req.body?.groupId || null));
    const now = Date.now();
    const expires = now + Math.round((days || 0) * 24 * 60 * 60 * 1000);
    for (const id of ids) {
      if (stop) (await db.prepare('UPDATE learn_mode SET ended_at=? WHERE device_id=? AND ended_at IS NULL').run(now, id));
      else (await db.prepare(`INSERT INTO learn_mode (device_id,started_at,expires_at,started_by,ended_at,notified_at)
        VALUES (?,?,?,?,NULL,NULL)
        ON CONFLICT(device_id) DO UPDATE SET started_at=excluded.started_at, expires_at=excluded.expires_at,
          started_by=excluded.started_by, ended_at=NULL, notified_at=NULL`)
        .run(id, now, expires, req.session?.username || null));
      learnInvalidate(id);
    }
    log('info', stop ? 'Learn Mode stopped (fleet)' : 'Learn Mode started (fleet)',
      { count: ids.length, days: stop ? null : days, by: req.session?.username });
    res.json({ ok: true, devices: ids.length });
  } catch (e) { res.status(500).json({ error: e.message }); }
});
};
