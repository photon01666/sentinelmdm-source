// routes/bug-reports.js — Bug report submission, listing, conversation thread, admin triage.
// Extracted from server.js L3846-3949. 7 routes.
module.exports = ({ app, db, decryptText, encryptText, io, log, notifyAdminForUser, requireAdmin, requireAuth, sendWebPushToUser }) => {

// Any logged-in user submits a report; admins triage (open → pending → fixed).
app.post('/api/bug-reports', requireAuth, async (req, res) => {
  const title = String(req.body?.title || '').trim().slice(0, 200);
  const description = String(req.body?.description || '').trim().slice(0, 4000);
  if (!title) return res.status(400).json({ error: 'A short summary is required' });
  const now = Date.now();
  const { id } = (await db.prepare(
    'INSERT INTO bug_reports (user_id,username,title,description,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?) RETURNING id'
  ).get(req.session.userId || null, req.session.username || null, encryptText(title), encryptText(description), 'open', now, now));
  // Optional image attachments: [{ content_type, data(base64) }] — cap 4 images, ~4 MB each decoded.
  const photos = Array.isArray(req.body?.photos) ? req.body.photos.slice(0, 4) : [];
  for (const p of photos) {
    const data = typeof p?.data === 'string' ? p.data : '';
    if (!data || data.length > 5_600_000) continue;                      // ~4 MB binary in base64
    const ct = /^image\/(png|jpe?g|gif|webp)$/.test(p?.content_type || '') ? p.content_type : 'image/png';
    try { (await db.prepare('INSERT INTO bug_report_photos (bug_id,content_type,data,uploaded_at) VALUES (?,?,?,?)').run(id, ct, data, now)); } catch {}
  }
  io.to('monitors').emit('bug_report_new', { id });
  notifyAdminForUser(`🐞 New bug report from ${req.session.username || 'a user'}\n\n${title}`, req.session.userId).catch(() => {});
  log('info', 'Bug report submitted', { id, by: req.session.username });
  res.json({ ok: true, id });
});

// List: admins see all; everyone else sees only their own.
app.get('/api/bug-reports', requireAuth, async (req, res) => {
  const isAdmin = req.session.role === 'admin';
  const rows = isAdmin
    ? (await db.prepare('SELECT * FROM bug_reports ORDER BY created_at DESC').all())
    : (await db.prepare('SELECT * FROM bug_reports WHERE user_id=? ORDER BY created_at DESC').all(req.session.userId));
  const reports = await Promise.all(rows.map(async b => {
    let email = null;
    if (isAdmin && b.user_id) { try { const u = (await db.prepare('SELECT email FROM users WHERE id=?').get(b.user_id)); if (u) email = decryptText(u.email) || null; } catch {} }
    // Lightweight photo metadata only (ids/types) — the image bytes are fetched on demand.
    let photos = [];
    try { photos = (await db.prepare('SELECT id, content_type FROM bug_report_photos WHERE bug_id=? ORDER BY id').all(b.id)) || []; } catch {}
    let msg_count = 0;
    try { msg_count = Number((await db.prepare('SELECT COUNT(*) AS n FROM bug_report_messages WHERE bug_id=?').get(b.id))?.n) || 0; } catch {}
    return { id: b.id, user_id: b.user_id, username: b.username, email,
             title: decryptText(b.title) || '', description: decryptText(b.description) || '',
             status: b.status || 'open', created_at: b.created_at, updated_at: b.updated_at,
             photos: photos.map(p => ({ id: p.id, content_type: p.content_type })), msg_count };
  }));
  res.json({ reports });
});

// Stream a bug-report image. Auth: admin (any report) OR the report's own submitter.
app.get('/api/bug-reports/:id/photo/:pid', requireAuth, async (req, res) => {
  const bug = (await db.prepare('SELECT id, user_id FROM bug_reports WHERE id=?').get(req.params.id));
  if (!bug) return res.status(404).json({ error: 'not found' });
  if (req.session.role !== 'admin' && bug.user_id !== req.session.userId) return res.status(403).json({ error: 'forbidden' });
  const p = (await db.prepare('SELECT content_type, data FROM bug_report_photos WHERE id=? AND bug_id=?').get(req.params.pid, bug.id));
  if (!p) return res.status(404).json({ error: 'not found' });
  try {
    const buf = Buffer.from(p.data, 'base64');
    res.set('Content-Type', p.content_type || 'image/png');
    res.set('Cache-Control', 'private, max-age=300');
    res.send(buf);
  } catch { res.status(500).json({ error: 'decode failed' }); }
});

// ── Bug-report conversation thread (admin ↔ submitter) ─────────────────────
// Auth: admin (any report) OR the report's submitter. Bodies are encrypted at rest.
app.get('/api/bug-reports/:id/messages', requireAuth, async (req, res) => {
  const bug = (await db.prepare('SELECT id, user_id FROM bug_reports WHERE id=?').get(req.params.id));
  if (!bug) return res.status(404).json({ error: 'not found' });
  if (req.session.role !== 'admin' && bug.user_id !== req.session.userId) return res.status(403).json({ error: 'forbidden' });
  const rows = (await db.prepare('SELECT * FROM bug_report_messages WHERE bug_id=? ORDER BY created_at').all(bug.id));
  res.json({ messages: rows.map(m => ({ id: m.id, sender_role: m.sender_role, sender_name: m.sender_name,
    body: decryptText(m.body) || '', created_at: m.created_at })) });
});
app.post('/api/bug-reports/:id/messages', requireAuth, async (req, res) => {
  const bug = (await db.prepare('SELECT id, user_id, title FROM bug_reports WHERE id=?').get(req.params.id));
  if (!bug) return res.status(404).json({ error: 'not found' });
  const isAdmin = req.session.role === 'admin';
  if (!isAdmin && bug.user_id !== req.session.userId) return res.status(403).json({ error: 'forbidden' });
  const body = String(req.body?.body || '').trim().slice(0, 4000);
  if (!body) return res.status(400).json({ error: 'Message required' });
  const now = Date.now();
  (await db.prepare('INSERT INTO bug_report_messages (bug_id,sender_role,sender_user_id,sender_name,body,created_at) VALUES (?,?,?,?,?,?)')
    .run(bug.id, isAdmin ? 'admin' : 'user', req.session.userId || null, req.session.username || null, encryptText(body), now));
  (await db.prepare('UPDATE bug_reports SET updated_at=? WHERE id=?').run(now, bug.id));
  io.to('monitors').emit('bug_report_new', { id: bug.id });            // admins refresh in realtime
  if (isAdmin) {
    // Admin replied → web-push the submitter (no email — keep public-user mail minimal).
    if (bug.user_id) sendWebPushToUser(bug.user_id, '🐞 Reply on your bug report', body.slice(0, 140), '/').catch(() => {});
  } else {
    notifyAdminForUser(`🐞 Bug-report reply from ${req.session.username || 'a user'}\n${decryptText(bug.title) || ''}\n\n${body}`, req.session.userId).catch(() => {});
  }
  res.json({ ok: true });
});

app.patch('/api/admin/bug-reports/:id/status', requireAdmin, async (req, res) => {
  const status = ['open', 'pending', 'fixed'].includes(req.body?.status) ? req.body.status : null;
  if (!status) return res.status(400).json({ error: 'Invalid status' });
  const info = (await db.prepare('UPDATE bug_reports SET status=?, updated_at=? WHERE id=?').run(status, Date.now(), req.params.id));
  if (!info.changes) return res.status(404).json({ error: 'Report not found' });
  io.to('monitors').emit('bug_report_new', { id: Number(req.params.id) });
  res.json({ ok: true, status });
});

app.delete('/api/admin/bug-reports/:id', requireAdmin, async (req, res) => {
  try { (await db.prepare('DELETE FROM bug_report_photos WHERE bug_id=?').run(req.params.id)); } catch {}
  (await db.prepare('DELETE FROM bug_reports WHERE id=?').run(req.params.id));
  res.json({ ok: true });
});

};
