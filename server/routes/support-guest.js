// routes/support-guest.js — Public contact form + guest live chat (no login — marketing site widget).
// All routes allow cross-origin from the marketing site.
module.exports = ({ app, cors, db, decryptText, encryptText, getSupportPresence,
                    guestChatRateLimit, guestMsgOut, guestReadRateLimit, guestStmts,
                    io, log, notifyAdmin, notifyPush, MAX_SUPPORT_MSG }) => {
// ── Public contact form + guest live chat (no login — marketing site widget) ──
// All routes allow cross-origin from the marketing site.
app.options(/^\/api\/support\/(contact|presence|guest.*)$/, (req, res) => { cors(res).sendStatus(204); });

// Visitor polls this to decide leave-a-message vs live chat.
app.get('/api/support/presence', async (req, res) => { cors(res).json({ presence: (await getSupportPresence()) }); });

app.post('/api/support/contact', guestChatRateLimit, async (req, res) => {
  cors(res);
  const name    = String(req.body?.name    || '').trim().slice(0, 120);
  const email   = String(req.body?.email   || '').trim().slice(0, 200);
  const message = String(req.body?.message || '').trim().slice(0, 2000);
  if (!message) return res.status(400).json({ error: 'Message is required' });
  if (email && (!email.includes('@') || email.length > 200))
    return res.status(400).json({ error: 'Invalid email address' });
  const now = Date.now();
  (await db.prepare('INSERT INTO guest_contacts (name,email,message,created_at) VALUES (?,?,?,?)')
    .run(name || null, email || null, message, now));
  notifyAdmin(`📬 New Public Contact\nName: ${name || '(anonymous)'}\nEmail: ${email || '(none)'}\n\n${message}`);
  (await notifyPush('support', '📬 New contact message', `${name || 'Someone'}: ${message.slice(0, 120)}`, '/'));
  io.to('monitors').emit('guest_contact', { name, email, message, created_at: now });
  log('info', 'Guest contact received', { name, email: email || '(none)' });
  res.json({ ok: true });
});

// Guest sends a chat message. If conversation_id supplied, uses that thread;
// otherwise finds latest active thread or creates a new one.
app.post('/api/support/guest/message', guestChatRateLimit, async (req, res) => {
  cors(res);
  const guestId  = String(req.body?.guest_id        || '').trim().slice(0, 64);
  const body     = String(req.body?.message         || '').trim().slice(0, MAX_SUPPORT_MSG);
  const name     = String(req.body?.name   || '').trim().slice(0, 120) || null;
  const email    = String(req.body?.email  || '').trim().slice(0, 200) || null;
  const convoId  = String(req.body?.conversation_id || '').trim().slice(0, 128) || null;
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(guestId)) return res.status(400).json({ error: 'Invalid session' });
  if (!body) return res.status(400).json({ error: 'Message is required' });
  if (email && !email.includes('@')) return res.status(400).json({ error: 'Invalid email address' });
  const now = Date.now();
  let t;
  if (convoId) {
    t = (await guestStmts.byConvoId.get(convoId));
    if (!t || t.guest_id !== guestId) return res.status(403).json({ error: 'Access denied' });
  } else {
    t = (await guestStmts.byGuestIdLatest.get(guestId));
    if (!t) {
      const newConvId = 'c' + Math.random().toString(36).slice(2) + Date.now().toString(36);
      const { id: lastInsertRowid } = (await guestStmts.insert.get(guestId, newConvId, name, email, 'open', now, now));
      t = (await guestStmts.byId.get(lastInsertRowid));
    }
  }
  if (name || email) (await guestStmts.updateContact.run(name, email, t.id));
  const { id: msgId } = (await guestStmts.insertMsg.get(t.id, 'guest', encryptText(body), now));
  (await guestStmts.touchGuestMsg.run(now, t.id));
  const payload = { id: msgId, thread_id: t.id, guest_id: guestId, sender: 'guest', body, created_at: now,
                    name: name || t.name, email: email || t.email, conversation_id: t.conversation_id };
  io.to('monitors').emit('guest_chat', payload);
  (await notifyPush('support', '💬 Live chat message', `${(name || t.name) || 'Visitor'}: ${body.slice(0, 120)}`, '/'));
  // Always Signal the admin on an inbound live-chat message (presence-independent).
  notifyAdmin(`💬 Live chat message${(await getSupportPresence()) === 'available' ? '' : ' (you are offline)'}\nFrom: ${(name || t.name) || 'Visitor'}\n\n${body.slice(0, 500)}`);
  log('info', 'Guest chat message', { threadId: t.id, convoId: t.conversation_id });
  res.json({ ok: true, id: msgId, created_at: now, presence: (await getSupportPresence()), conversation_id: t.conversation_id });
});

// Guest polls transcript + presence. Pass ?conversation_id=xxx for a specific thread;
// omit for backward-compat (falls back to latest thread for this guest_id).
app.get('/api/support/guest/poll', guestReadRateLimit, async (req, res) => {
  cors(res);
  const guestId = String(req.query?.guest_id        || '').trim();
  const convoId = String(req.query?.conversation_id || '').trim() || null;
  const after   = parseInt(/** @type {any} */ (req.query?.after), 10) || 0;
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(guestId)) return res.status(400).json({ error: 'Invalid session' });
  let t;
  if (convoId) {
    t = (await guestStmts.byConvoId.get(convoId));
    if (!t || t.guest_id !== guestId) return res.json({ presence: (await getSupportPresence()), messages: [], status: 'open' });
  } else {
    t = (await guestStmts.byGuestIdLatest.get(guestId));
  }
  if (!t) return res.json({ presence: (await getSupportPresence()), messages: [], status: 'open' });
  if (!after) (await guestStmts.clearGuestUnread.run(t.conversation_id));
  const rows = (after ? (await guestStmts.msgsSince.all(t.id, after)) : (await guestStmts.msgsByThread.all(t.id))).map(guestMsgOut);
  res.json({ presence: (await getSupportPresence()), status: t.status, messages: rows, conversation_id: t.conversation_id });
});

// ── Guest conversation management ─────────────────────────────────────────
// List all (non-deleted) conversations for a guest
app.get('/api/support/guest/threads', guestReadRateLimit, async (req, res) => {
  cors(res);
  const guestId = String(req.query?.guest_id || '').trim();
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(guestId)) return res.status(400).json({ error: 'Invalid session' });
  const threads = await Promise.all((await guestStmts.listByGuestId.all(guestId)).map(async t => {
    const last = (await guestStmts.lastMsg.get(t.id));
    return {
      conversation_id: t.conversation_id,
      status:          t.status,
      archived:        t.archived,
      unread_guest:    t.unread_guest,
      created_at:      t.created_at,
      last_msg_at:     t.last_msg_at,
      last_message:    last ? { body: decryptText(last.body).slice(0, 80), sender: last.sender, created_at: last.created_at } : null,
    };
  }));
  res.json({ threads });
});

// Create a new blank conversation (widget calls this before the user sends)
app.post('/api/support/guest/thread', guestChatRateLimit, async (req, res) => {
  cors(res);
  const guestId = String(req.body?.guest_id || '').trim().slice(0, 64);
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(guestId)) return res.status(400).json({ error: 'Invalid session' });
  const convId = 'c' + Math.random().toString(36).slice(2) + Date.now().toString(36);
  const now = Date.now();
  (await guestStmts.insert.run(guestId, convId, null, null, 'open', now, null));
  res.json({ ok: true, conversation_id: convId });
});

// Archive / unarchive a conversation
app.patch('/api/support/guest/thread/:convId/archive', guestReadRateLimit, async (req, res) => {
  cors(res);
  const guestId = String(req.body?.guest_id || req.query?.guest_id || '').trim();
  const convId  = String(req.params.convId  || '').trim();
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(guestId)) return res.status(400).json({ error: 'Invalid session' });
  const t = (await guestStmts.byConvoId.get(convId));
  if (!t || t.guest_id !== guestId) return res.status(404).json({ error: 'Not found' });
  const newVal = t.archived ? 0 : 1;
  (await guestStmts.setArchived.run(newVal, convId, guestId));
  res.json({ ok: true, archived: !!newVal });
});

// Soft-delete a conversation (hidden from guest; preserved for admin)
app.delete('/api/support/guest/thread/:convId', guestReadRateLimit, async (req, res) => {
  cors(res);
  const guestId = String(req.query?.guest_id || req.body?.guest_id || '').trim();
  const convId  = String(req.params.convId   || '').trim();
  if (!/^[A-Za-z0-9_-]{8,64}$/.test(guestId)) return res.status(400).json({ error: 'Invalid session' });
  const t = (await guestStmts.byConvoId.get(convId));
  if (!t || t.guest_id !== guestId) return res.status(404).json({ error: 'Not found' });
  (await guestStmts.softDelete.run(convId, guestId));
  res.json({ ok: true });
});
};
