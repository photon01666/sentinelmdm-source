// routes/support.js — Support chat (admin ↔ buyer) + E2E key management + guest admin.
// REST handles auth'd writes + history (reusing requireAuth/requireAdmin); the
// Socket.IO rooms joined at connection push messages live to the other side.
module.exports = ({ app, db, decryptText, encryptText, getOrCreateThread, getSupportPresence,
                    guestMsgOut, guestStmts, io, log, notifyAdminForUser, notifyUser,
                    parseEncMsg, randomUUID, requireAdmin, requireAuth, setSupportPresence,
                    supportMsgOut, supportStmts, _isWrapObj, actingUserRow, buildSupportContext,
                    makeRateLimit, speakeasy, verifyUserPassword, TOTP_SECRET }) => {
// ── Phase 4: Support chat (admin ↔ buyer) ────────────────────────────────────
// REST handles auth'd writes + history (reusing requireAuth/requireAdmin); the
// Socket.IO rooms joined at connection push messages live to the other side.
const MAX_SUPPORT_MSG = 4000;

function pushSupport(room, payload) { io.to(room).emit('support:message', payload); }

// ── Buyer side (public user) ────────────────────────────────────────────────
// List all conversations for current public user
app.get('/api/support/threads', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'public account required' });
  const archived = req.query.archived === '1';
  const threads = await Promise.all((await (archived ? supportStmts.listByUserArchived : supportStmts.listByUser)
    .all(req.session.userId)).map(async t => {
      const last = (await supportStmts.lastMsg.get(t.id));
      return { id: t.id, conversation_id: t.conversation_id, status: t.status, archived: t.archived || 0,
               created_at: t.created_at, last_msg_at: t.last_msg_at, unread_user: t.unread_user || 0,
               last_preview: last && !last.enc ? decryptText(last.body).slice(0, 60) : '',
               last_enc: last ? !!last.enc : false, last_sender: last?.sender || null };
    }));
  res.json({ threads });
});

// Create a new conversation thread
app.post('/api/support/thread/new', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'public account required' });
  const now = Date.now();
  const convId = randomUUID();
  const { id: lastInsertRowid } = (await supportStmts.insertThread.get(req.session.userId, 'Support', 'open', now, now, convId));
  const t = (await supportStmts.threadById.get(lastInsertRowid));
  res.json({ ok: true, conversation_id: t.conversation_id, thread: { id: t.id, conversation_id: t.conversation_id, created_at: t.created_at } });
});

// Fetch a specific conversation + full history; clears my unread counter.
app.get('/api/support/thread', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'public account required' });
  let t;
  if (req.query.conv) {
    t = (await supportStmts.threadByConvoId.get(req.query.conv, req.session.userId));
    if (!t) return res.status(404).json({ error: 'Thread not found' });
  } else {
    t = (await getOrCreateThread(req.session.userId));
  }
  const after = parseInt(/** @type {any} */ (req.query.after), 10) || 0;
  if (!after) (await supportStmts.markUserRead.run(t.id));
  const msgs = after
    ? (await supportStmts.msgsSince.all(t.id, after)).map(supportMsgOut)
    : (await supportStmts.msgsByThread.all(t.id)).map(supportMsgOut);
  res.json({
    thread: { id: t.id, conversation_id: t.conversation_id, status: t.status, archived: t.archived || 0,
              created_at: t.created_at, last_msg_at: t.last_msg_at },
    messages: msgs,
  });
});

// Buyer sends a message → store, bump admin unread, push to admins + own tabs.
app.post('/api/support/message', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public')
    return res.status(403).json({ error: 'public account required' });
  const enc  = parseEncMsg(req.body);            // E2E envelope, or null for legacy plaintext
  const body = enc ? null : String(req.body?.body || '').trim().slice(0, MAX_SUPPORT_MSG);
  if (!enc && !body) return res.status(400).json({ error: 'message body required' });
  let t;
  const convId = req.body?.convId;
  if (convId) {
    t = (await supportStmts.threadByConvoId.get(convId, req.session.userId));
    if (!t) return res.status(404).json({ error: 'Thread not found' });
  } else {
    t = (await getOrCreateThread(req.session.userId));
  }
  const now = Date.now();
  let id, payload;
  if (enc) {
    ({ id } = (await supportStmts.insertMsgEnc.get(t.id, 'user', now, enc.payload, enc.dek_user, enc.dek_support)));
    payload = { id, thread_id: t.id, conversation_id: t.conversation_id, sender: 'user', enc: 1,
                payload: enc.payload, dek_user: enc.dek_user, dek_support: enc.dek_support, created_at: now,
                user_id: req.session.userId, username: req.session.username || null };
  } else {
    ({ id } = (await supportStmts.insertMsg.get(t.id, 'user', encryptText(body), now)));
    payload = { id, thread_id: t.id, conversation_id: t.conversation_id, sender: 'user', body, created_at: now,
                user_id: req.session.userId, username: req.session.username || null };
  }
  (await supportStmts.touchUserMsg.run(now, t.id));
  pushSupport('support:admins', payload);
  pushSupport(`support:user:${req.session.userId}`, payload);
  // E2E: the server holds no key, so the relay carries NO message body (content-free).
  const who = req.session.username || ('user#' + req.session.userId);
  notifyAdminForUser(enc
    ? `💬 New encrypted support message from ${who}\n(end-to-end encrypted — open the dashboard to read)`
    : `💬 Support message from ${who}\n\n${body.slice(0, 500)}`, req.session.userId).catch(() => {});
  log('info', 'Support message (user→admin)', { userId: req.session.userId, threadId: t.id, enc: !!enc });
  res.json({ ok: true, id, created_at: now });
});

// Public user deletes one of their own messages (any conversation)
app.delete('/api/support/message/:id', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public') return res.status(403).json({ error: 'public account required' });
  const msgId = parseInt(req.params.id, 10);
  const msg = (await db.prepare('SELECT sm.* FROM support_messages sm JOIN support_threads st ON st.id=sm.thread_id WHERE sm.id=? AND st.user_id=?').get(msgId, req.session.userId));
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  if (msg.sender !== 'user') return res.status(403).json({ error: 'Can only delete your own messages' });
  (await db.prepare('DELETE FROM support_messages WHERE id=?').run(msgId));
  pushSupport('support:admins', { deleted: true, id: msgId, thread_id: msg.thread_id });
  pushSupport(`support:user:${req.session.userId}`, { deleted: true, id: msgId, thread_id: msg.thread_id });
  res.json({ ok: true });
});

// Public user archives / unarchives their own support thread (legacy single-thread)
app.post('/api/support/thread/archive', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public') return res.status(403).json({ error: 'public account required' });
  const t = (await getOrCreateThread(req.session.userId));
  const newVal = t.archived ? 0 : 1;
  (await db.prepare('UPDATE support_threads SET archived=? WHERE id=?').run(newVal, t.id));
  res.json({ ok: true, archived: !!newVal });
});

// Archive / unarchive a specific conversation by conversation_id
app.patch('/api/support/thread/:convId/archive', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public') return res.status(403).json({ error: 'public account required' });
  const t = (await supportStmts.threadByConvoId.get(req.params.convId, req.session.userId));
  if (!t) return res.status(404).json({ error: 'Thread not found' });
  const newVal = t.archived ? 0 : 1;
  (await db.prepare('UPDATE support_threads SET archived=? WHERE id=?').run(newVal, t.id));
  res.json({ ok: true, archived: !!newVal });
});

// Delete a specific conversation by conversation_id
app.delete('/api/support/thread/:convId', requireAuth, async (req, res) => {
  if (req.session.account_type !== 'public') return res.status(403).json({ error: 'public account required' });
  const t = (await supportStmts.threadByConvoId.get(req.params.convId, req.session.userId));
  if (!t) return res.status(404).json({ error: 'Thread not found' });
  (await db.prepare('DELETE FROM support_messages WHERE thread_id=?').run(t.id));
  (await db.prepare('DELETE FROM support_threads WHERE id=?').run(t.id));
  pushSupport('support:admins', { thread_deleted: true, thread_id: t.id });
  res.json({ ok: true });
});

// ── Admin side ──────────────────────────────────────────────────────────────
// Inbox: all threads with last-message preview + unread + the user's display name.
app.get('/api/admin/support/threads', requireAdmin, async (_req, res) => {
  const threads = await Promise.all((await supportStmts.allThreads.all()).map(async t => {
    let username = null, email = null;
    try { const u = (await db.prepare('SELECT username,email FROM users WHERE id=?').get(t.user_id)); if (u) { username = u.username; email = u.email; } } catch {}
    const last = (await supportStmts.lastMsg.get(t.id));
    return { id: t.id, user_id: t.user_id, username, email, status: t.status, archived: t.archived || 0,
             last_msg_at: t.last_msg_at, unread_admin: t.unread_admin,
             last_preview: last && !last.enc ? decryptText(last.body).slice(0, 80) : '',
             last_enc: last ? !!last.enc : false, last_sender: last?.sender || null };
  }));
  res.json({ threads });
});

// Open one thread: history + the dispute-resolution context panel; clears admin unread.
app.get('/api/admin/support/threads/:id', requireAdmin, async (req, res) => {
  const t = (await supportStmts.threadById.get(req.params.id));
  if (!t) return res.status(404).json({ error: 'thread not found' });
  (await supportStmts.markAdminRead.run(t.id));
  // Owner's personal public key so the admin can E2E-encrypt replies to {owner, Support}.
  const ownerRow = (await db.prepare('SELECT zk_public_key FROM users WHERE id=?').get(t.user_id));
  res.json({
    thread: { id: t.id, user_id: t.user_id, status: t.status, created_at: t.created_at },
    owner_zk_pub: ownerRow?.zk_public_key || null,
    messages: (await supportStmts.msgsByThread.all(t.id)).map(supportMsgOut),
    context: (await buildSupportContext(t.user_id)),   // serial/IMEI, ToS timestamps, both deadlines
  });
});

// ── E2E "Conversations" key management ───────────────────────────────────────
// Support staff (admin / admin_created) self-provision a personal EC P-256 keypair (first login),
// then ONE shared "Support" keypair is bootstrapped: its public key is encryption target for every
// Conversation, its private key is ECDH-wrapped to each staffer's personal pubkey. The server stores
// only public keys + opaque wraps — it can never read a message.

// Staff self-provision their personal keypair (browser generated it under the login password).
app.post('/api/users/me/zk_keypair', requireAuth, async (req, res) => {
  if (req.session.account_type === 'public')
    return res.status(403).json({ error: 'not applicable to public accounts' });
  const u = (await actingUserRow(req));
  if (!u) return res.status(400).json({ error: 'no acting user' });
  const { zk_public_key, zk_encrypted_priv_key, zk_salt } = req.body || {};
  if (typeof zk_public_key !== 'string' || typeof zk_encrypted_priv_key !== 'string' || typeof zk_salt !== 'string')
    return res.status(400).json({ error: 'bad keypair' });
  if (u.zk_public_key) return res.json({ ok: true, already: true });   // never overwrite → would orphan grants
  (await db.prepare('UPDATE users SET zk_public_key=?, zk_encrypted_priv_key=?, zk_salt=? WHERE id=?')
    .run(zk_public_key, zk_encrypted_priv_key, zk_salt, u.id));
  log('info', 'Staff ZK keypair provisioned', { user: u.username });
  res.json({ ok: true });
});

// Staff: re-unlock the personal key in an ALREADY-SIGNED-IN tab that lost it (browser restart,
// new tab, passkey sign-in without the E2E link, companion app recreated its WebView). The
// persistent session cookie keeps you logged in, but the private key deliberately lives only in
// per-tab sessionStorage — so E2E Conversations show the "personal key isn't loaded" banner and
// the only recovery used to be a full sign-out. This re-authenticates with the PASSWORD (+TOTP
// when configured) and returns the same PBKDF2-wrapped blob /login returns, so the browser can
// derive the key in place. Password+TOTP are mandatory (never the bare session): the wrapped key
// is offline-crackable if it ever leaks, so a hijacked-but-unlocked session must not fetch it.
const reunlockRateLimit = makeRateLimit(10, 15 * 60 * 1000, 'reunlock');
app.post('/api/support/reunlock-key', requireAuth, reunlockRateLimit, async (req, res) => {
  const u = (await actingUserRow(req));
  if (!u) return res.status(400).json({ error: 'no acting user' });
  if (u.role !== 'admin' && u.account_type !== 'admin_created')
    return res.status(403).json({ error: 'Staff accounts only' });
  const { password, authHash, code } = req.body || {};
  if (!(await verifyUserPassword(u, { password, authHash })))
    return res.status(401).json({ error: 'Incorrect password' });
  // Mirror the login routes' 2FA rule: admins answer to their own secret (or the deployment's
  // global TOTP_SECRET) unless explicitly disabled; admin_created sub-users normally have none.
  const dbSecret = u.totp_secret ? decryptText(u.totp_secret) : null;
  let totpSecretToUse = null;
  if (u.role === 'admin') {
    if (!(dbSecret === 'DISABLED' && !u.totp_verified))
      totpSecretToUse = (u.totp_verified && dbSecret) ? dbSecret : TOTP_SECRET;
  } else if (u.totp_verified && dbSecret) {
    totpSecretToUse = dbSecret;
  }
  if (totpSecretToUse) {
    const ok = speakeasy.totp.verify({
      secret: totpSecretToUse, encoding: 'base32',
      token: String(code || '').replace(/\s/g, ''), window: 1,
    });
    if (!ok) return res.status(401).json({ error: 'Invalid 2FA code' });
  }
  if (!u.zk_encrypted_priv_key || !u.zk_salt)
    return res.status(409).json({ error: 'No wrapped key on file — sign out and sign back in with your password.' });
  res.json({ zk_salt: u.zk_salt, zk_encrypted_priv_key: u.zk_encrypted_priv_key });
});

// The Support PUBLIC key — any authed user fetches it to encrypt a Conversation message to Support.
app.get('/api/support/support-pubkey', requireAuth, async (_req, res) => {
  const row = (await db.prepare("SELECT value FROM settings WHERE key='support_zk_public'").get());
  res.json({ pub: row?.value || null });
});

// Admin: Support-key status + the staff roster (for granting). `my_support_wrap` is wrapped to the
// caller's own key, so returning it is safe — only they can unwrap it.
app.get('/api/admin/support/keys/status', requireAdmin, async (req, res) => {
  const pubRow = (await db.prepare("SELECT value FROM settings WHERE key='support_zk_public'").get());
  const me = (await actingUserRow(req));
  const staff = (await db.prepare(
    "SELECT id, username, account_type, zk_public_key, support_key_wrap FROM users WHERE role='admin' OR account_type='admin_created' ORDER BY username").all());
  res.json({
    enabled:         !!pubRow?.value,
    support_pub:     pubRow?.value || null,
    my_personal_pub: me?.zk_public_key || null,
    my_support_wrap: me?.support_key_wrap || null,
    staff: staff.map(s => ({ id: s.id, username: s.username, account_type: s.account_type,
      has_personal_key: !!s.zk_public_key, personal_pub: s.zk_public_key || null, granted: !!s.support_key_wrap })),
  });
});

// Admin: bootstrap the shared Support keypair (one-time). Browser generates it, stores the PUBLIC
// key here and the PRIVATE key wrapped to the calling admin's personal pubkey. Refuses if already
// enabled (re-enabling would orphan every existing E2E message).
app.post('/api/admin/support/keys/enable', requireAdmin, async (req, res) => {
  const existing = (await db.prepare("SELECT value FROM settings WHERE key='support_zk_public'").get());
  if (existing?.value) return res.status(409).json({ error: 'Encrypted support is already enabled.' });
  const { support_pub, self_wrap } = req.body || {};
  if (typeof support_pub !== 'string' || !_isWrapObj(self_wrap)) return res.status(400).json({ error: 'bad payload' });
  const me = (await actingUserRow(req));
  if (!me) return res.status(400).json({ error: 'no acting user' });
  if (!me.zk_public_key) return res.status(400).json({ error: 'Set up your personal key first — sign out and back in.' });
  (await db.prepare("INSERT INTO settings (key,value) VALUES ('support_zk_public',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(support_pub));
  (await db.prepare('UPDATE users SET support_key_wrap=? WHERE id=?').run(JSON.stringify(self_wrap), me.id));
  log('info', 'E2E support encryption enabled', { by: req.session.username });
  res.json({ ok: true });
});

// Admin (holding the Support priv) grants Support-key access to another staffer by wrapping the
// Support private key to that staffer's personal pubkey.
app.post('/api/admin/support/keys/grant', requireAdmin, async (req, res) => {
  const { user_id, wrap } = req.body || {};
  if (!user_id || !_isWrapObj(wrap)) return res.status(400).json({ error: 'bad payload' });
  const target = (await db.prepare('SELECT id, role, account_type, zk_public_key FROM users WHERE id=?').get(user_id));
  if (!target || (target.role !== 'admin' && target.account_type !== 'admin_created'))
    return res.status(404).json({ error: 'not a staff user' });
  if (!target.zk_public_key) return res.status(400).json({ error: 'target has no personal key yet' });
  (await db.prepare('UPDATE users SET support_key_wrap=? WHERE id=?').run(JSON.stringify(wrap), target.id));
  log('info', 'E2E support key granted', { to: target.id, by: req.session.username });
  res.json({ ok: true });
});

// Admin: RE-ESTABLISH the shared Support keypair (recovery). Unlike /enable, this overwrites an
// existing key and CLEARS every staff wrap (they must be re-granted). Used when the holder's
// personal key drifted and the old wrap can no longer be unwrapped. Re-keying makes any prior
// enc=1 messages undecryptable — a deliberate, admin-authorized recovery step. The browser
// generates the new keypair and wraps the private key to the calling admin's own personal key.
app.post('/api/admin/support/keys/reestablish', requireAdmin, async (req, res) => {
  const { support_pub, self_wrap } = req.body || {};
  if (typeof support_pub !== 'string' || !_isWrapObj(self_wrap)) return res.status(400).json({ error: 'bad payload' });
  const me = (await actingUserRow(req));
  if (!me) return res.status(400).json({ error: 'no acting user' });
  if (!me.zk_public_key) return res.status(400).json({ error: 'Set up your personal key first — sign out and back in.' });
  await db.transaction(async () => {
    (await db.prepare('UPDATE users SET support_key_wrap=NULL WHERE support_key_wrap IS NOT NULL').run());
    (await db.prepare("INSERT INTO settings (key,value) VALUES ('support_zk_public',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(support_pub));
    (await db.prepare('UPDATE users SET support_key_wrap=? WHERE id=?').run(JSON.stringify(self_wrap), me.id));
  })();
  log('warn', 'E2E support encryption RE-ESTABLISHED (re-keyed; all prior staff grants cleared)', { by: req.session.username });
  res.json({ ok: true });
});

// Admin starts a conversation with a user (from the Contacts tab). Finds or creates the
// support thread for that user, then returns the thread ID so the UI can load it.
app.post('/api/admin/support/threads/new-for-user', requireAdmin, async (req, res) => {
  const userId = Number(req.body?.user_id);
  if (!userId) return res.status(400).json({ error: 'user_id required' });
  const u = (await db.prepare('SELECT id,username,email,account_type FROM users WHERE id=?').get(userId));
  if (!u || u.account_type !== 'public') return res.status(404).json({ error: 'Public user not found' });
  const convId = String(Date.now()) + '-' + Math.random().toString(36).slice(2, 7);
  try {
    // Find existing open thread, or create one
    let t = (await supportStmts.threadByUser.get(userId));
    if (!t) {
      const now = Date.now();
      const { id } = (await supportStmts.insertThread.get(userId, 'Support', 'open', now, now, convId));
      t = (await supportStmts.threadById.get(id));
    } else if (!t.conversation_id) {
      await db.prepare('UPDATE support_threads SET conversation_id=? WHERE id=?').run(String(t.id), t.id);
      t = (await supportStmts.threadById.get(t.id));
    }
    res.json({ ok: true, thread_id: t.id, conversation_id: t.conversation_id, username: u.username, email: u.email });
  } catch (e) {
    log('error', 'Failed to create support thread for user', { userId, err: e.message });
    res.status(500).json({ error: 'Could not start conversation' });
  }
});

// Admin replies → store, bump user unread, push to that user + admins.
app.post('/api/admin/support/threads/:id/reply', requireAdmin, async (req, res) => {
  const t = (await supportStmts.threadById.get(req.params.id));
  if (!t) return res.status(404).json({ error: 'thread not found' });
  const enc  = parseEncMsg(req.body);            // E2E envelope, or null for legacy plaintext
  const body = enc ? null : String(req.body?.body || '').trim().slice(0, MAX_SUPPORT_MSG);
  if (!enc && !body) return res.status(400).json({ error: 'message body required' });
  const now = Date.now();
  let id, payload;
  if (enc) {
    ({ id } = (await supportStmts.insertMsgEnc.get(t.id, 'admin', now, enc.payload, enc.dek_user, enc.dek_support)));
    payload = { id, thread_id: t.id, sender: 'admin', enc: 1,
                payload: enc.payload, dek_user: enc.dek_user, dek_support: enc.dek_support,
                created_at: now, user_id: t.user_id };
  } else {
    ({ id } = (await supportStmts.insertMsg.get(t.id, 'admin', encryptText(body), now)));
    payload = { id, thread_id: t.id, sender: 'admin', body, created_at: now, user_id: t.user_id };
  }
  (await supportStmts.touchAdminMsg.run(now, t.id));
  pushSupport(`support:user:${t.user_id}`, payload);
  pushSupport('support:admins', payload);
  // E2E: content-free relay (the server cannot read the reply).
  notifyUser(t.user_id, enc
    ? `💬 New encrypted support reply\n(end-to-end encrypted — open the dashboard to read)`
    : `💬 Support reply\n\n${body.slice(0, 500)}\n\nOpen the dashboard to reply.`).catch(() => {});
  log('info', 'Support message (admin→user)', { userId: t.user_id, threadId: t.id, by: req.session.username, enc: !!enc });
  res.json({ ok: true, id, created_at: now });
});

app.post('/api/admin/support/threads/:id/status', requireAdmin, async (req, res) => {
  const t = (await supportStmts.threadById.get(req.params.id));
  if (!t) return res.status(404).json({ error: 'thread not found' });
  const status = req.body?.status === 'closed' ? 'closed' : 'open';
  (await supportStmts.setStatus.run(status, t.id));
  res.json({ ok: true, status });
});

// Admin deletes a single message from a Conversations thread. Broadcasts a
// `{ deleted:true, id }` payload so the user's open widget removes it too.
app.delete('/api/admin/support/threads/:tid/messages/:mid', requireAdmin, async (req, res) => {
  const t = (await supportStmts.threadById.get(req.params.tid));
  if (!t) return res.status(404).json({ error: 'thread not found' });
  const info = (await db.prepare('DELETE FROM support_messages WHERE id=? AND thread_id=?').run(req.params.mid, t.id));
  if (!info.changes) return res.status(404).json({ error: 'message not found' });
  // Keep the thread's preview/ordering coherent if the latest message was removed.
  const last = (await supportStmts.lastMsg.get(t.id));
  (await db.prepare('UPDATE support_threads SET last_msg_at=? WHERE id=?').run(last ? last.created_at : t.created_at, t.id));
  const payload = { deleted: true, id: Number(req.params.mid), thread_id: t.id, user_id: t.user_id };
  pushSupport(`support:user:${t.user_id}`, payload);
  pushSupport('support:admins', payload);
  log('info', 'Support message deleted', { threadId: t.id, msgId: req.params.mid, by: req.session.username });
  res.json({ ok: true });
});

// Archive (soft-hide) or unarchive an entire Conversations thread.
app.post('/api/admin/support/threads/:id/archive', requireAdmin, async (req, res) => {
  const t = (await supportStmts.threadById.get(req.params.id));
  if (!t) return res.status(404).json({ error: 'thread not found' });
  const archived = req.body?.archived ? 1 : 0;
  (await db.prepare('UPDATE support_threads SET archived=? WHERE id=?').run(archived, t.id));
  res.json({ ok: true, archived });
});

// Delete an entire Conversations thread (thread + all its messages).
app.delete('/api/admin/support/threads/:id', requireAdmin, async (req, res) => {
  const t = (await supportStmts.threadById.get(req.params.id));
  if (!t) return res.status(404).json({ error: 'thread not found' });
  (await db.prepare('DELETE FROM support_messages WHERE thread_id=?').run(t.id));
  (await db.prepare('DELETE FROM support_threads WHERE id=?').run(t.id));
  pushSupport('support:admins', { thread_deleted: true, thread_id: t.id });
  pushSupport(`support:user:${t.user_id}`, { thread_deleted: true, thread_id: t.id });
  log('info', 'Support thread deleted', { threadId: t.id, by: req.session.username });
  res.json({ ok: true });
});

// ── Guest contact messages (public contact form) ─────────────────────────────
app.get('/api/admin/support/contacts', requireAdmin, async (_req, res) => {
  const rows = (await db.prepare('SELECT * FROM guest_contacts ORDER BY created_at DESC').all());
  res.json({ contacts: rows });
});
app.patch('/api/admin/support/contacts/:id/read', requireAdmin, async (req, res) => {
  (await db.prepare('UPDATE guest_contacts SET read=1 WHERE id=?').run(req.params.id));
  res.json({ ok: true });
});
app.post('/api/admin/support/contacts/:id/archive', requireAdmin, async (req, res) => {
  const archived = req.body?.archived ? 1 : 0;
  (await db.prepare('UPDATE guest_contacts SET archived=? WHERE id=?').run(archived, req.params.id));
  res.json({ ok: true, archived });
});
app.delete('/api/admin/support/contacts/:id', requireAdmin, async (req, res) => {
  (await db.prepare('DELETE FROM guest_contacts WHERE id=?').run(req.params.id));
  log('info', 'Guest contact message deleted', { id: req.params.id, by: req.session.username });
  res.json({ ok: true });
});

// ── Support presence (admin Away/Available toggle) ───────────────────────────
app.get('/api/admin/support/presence', requireAdmin, async (_req, res) => {
  res.json({ presence: (await getSupportPresence()) });
});
app.post('/api/admin/support/presence', requireAdmin, async (req, res) => {
  const p = req.body?.presence === 'available' ? 'available' : 'away';
  (await setSupportPresence(p));
  // Tell every connected admin tab + any guests polling will see it on next poll.
  io.to('monitors').emit('support_presence', { presence: p });
  log('info', 'Support presence changed', { presence: p, by: req.session?.username });
  res.json({ ok: true, presence: p });
});

// ── Guest live-chat threads (admin side) ─────────────────────────────────────
app.get('/api/admin/support/guest-threads', requireAdmin, async (_req, res) => {
  const threads = await Promise.all((await guestStmts.all.all()).map(async t => {
    const last = (await guestStmts.lastMsg.get(t.id));
    return { id: t.id, guest_id: t.guest_id, name: t.name, email: t.email, status: t.status, archived: t.archived || 0,
             last_msg_at: t.last_msg_at, unread_admin: t.unread_admin,
             last_preview: last ? decryptText(last.body).slice(0, 80) : '', last_sender: last?.sender || null };
  }));
  res.json({ threads });
});
app.get('/api/admin/support/guest-threads/:id', requireAdmin, async (req, res) => {
  const t = (await guestStmts.byId.get(req.params.id));
  if (!t) return res.status(404).json({ error: 'thread not found' });
  (await guestStmts.markAdminRead.run(t.id));
  res.json({
    thread: { id: t.id, guest_id: t.guest_id, name: t.name, email: t.email, status: t.status, created_at: t.created_at },
    messages: (await guestStmts.msgsByThread.all(t.id)).map(guestMsgOut),
  });
});
app.post('/api/admin/support/guest-threads/:id/reply', requireAdmin, async (req, res) => {
  const t = (await guestStmts.byId.get(req.params.id));
  if (!t) return res.status(404).json({ error: 'thread not found' });
  const body = String(req.body?.body || '').trim().slice(0, MAX_SUPPORT_MSG);
  if (!body) return res.status(400).json({ error: 'message body required' });
  const now = Date.now();
  const { id: id } = (await guestStmts.insertMsg.get(t.id, 'admin', encryptText(body), now));
  (await guestStmts.touchAdminMsg.run(now, t.id));
  // Guest receives it on their next poll. Echo to admin tabs so the bubble appears immediately.
  const payload = { id, thread_id: t.id, guest_id: t.guest_id, sender: 'admin', body, created_at: now };
  io.to('monitors').emit('guest_chat', payload);
  log('info', 'Guest chat reply (admin→guest)', { threadId: t.id, by: req.session.username });
  res.json({ ok: true, id, created_at: now });
});

// Admin deletes a single message from a guest live-chat thread.
app.delete('/api/admin/support/guest-threads/:tid/messages/:mid', requireAdmin, async (req, res) => {
  const t = (await guestStmts.byId.get(req.params.tid));
  if (!t) return res.status(404).json({ error: 'thread not found' });
  const info = (await db.prepare('DELETE FROM guest_messages WHERE id=? AND thread_id=?').run(req.params.mid, t.id));
  if (!info.changes) return res.status(404).json({ error: 'message not found' });
  const last = (await guestStmts.lastMsg.get(t.id));
  (await db.prepare('UPDATE guest_threads SET last_msg_at=? WHERE id=?').run(last ? last.created_at : t.created_at, t.id));
  const payload = { deleted: true, id: Number(req.params.mid), thread_id: t.id, guest_id: t.guest_id };
  io.to('monitors').emit('guest_chat', payload);
  log('info', 'Guest message deleted', { threadId: t.id, msgId: req.params.mid, by: req.session.username });
  res.json({ ok: true });
});

// Archive (soft-hide) or unarchive an entire guest live-chat thread.
app.post('/api/admin/support/guest-threads/:id/archive', requireAdmin, async (req, res) => {
  const t = (await guestStmts.byId.get(req.params.id));
  if (!t) return res.status(404).json({ error: 'thread not found' });
  const archived = req.body?.archived ? 1 : 0;
  (await db.prepare('UPDATE guest_threads SET archived=? WHERE id=?').run(archived, t.id));
  res.json({ ok: true, archived });
});

// Delete an entire guest live-chat thread (thread + all its messages).
app.delete('/api/admin/support/guest-threads/:id', requireAdmin, async (req, res) => {
  const t = (await guestStmts.byId.get(req.params.id));
  if (!t) return res.status(404).json({ error: 'thread not found' });
  (await db.prepare('DELETE FROM guest_messages WHERE thread_id=?').run(t.id));
  (await db.prepare('DELETE FROM guest_threads WHERE id=?').run(t.id));
  io.to('monitors').emit('guest_chat', { thread_deleted: true, thread_id: t.id });
  log('info', 'Guest thread deleted', { threadId: t.id, by: req.session.username });
  res.json({ ok: true });
});
};
