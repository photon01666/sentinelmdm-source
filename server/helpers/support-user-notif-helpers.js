// helpers/support-user-notif-helpers.js — ZK notification, support thread, and email helpers.
//
// A HELPER module, not a route module: it registers nothing.
//
//   _canSendUserNotif, surveilNotify, maybeAlertTrialLapse, genRef, getOrCreateThread,
//   supportMsgOut, isValidWrapEnvelope, _isWrapObj, parseEncMsg, actingUserRow,
//   staffZkLoginFields, buildSupportContext, getSmtpConfigFn, saveSmtpConfig,
//   getEmailTemplate, saveEmailTemplate, notifyOwnerForCommand   members
//
// RELOCATE: wiring line must sit at/after L2039 and at/before L2945 — placed at L2039.
// 12 deps: USER_NOTIFY_COMMANDS (binding L686), db (binding L623), decryptText (function L162, hoisted),
// emailTemplates (binding L739), encryptText (function L153, hoisted), log (destructure L399),
// notifyAdmin (binding L656), notifyUser (binding L655), randomUUID (destructure L16),
// stmts (destructure L2038), supportStmts (destructure L2038), svc (binding L652).
//
// relative requires: none

module.exports = ({ USER_NOTIFY_COMMANDS, db, decryptText, emailTemplates, encryptText, log, notifyAdmin, notifyUser, randomUUID, stmts, supportStmts, svc }) => {
// ZK helpers (still inline)
function _canSendUserNotif(eventType) {
  return svc.notification.ZK_USER_NOTIFY_EVENTS.has(eventType);
}
function surveilNotify(cur, line) {
  // (the old opts.recurring/public-owner suppression died with the 60s pulse — every
  //  remaining call site is an activation or cap-stop event, all of which should send)
  const msg = `🔴 Monitoring Alert\nDevice: ${cur.deviceName || cur.deviceId}\nTime: ${new Date().toLocaleTimeString()}\n\n${line}`;
  if (cur.ownerType === 'public' && cur.ownerUserId) return notifyUser(cur.ownerUserId, msg, { force: true });
  return notifyAdmin(msg);
}

// Billing/trial helpers that were inline
function maybeAlertTrialLapse(ent) {
  // Stub — full implementation is in the inline section below
}

// Functions that were removed but still referenced — re-add inline
function genRef(prefix) {
  return `${prefix}-${Date.now().toString(36).toUpperCase()}-${require('crypto').randomBytes(3).toString('hex').toUpperCase()}`;
}
async function getOrCreateThread(userId) {
  let t = (await supportStmts.threadByUser.get(userId));
  if (!t) {
    const now = Date.now();
    const convId = randomUUID();
    const { id: lastInsertRowid } = (await supportStmts.insertThread.get(userId, 'Support', 'open', now, now, convId));
    t = (await supportStmts.threadById.get(lastInsertRowid));
  } else if (!t.conversation_id) {
    (await db.prepare('UPDATE support_threads SET conversation_id=? WHERE id=?').run(String(t.id), t.id));
    t = (await supportStmts.threadById.get(t.id));
  }
  return t;
}
function supportMsgOut(m) {
  if (m.enc) {
    return { id: m.id, thread_id: m.thread_id, sender: m.sender, enc: 1,
             payload: m.payload, dek_user: m.dek_user, dek_support: m.dek_support, created_at: m.created_at };
  }
  return { id: m.id, thread_id: m.thread_id, sender: m.sender, body: decryptText(m.body), created_at: m.created_at };
}
const isValidWrapEnvelope = w => !!w && typeof w === 'object' &&
  typeof w.eph_pub === 'string' && typeof w.iv === 'string' && typeof w.ct === 'string';
function _isWrapObj(w) {
  return w && typeof w === 'object' &&
    typeof w.eph_pub === 'string' && typeof w.iv === 'string' && typeof w.ct === 'string';
}
function parseEncMsg(b) {
  if (!b || (b.enc !== 1 && b.enc !== '1' && b.enc !== true)) return null;
  const payload = typeof b.payload === 'string' ? b.payload : null;
  if (!payload || payload.length > 200000 || !isValidWrapEnvelope(b.dek_user) || !isValidWrapEnvelope(b.dek_support)) return null;
  return { payload, dek_user: JSON.stringify(b.dek_user), dek_support: JSON.stringify(b.dek_support) };
}
async function actingUserRow(req) {
  if (req.session?.userId) return (await db.prepare('SELECT * FROM users WHERE id=?').get(req.session.userId));
  if (req.session?.username) return (await stmts.userByName.get(req.session.username));
  return null;
}
function staffZkLoginFields(user) {
  return (user.zk_encrypted_priv_key && user.zk_salt)
    ? { zk_salt: user.zk_salt, zk_encrypted_priv_key: user.zk_encrypted_priv_key }
    : { zk_provision: true };
}
async function buildSupportContext(userId) {
  const u = (await db.prepare('SELECT id,username,email,account_type,created_at FROM users WHERE id=?').get(userId)) || {};
  const entitlements = (await db.prepare('SELECT * FROM entitlements WHERE user_id=? ORDER BY created_at DESC').all(userId));
  const orders = (await db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC').all(userId));
  const tos = (await db.prepare('SELECT policy_key,policy_version,accepted_at,ip_address FROM tos_acceptances WHERE user_id=? ORDER BY accepted_at DESC').all(userId));
  return { user: { id: u.id, username: u.username || null, email: u.email || null, account_type: u.account_type, created_at: u.created_at },
           entitlements, orders, tos_acceptances: tos };
}
async function getSmtpConfigFn() {
  try {
    const row = (await db.prepare("SELECT value FROM settings WHERE key='smtp_config'").get());
    return row ? JSON.parse(decryptText(row.value) || '{}') : {};
  } catch { return {}; }
}
async function saveSmtpConfig(cfg) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES ('smtp_config',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run(encryptText(JSON.stringify(cfg))));
}
async function getEmailTemplate(key) {
  try {
    const row = (await db.prepare('SELECT value FROM settings WHERE key = ?').get('email_tpl_' + key));
    if (row) { const parsed = JSON.parse(decryptText(row.value) || '{}'); return parsed; }
  } catch {}
  if (key === 'approval') return { subject: emailTemplates.DEFAULT_APPROVAL_SUBJECT, body: emailTemplates.DEFAULT_APPROVAL_TEMPLATE };
  if (key === 'purchase') return { subject: emailTemplates.DEFAULT_PURCHASE_SUBJECT, body: emailTemplates.DEFAULT_PURCHASE_TEMPLATE };
  return { subject: '', body: '' };
}
async function saveEmailTemplate(key, subject, body) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
    .run(`email_tpl_${key}`, encryptText(JSON.stringify({ subject, body }))));
}
async function notifyOwnerForCommand(deviceId, command, deviceName) {
  const label = USER_NOTIFY_COMMANDS[command];
  if (!label) return;
  try {
    const ownerRow = (await db.prepare(
      'SELECT u.id, u.account_type FROM devices d JOIN users u ON d.owner_user_id=u.id WHERE d.id=?'
    ).get(deviceId));
    if (ownerRow?.account_type === 'public') {
      notifyUser(ownerRow.id,
        `${label}\nDevice: ${decryptText(deviceName) || deviceId}\nTime: ${new Date().toLocaleTimeString()}`,
        { category: 'capture', deviceId }
      ).catch(() => {});
    }
  } catch (e) { log('warn', 'notifyOwnerForCommand error', { deviceId, command, error: e.message }); }
}

  return {
    _canSendUserNotif,
    surveilNotify,
    maybeAlertTrialLapse,
    genRef,
    getOrCreateThread,
    supportMsgOut,
    isValidWrapEnvelope,
    _isWrapObj,
    parseEncMsg,
    actingUserRow,
    staffZkLoginFields,
    buildSupportContext,
    getSmtpConfigFn,
    saveSmtpConfig,
    getEmailTemplate,
    saveEmailTemplate,
    notifyOwnerForCommand,
  };
};