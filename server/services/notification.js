// services/notification.js — Signal, Discord, email, web-push, FCM dispatch.
// Factory pattern: initialized with dependencies to avoid circular requires.

const webPush = require('web-push');

module.exports = function createNotificationService({ db, log, decryptText, kv, state, config, reqClientIp: _reqClientIp }) {
  const {
    SIGNAL_API_URL, SIGNAL_SENDER, SIGNAL_GROUP, SIGNAL_SECURITY_GROUP, SIGNAL_HYBRID_GROUP,
    PLAN_KEY_BY_PRICE,
  } = config;

  // ── ZK event → human-readable label map ──────────────────────────────────────
  const ZK_EVENT_LABELS = {
    location:          '📍 Location Update',
    photo:             '📷 Photo Captured',
    screencapture:     '🖥️ Screenshot Captured',
    unlock_photo:      '🔓 Unlock Photo',
    audio_chunk:       '🎙️ Audio Clip',
    screen_frame:      '📺 Screen Frame',
    video_frame:       '📹 Video Frame',
    app_list:          '📦 App List',
    battery_stats:     '🔋 Battery Stats',
    call_log:          '📞 Call Log',
    sms_list:          '💬 SMS Messages',
    contacts_data:     '👤 Contacts',
    calendar_data:     '📅 Calendar',
    usage_stats_data:  '📊 Usage Stats',
    keylog_data:       '⌨️ Keylog Entry',
    screen_text_data:  '🔤 Screen Text',
    lockscreen_layout: '🔒 Lockscreen Layout',
    app_foreground:    '🔄 App Foreground',
    notification_event:'🔔 Notification',
    clipboard_event:   '📋 Clipboard',
    network_info:      '📶 Network Info',
    network_logs:      '📡 Network Logs',
    security_logs:     '🛡️ Security Logs',
    geofence_alert:    '🚨 Geofence Alert',
    geofence_list:     '🗺️ Geofence List',
    file_list:         '📂 File Listing',
    file_data:         '📥 File Data',
    file_chunk:        '📥 File Chunk',
    shell_output:      '💻 Shell Output',
    logcat_line:       '📜 Logcat',
    bt_device_event:   '📶 Bluetooth Scan',
    tracker_detection: '📡 Tracker Detected',
  };

  const ZK_USER_NOTIFY_EVENTS = new Set(['photo', 'audio_chunk', 'unlock_photo']);
  function _canSendUserNotif(eventType) { return ZK_USER_NOTIFY_EVENTS.has(eventType); }

  const USER_NOTIFY_COMMANDS = {
    start_screenshot_interval: '🖥️ Screenshot Capture Started',
    stop_screenshot_interval:  '🖥️ Screenshot Capture Stopped',
  };

  const USER_ALERT_CATEGORIES = new Set(['geofence', 'offline', 'capture', 'arp_spoof', 'arp_recon', 'edr_alert', 'ra_agent_update', 'applocker_blocked', 'applocker_audit', 'sentry', 'winupdate_force', 'usb_lockdown', 'learn_mode', 'screentext', 'tracker']);
  const AI_REPORT_CATEGORIES = new Set(['arp_summary', 'it_audit_summary']);

  function userWantsAlert(prefs, category) {
    if (!category || !USER_ALERT_CATEGORIES.has(category)) return true;
    return prefs?.events?.[category] !== false;
  }

  // ── Discord SSRF allowlist ───────────────────────────────────────────────────
  const DISCORD_WEBHOOK_HOSTS = new Set([
    'discord.com', 'discordapp.com', 'canary.discord.com', 'ptb.discord.com',
  ]);
  function isDiscordWebhookUrl(url) {
    let u;
    try { u = new URL(String(url)); } catch { return false; }
    return u.protocol === 'https:' &&
           DISCORD_WEBHOOK_HOSTS.has(u.hostname.toLowerCase()) &&
           u.pathname.startsWith('/api/webhooks/');
  }

  // ── Low-level senders ───────────────────────────────────────────────────────
  async function signalSend(message, base64Attachments = [], groupOverride = null) {
    if (!SIGNAL_SENDER) return;
    const recipients = [groupOverride || SIGNAL_GROUP];
    const body = { message, number: SIGNAL_SENDER, recipients };
    if (base64Attachments.length) body.base64_attachments = base64Attachments;
    try {
      const res = await fetch(`${SIGNAL_API_URL}/v2/send`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!res.ok) console.error('Signal send failed:', res.status, await res.text().catch(() => ''));
    } catch (e) { console.error('Signal send error:', e.message); }
  }

  async function discordSend(message, webhookUrl) {
    if (!webhookUrl) return;
    if (!isDiscordWebhookUrl(webhookUrl)) {
      console.error('Discord send blocked — non-Discord webhook URL rejected');
      return;
    }
    const chunks = [];
    for (let i = 0; i < message.length; i += 1990) chunks.push(message.slice(i, i + 1990));
    for (const chunk of chunks) {
      try {
        const res = await fetch(webhookUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ content: chunk }),
        });
        if (!res.ok) console.error('Discord send failed:', res.status, await res.text().catch(() => ''));
      } catch (e) { console.error('Discord send error:', e.message); }
    }
  }

  async function getDiscordWebhook() {
    try {
      const row = (await db.prepare("SELECT value FROM settings WHERE key='notif_discord_webhook'").get());
      return row?.value ? row.value.trim() : null;
    } catch { return null; }
  }

  async function getUserNotifPrefs(userId) {
    try {
      const row = (await db.prepare('SELECT notif_prefs FROM users WHERE id=?').get(userId));
      if (!row?.notif_prefs) return {};
      return JSON.parse(row.notif_prefs);
    } catch { return {}; }
  }

  // ── Admin-level dispatchers ─────────────────────────────────────────────────
  async function notifyAdmin(message, base64Attachments = []) {
    await signalSend(message, base64Attachments);
    const discordUrl = (await getDiscordWebhook());
    if (discordUrl) await discordSend(message, discordUrl);
  }

  // Is this (public) account on the Hybrid Managed plan?
  async function userOnHybridPlan(userId) {
    if (userId == null) return false;
    const u = (await db.prepare('SELECT account_type, comp_plan, comp_expires_at FROM users WHERE id=?').get(userId));
    if (!u || u.account_type !== 'public') return false;
    if (u.comp_plan === 'hybrid' && (u.comp_expires_at == null || Number(u.comp_expires_at) > Date.now())) return true;
    let row = (await db.prepare("SELECT status, price_id FROM subscriptions WHERE user_id=? ORDER BY created_at DESC LIMIT 1").get(userId));
    if (!row) {
      try {
        const emRow = (await db.prepare('SELECT email FROM users WHERE id=?').get(userId));
        const em = emRow ? String(decryptText(emRow.email) || '').toLowerCase() : '';
        if (em) row = (await db.prepare("SELECT status, price_id FROM subscriptions WHERE LOWER(email)=? AND (user_id IS NULL OR user_id=?) ORDER BY created_at DESC LIMIT 1").get(em, userId));
      } catch { /* best-effort email fallback */ }
    }
    const pk = row ? PLAN_KEY_BY_PRICE[row.price_id] : null;
    return !!row && ['trialing', 'active', 'past_due'].includes(row.status) && !!pk && String(pk).startsWith('hybrid');
  }

  async function publicAccountAlertPolicy(userId) {
    if (userId == null) return null;
    try {
      const row = (await db.prepare('SELECT account_type FROM users WHERE id=?').get(userId));
      if (!row || row.account_type !== 'public') return null;
      return (await userOnHybridPlan(userId)) ? 'hybrid' : 'suppress';
    } catch (e) { log('warn', 'publicAccountAlertPolicy error', { userId, error: e.message }); }
    return null;
  }

  async function deviceOwnerAlertPolicy(deviceId) {
    if (!deviceId) return null;
    try {
      const row = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(deviceId));
      if (!row?.owner_user_id) return null;
      return (await publicAccountAlertPolicy(row.owner_user_id));
    } catch (e) { log('warn', 'deviceOwnerAlertPolicy error', { deviceId, error: e.message }); }
    return null;
  }

  async function deviceAlertTarget(deviceId) {
    const policy = (await deviceOwnerAlertPolicy(deviceId));
    return { suppress: policy !== null, group: policy === 'hybrid' ? SIGNAL_HYBRID_GROUP : null };
  }

  async function notifyAdminForDevice(message, deviceId, base64Attachments = []) {
    const { suppress, group } = (await deviceAlertTarget(deviceId));
    if (suppress) { log('info', 'Admin alert suppressed (public non-hybrid device)', { deviceId }); return; }
    await signalSend(message, base64Attachments, group || null);
    const discordUrl = (await getDiscordWebhook());
    if (discordUrl) await discordSend(message, discordUrl);
  }

  async function notifyAdminForUser(message, userId, policyOverride = null) {
    const policy = policyOverride || (await publicAccountAlertPolicy(userId));
    if (policy) { log('info', 'Admin alert suppressed (public account)', { userId }); return; }
    await signalSend(message, [], null);
    const discordUrl = (await getDiscordWebhook());
    if (discordUrl) await discordSend(message, discordUrl);
  }

  async function notifyAdminLogin(message, userId) {
    const policy = (await publicAccountAlertPolicy(userId));
    await signalSend(message, [], policy === 'hybrid' ? SIGNAL_HYBRID_GROUP : null);
    const discordUrl = (await getDiscordWebhook());
    if (discordUrl) await discordSend(message, discordUrl);
  }

  async function notifyAdminExempt(message, deviceId = null) {
    const policy = (await deviceOwnerAlertPolicy(deviceId));
    if (policy === 'hybrid') { log('info', 'Admin alert suppressed (hybrid account)', { deviceId }); return; }
    await signalSend(message, [], null);
    const discordUrl = (await getDiscordWebhook());
    if (discordUrl) await discordSend(message, discordUrl);
  }

  async function notifySecurityAlert(message, deviceId = null, opts = {}) {
    let group = SIGNAL_SECURITY_GROUP;
    if (opts.hybridTarget && deviceId) {
      const { suppress, group: hybridGroup } = (await deviceAlertTarget(deviceId));
      if (suppress && hybridGroup) group = hybridGroup;
    }
    await signalSend(message, [], group);
    const discordUrl = (await getDiscordWebhook());
    if (discordUrl) await discordSend(message, discordUrl);
  }

  // ── Web Push / FCM ──────────────────────────────────────────────────────────
  async function sendFcmToUser(userId, title, body, url = '/') {
    if (!state.fcmMessaging) return;
    let tokens;
    try { tokens = (await db.prepare('SELECT token FROM fcm_tokens WHERE user_id=?').all(userId)).map(r => r.token); }
    catch { return; }
    if (!tokens.length) return;
    try {
      const resp = await state.fcmMessaging.sendEachForMulticast({
        tokens,
        notification: { title, body },
        data: { url: String(url) },
        android: { priority: 'high', notification: { channelId: 'sentinel_push' } },
      });
      for (let i = 0; i < resp.responses.length; i++) {
        const r = resp.responses[i];
        if (r.success) continue;
        const code = (r.error && (r.error.code || (r.error.errorInfo && r.error.errorInfo.code))) || '';
        if (code.includes('registration-token-not-registered') ||
            code.includes('invalid-registration-token') ||
            code.includes('invalid-argument')) {
          try { (await db.prepare('DELETE FROM fcm_tokens WHERE token=?').run(tokens[i])); } catch {}
        }
      }
    } catch (e) { log('warn', 'sendFcmToUser failed', { err: e.message }); }
  }

  async function sendWebPushToUser(userId, title, body, url = '/') {
    sendFcmToUser(userId, title, body, url).catch(() => {});
    const subs = (await db.prepare('SELECT * FROM push_subscriptions WHERE user_id=?').all(userId));
    for (const sub of subs) {
      try {
        await webPush.sendNotification(
          { endpoint: sub.endpoint, keys: { p256dh: sub.p256dh, auth: sub.auth } },
          JSON.stringify({ title, body, url })
        );
      } catch(e) {
        if (e.statusCode === 410 || e.statusCode === 404) {
          (await db.prepare('DELETE FROM push_subscriptions WHERE id=?').run(sub.id));
        }
      }
    }
  }

  async function sendWebPushToAdmins(title, body, url = '/') {
    const admins = (await db.prepare("SELECT id FROM users WHERE account_type='admin'").all());
    for (const a of admins) await sendWebPushToUser(a.id, title, body, url);
  }

  // ── Admin push-notification preferences ─────────────────────────────────────
  const NOTIFY_EVENT_TYPES = ['enrollment', 'offline', 'geofence', 'theft', 'support', 'tracker'];
  async function getNotifyPrefs() {
    try {
      const row = (await db.prepare("SELECT value FROM settings WHERE key='notify_prefs'").get());
      const saved = row ? JSON.parse(row.value) : {};
      const out = { login: true };
      for (const t of NOTIFY_EVENT_TYPES) out[t] = saved[t] !== false;
      return out;
    } catch {
      return { login: true, enrollment: true, offline: true, geofence: true, theft: true, support: true };
    }
  }
  async function saveNotifyPrefs(prefs) {
    const clean = {};
    for (const t of NOTIFY_EVENT_TYPES) clean[t] = !(prefs[t] === false || prefs[t] === 'false');
    (await db.prepare("INSERT INTO settings (key,value) VALUES ('notify_prefs',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(JSON.stringify(clean)));
  }
  async function notifyPush(type, title, body, url = '/') {
    try {
      if (type !== 'login' && (await getNotifyPrefs())[type] === false) return;
      sendWebPushToAdmins(title, body, url).catch(() => {});
    } catch (e) { log('warn', 'notifyPush failed', { err: e.message, type }); }
  }

  // ── User alert center ───────────────────────────────────────────────────────
  async function persistUserAlert(userId, category, message, deviceId = null) {
    try {
      (await db.prepare(
        'INSERT INTO user_alerts (user_id, device_id, category, message, created_at) VALUES (?,?,?,?,?)'
      ).run(String(userId), deviceId || null, category, String(message || '').slice(0, 4000), Date.now()));
    } catch (e) { log('warn', 'persistUserAlert failed', { userId, error: e.message }); }
  }

  // ── Email ───────────────────────────────────────────────────────────────────
  const emailTemplates = require('../templates/email');

  async function getSmtpConfig() {
    try {
      const row = (await db.prepare("SELECT value FROM settings WHERE key='smtp_config'").get());
      return row ? JSON.parse(decryptText(row.value) || '{}') : {};
    } catch { return {}; }
  }

  async function sendEmail(to, subject, html) {
    const cfg = (await getSmtpConfig());
    if (!cfg.host) { log('warn', 'SMTP not configured — email not sent', { to }); return false; }
    try {
      const nodemailer = require('nodemailer');
      const transport = nodemailer.createTransport({
        host:   cfg.host,
        port:   Number(cfg.port) || 587,
        secure: cfg.secure === true || cfg.port == 465,
        auth:   cfg.user ? { user: cfg.user, pass: cfg.pass } : undefined,
      });
      await transport.sendMail({
        from: `"${cfg.from_name || 'SentinelMDM'}" <${cfg.from_email || cfg.user}>`,
        to, subject, html,
      });
      log('info', 'Email sent', { to, subject });
      return true;
    } catch(e) {
      log('error', 'Email send failed', { to, err: e.message });
      return false;
    }
  }

  async function sendUserAlertEmail(userId, message) {
    try {
      const prefs = (await getUserNotifPrefs(userId));
      if (!prefs.email_alerts) return;
      const row = (await db.prepare('SELECT email FROM users WHERE id=?').get(userId));
      const email = (row && decryptText(row.email)) || '';
      if (!email) return;
      const title = String(message || '').split('\n')[0].slice(0, 120) || 'New alert';
      await sendEmail(email, `SentinelMDM alert — ${title}`, emailTemplates.renderAlertEmailHtml(title, message));
    } catch (e) { log('warn', 'sendUserAlertEmail error', { userId, error: e.message }); }
  }

  async function sendAiReportEmail(userId, kind, title, deviceName, bodyText) {
    try {
      const prefs = (await getUserNotifPrefs(userId));
      if (prefs.ai_reports?.[kind] !== true) return false;
      const row = (await db.prepare('SELECT email FROM users WHERE id=?').get(userId));
      const email = (row && decryptText(row.email)) || '';
      if (!email) return false;
      return await sendEmail(email, `SentinelMDM — ${title}`, emailTemplates.renderAiReportEmailHtml(title, deviceName, bodyText));
    } catch (e) { log('warn', 'sendAiReportEmail error', { userId, kind, error: e.message }); return false; }
  }

  async function sendLoginNotificationEmail(userId, username, ip) {
    try {
      const row = (await db.prepare('SELECT email FROM users WHERE id=?').get(userId));
      const email = (row && decryptText(row.email)) || '';
      if (!email) { log('warn', 'Login email skipped — no email on user', { userId }); return; }
      await sendEmail(email, 'New sign-in to your SentinelMDM account',
        emailTemplates.renderLoginEmailHtml(username || 'your account', ip || 'unknown', new Date().toUTCString()));
    } catch (e) { log('warn', 'sendLoginNotificationEmail error', { userId, error: e.message }); }
  }

  async function sendEmailVerifyCode(email, code) {
    if (!email) return false;
    return sendEmail(email, `Your SentinelMDM verification code: ${code}`, emailTemplates.renderEmailVerifyHtml(code));
  }

  async function sendApprovalEmail(user) {
    const tpl = { subject: emailTemplates.DEFAULT_APPROVAL_SUBJECT, body: emailTemplates.DEFAULT_APPROVAL_TEMPLATE };
    try {
      const row = (await db.prepare("SELECT value FROM settings WHERE key='email_tpl_approval'").get());
      if (row) { const p = JSON.parse(decryptText(row.value) || '{}'); if (p.subject) tpl.subject = p.subject; if (p.body) tpl.body = p.body; }
    } catch {}
    const email = decryptText(user.email) || '';
    if (!email) { log('warn', 'Approval email skipped — no email on user', { userId: user.id }); return; }
    const html = tpl.body
      .replace(/\{\{username\}\}/g, emailTemplates.esc(decryptText(user.username) || user.username || 'there'))
      .replace(/\{\{email\}\}/g, emailTemplates.esc(email))
      .replace(/\{\{register_url\}\}/g, `${emailTemplates.TRACKER_REGISTER_URL}?em=${encodeURIComponent(email)}`)
      .replace(/\{\{login_url\}\}/g, emailTemplates.TRACKER_LOGIN_URL)
      .replace(/\{\{setup_url\}\}/g, emailTemplates.SETUP_GUIDE_URL)
      .replace(/\{\{tracker_domain\}\}/g, emailTemplates.TRACKER_DOMAIN);
    await sendEmail(email, tpl.subject, html);
  }

  async function sendPurchaseEmail(email, name) {
    if (!email) { log('warn', 'Purchase email skipped — no email'); return false; }
    const tpl = { subject: emailTemplates.DEFAULT_PURCHASE_SUBJECT, body: emailTemplates.DEFAULT_PURCHASE_TEMPLATE };
    try {
      const row = (await db.prepare("SELECT value FROM settings WHERE key='email_tpl_purchase'").get());
      if (row) { const p = JSON.parse(decryptText(row.value) || '{}'); if (p.subject) tpl.subject = p.subject; if (p.body) tpl.body = p.body; }
    } catch {}
    const registerUrl = `${emailTemplates.TRACKER_REGISTER_URL}?em=${encodeURIComponent(email)}`;
    const html = tpl.body
      .replace(/\{\{name\}\}/g, emailTemplates.esc(name || String(email).split('@')[0] || 'there'))
      .replace(/\{\{email\}\}/g, emailTemplates.esc(email))
      .replace(/\{\{register_url\}\}/g, registerUrl)
      .replace(/\{\{tracker_domain\}\}/g, emailTemplates.TRACKER_DOMAIN);
    return sendEmail(email, tpl.subject, html);
  }

  // ── Per-user dispatcher ─────────────────────────────────────────────────────
  async function notifyUser(userId, message, opts = {}) {
    if (!userId) return;
    try {
      const prefs = (await getUserNotifPrefs(userId));
      if (!opts.force && !userWantsAlert(prefs, opts.category)) return;
      persistUserAlert(userId, opts.category || null, message, opts.deviceId);
      if (prefs.discord_webhook)             await discordSend(message, prefs.discord_webhook);
      if ((prefs.email_alerts || opts.force) && !opts.skipEmail) await sendUserAlertEmail(userId, message);
      if (prefs.push_alerts !== false || opts.force) {
        const lines = String(message || '').split('\n');
        const title = (lines[0] || 'SentinelMDM').slice(0, 80);
        const body  = (lines.slice(1).join('  ').trim() || title).slice(0, 180);
        await sendWebPushToUser(userId, title, body, '/');
      }
    } catch (e) { console.error('notifyUser error:', e.message); }
  }

  // ── Node-RED alert ──────────────────────────────────────────────────────────
  const { NODERED_ALERT_URL, NODERED_ALERT_KEY } = config;
  function notifyAdminLoginNodeRed(event, username, req) {
    if (!NODERED_ALERT_KEY) return;
    const ip = _reqClientIp(req) || 'unknown';
    fetch(NODERED_ALERT_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'X-Sentinel-Key': NODERED_ALERT_KEY },
      body: JSON.stringify({ event, username: username || '(unknown)', ip, time: new Date().toLocaleString() }),
      signal: AbortSignal.timeout(5000),
    }).catch(() => {});
  }

  // ── Return all exported functions ───────────────────────────────────────────
  return {
    ZK_EVENT_LABELS,
    ZK_USER_NOTIFY_EVENTS,
    _canSendUserNotif,
    USER_NOTIFY_COMMANDS,
    USER_ALERT_CATEGORIES,
    AI_REPORT_CATEGORIES,
    userWantsAlert,
    isDiscordWebhookUrl,
    signalSend,
    discordSend,
    getDiscordWebhook,
    getUserNotifPrefs,
    notifyAdmin,
    userOnHybridPlan,
    publicAccountAlertPolicy,
    deviceOwnerAlertPolicy,
    deviceAlertTarget,
    notifyAdminForDevice,
    notifyAdminForUser,
    notifyAdminLogin,
    notifyAdminExempt,
    notifySecurityAlert,
    sendFcmToUser,
    sendWebPushToUser,
    sendWebPushToAdmins,
    getNotifyPrefs,
    saveNotifyPrefs,
    notifyPush,
    persistUserAlert,
    getSmtpConfig,
    sendEmail,
    sendUserAlertEmail,
    sendAiReportEmail,
    sendLoginNotificationEmail,
    sendEmailVerifyCode,
    sendApprovalEmail,
    sendPurchaseEmail,
    notifyUser,
    notifyAdminLoginNodeRed,
  };
};
