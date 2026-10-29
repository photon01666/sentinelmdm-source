// services/commerce.js — Commerce helpers, web analytics, policy acceptances.
// Factory pattern: initialized with dependencies.

module.exports = function createCommerceService({ db, log, decryptText, kv }) {
  const DAY_MS = 24 * 60 * 60 * 1000;
  const TRIAL_DAYS = { digital_mdm_7: 30, hardware_software_30: 30, os_flash_7: 30 };

  const crypto = require('crypto');
  const PUBLIC_SITE_URL = process.env.PUBLIC_SITE_URL || 'http://localhost:3000';

  function reqClientIp(req) {
    return (req.headers?.['cf-connecting-ip'] || '').trim()
      || ((req.headers?.['x-forwarded-for'] || '').split(',')[0].trim())
      || req.socket?.remoteAddress || req.ip || null;
  }

  function daysRemaining(deadlineMs) {
    if (!deadlineMs) return null;
    return Math.max(0, Math.ceil((deadlineMs - Date.now()) / DAY_MS));
  }

  // ── Canonical policy texts ───────────────────────────────────────────────────
  const POLICY_TEXTS = {
    msa: { version: '1', text:
      `Master Service Agreement v1, ${PUBLIC_SITE_URL}/legal/msa — `
      + 'I have read and agree to the Master Service Agreement, the Terms of Service, and the Privacy Policy.' },
    terms_of_service: { version: '2', text:
      `Terms of Service v2, ${PUBLIC_SITE_URL}/legal/terms — `
      + 'I have read and agree to the Terms of Service.' },
    physical_damage_voids_return: { version: '1', text:
      'SentinelOS Terms of Service v1: Software trials are 30 days. Physical hardware may be returned '
      + 'within 14 days of delivery. Physical damage voids the hardware return. Encrypted data auto-purges '
      + 'on a 30-day TTL.' },
    zk_no_recovery: { version: '1', text:
      'I understand SentinelMDM cannot reset my password or recover my data. If I lose my password, all '
      + 'encrypted data is permanently lost — by me, by SentinelMDM, and by anyone else. (MSA v1 section 7.2)' },
    lawful_monitoring: { version: '1', text:
      'I own the devices I enroll or am authorized to manage them, and I am responsible for disclosing the '
      + 'monitoring and obtaining any consent required by law. (MSA v1 sections 4.2, 4.3 and 6.5)' },
  };

  async function recordTosAcceptance(req, { userId = null, orderId = null, email = null,
                                      policyKey, policyVersion, policyText = null }) {
    try {
      const sha = policyText
        ? crypto.createHash('sha256').update(String(policyText)).digest('hex') : null;
      (await db.prepare(`INSERT INTO tos_acceptances
        (user_id, order_id, email, policy_key, policy_version, policy_sha256, accepted_at, ip_address, user_agent)
        VALUES (?,?,?,?,?,?,?,?,?)`).run(
        userId, orderId, email, policyKey, policyVersion, sha,
        Date.now(), reqClientIp(req), String(req.headers['user-agent'] || '').slice(0, 400)));
      return true;
    } catch (e) { log('warn', 'recordTosAcceptance failed', { err: e.message }); return false; }
  }

  async function recordPolicyAcceptances(req, keys, { userId = null, orderId = null, email = null } = {}) {
    let written = 0;
    for (const key of (Array.isArray(keys) ? keys : [])) {
      const policy = POLICY_TEXTS[String(key)];
      if (!policy) { log('warn', 'unknown policy key at acceptance', { key: String(key).slice(0, 64) }); continue; }
      if (await recordTosAcceptance(req, {
        userId, orderId, email,
        policyKey: String(key), policyVersion: policy.version, policyText: policy.text,
      })) written++;
    }
    return written;
  }

  async function genLicenseKey() {
    const A = 'ABCDEFGHJKMNPQRSTVWXYZ0123456789';
    for (let attempt = 0; attempt < 6; attempt++) {
      const r = Array.from(crypto.randomBytes(16)).map(b => A[b % 32]).join('');
      const key = `SENT-${r.slice(0,4)}-${r.slice(4,8)}-${r.slice(8,12)}-${r.slice(12,16)}`;
      if (!(await db.prepare('SELECT 1 FROM entitlements WHERE license_key=?').get(key))) return key;
    }
    return 'SENT-' + crypto.randomUUID().replace(/-/g, '').slice(0, 16).toUpperCase();
  }

  // ── Web Analytics helpers ───────────────────────────────────────────────────
  function parseUA(ua) {
    if (!ua) return { browser: 'Unknown', os: 'Unknown', device: 'Desktop' };
    let browser = 'Other';
    if (/Edg\//.test(ua)) browser = 'Edge';
    else if (/Chrome/.test(ua)) browser = 'Chrome';
    else if (/Firefox/.test(ua)) browser = 'Firefox';
    else if (/Safari/.test(ua)) browser = 'Safari';
    let os = 'Other';
    if (/Windows/.test(ua)) os = 'Windows';
    else if (/Mac OS X/.test(ua)) os = 'macOS';
    else if (/Linux/.test(ua)) os = 'Linux';
    else if (/Android/.test(ua)) os = 'Android';
    else if (/iPhone|iPad/.test(ua)) os = 'iOS';
    let device = 'Desktop';
    if (/Mobile|Android|iPhone/.test(ua)) device = 'Mobile';
    else if (/iPad|Tablet/.test(ua)) device = 'Tablet';
    return { browser, os, device };
  }

  function getDailySalt() {
    return new Date().toISOString().slice(0, 10);
  }

  function classifyBotUA(ua) {
    if (!ua) return 'unknown';
    if (/bot|crawl|spider|slurp|mediapartners/i.test(ua)) return 'bot';
    if (/facebookexternalhit|Twitterbot|LinkedInBot|Discordbot|TelegramBot/i.test(ua)) return 'social';
    return 'human';
  }

  // rmaWindowState helper
  function rmaWindowState(order) {
    if (!order || order.order_type !== 'hardware') return { deadline: null, daysLeft: null, withinWindow: false };
    const delivered = order.delivered_at;
    if (!delivered) return { deadline: null, daysLeft: null, withinWindow: false };
    const deadline = delivered + 14 * DAY_MS;
    const daysLeft = daysRemaining(deadline);
    return { deadline, daysLeft, withinWindow: daysLeft !== null && daysLeft > 0 };
  }

  return {
    DAY_MS,
    TRIAL_DAYS,
    reqClientIp,
    daysRemaining,
    POLICY_TEXTS,
    recordTosAcceptance,
    recordPolicyAcceptances,
    genLicenseKey,
    parseUA,
    getDailySalt,
    classifyBotUA,
    rmaWindowState,
  };
};
