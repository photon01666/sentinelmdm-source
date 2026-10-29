// middleware/security.js — CSP, security headers, rate limiters.
// Factory pattern: initialized with dependencies.

const crypto = require('crypto');

module.exports = function createSecurityMiddleware({ db, kv, redisClient, redisEnabled, log }) {
  // ── Security response headers ──────────────────────────────────────────────
  const CSP_SCRIPT_HOSTS = "https://maps.googleapis.com https://maps.gstatic.com https://www.google.com https://www.gstatic.com";
  const CSP_NONSCRIPT = [
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "img-src 'self' data: blob: https:",
    "font-src 'self' data: https://fonts.gstatic.com",
    "media-src 'self' blob:",
    "connect-src 'self' wss: https://maps.googleapis.com https://maps.gstatic.com",
    "worker-src 'self' blob:",
    "child-src 'self' blob:",
    "frame-src 'self' https://www.google.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "object-src 'none'",
    "report-uri /api/csp-report",
    "report-to csp-endpoint"
  ];
  const SECURITY_CSP = [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline' 'unsafe-eval' ${CSP_SCRIPT_HOSTS}`,
    ...CSP_NONSCRIPT
  ].join('; ');

  function cspWithNonce(nonce) {
    return [
      "default-src 'self'",
      `script-src 'self' 'unsafe-inline' ${CSP_SCRIPT_HOSTS}`,
      `script-src-elem 'self' 'nonce-${nonce}' ${CSP_SCRIPT_HOSTS}`,
      "script-src-attr 'unsafe-inline'",
      ...CSP_NONSCRIPT
    ].join('; ');
  }

  const AUTH_PAGE_HTML = {};
  const fs = require('fs');
  const path = require('path');
  for (const _f of ['login.html', 'register.html', 'unlock.html']) {
    try { AUTH_PAGE_HTML[_f] = fs.readFileSync(path.join(__dirname, '..', 'public', _f), 'utf8'); } catch {}
  }

  function sendAuthPage(res, file) {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.setHeader('Content-Security-Policy', cspWithNonce(nonce));
    res.type('html').send((AUTH_PAGE_HTML[file] || '').replaceAll('__CSP_NONCE__', nonce));
  }

  function securityHeadersMiddleware(req, res, next) {
    res.setHeader('Content-Security-Policy', SECURITY_CSP);
    res.setHeader('Reporting-Endpoints', 'csp-endpoint="/api/csp-report"');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000');
    res.setHeader('X-Frame-Options', 'DENY');
    next();
  }

  // ── Rate limiters ──────────────────────────────────────────────────────────
  function makeRateLimit(max, windowMs, name, keyFn) {
    const windowSec = Math.max(1, Math.ceil(windowMs / 1000));
    const prefix    = `rl:${name || 'unnamed'}:`;
    const memHits   = new Map();
    setInterval(() => memHits.clear(), windowMs).unref();
    return async (req, res, next) => {
      const ip = keyFn ? keyFn(req)
        : (req.headers['cf-connecting-ip'] || req.ip || req.socket?.remoteAddress || 'unknown');
      let n;
      try {
        n = await kv.incrWindow(prefix + ip, windowSec);
      } catch {
        n = (memHits.get(ip) || 0) + 1; memHits.set(ip, n);
      }
      if (n > max) return res.status(429).json({ error: 'Too many attempts — try again later' });
      next();
    };
  }

  const CHAT_RL_LUA = `
local now = tonumber(ARGV[1])
local win = tonumber(ARGV[2])
local banttl = redis.call('PTTL', KEYS[2])
if banttl and banttl > 0 then return {1, banttl} end
redis.call('ZREMRANGEBYSCORE', KEYS[1], 0, now - win)
redis.call('ZADD', KEYS[1], now, ARGV[6])
local count = redis.call('ZCARD', KEYS[1])
redis.call('PEXPIRE', KEYS[1], win)
if count >= tonumber(ARGV[4]) then
  redis.call('SET', KEYS[2], '1', 'PX', tonumber(ARGV[5]))
  redis.call('DEL', KEYS[1])
  return {2, tonumber(ARGV[5])}
end
if count > tonumber(ARGV[3]) then return {3, win} end
return {0, 0}`;

  function makeChatRateLimit({ soft = 5, hard = 10, windowMs = 30 * 1000, banMs = 60 * 60 * 1000, name = 'chat' } = {}) {
    const hits = new Map();
    const bans = new Map();
    setInterval(() => {
      const now = Date.now();
      for (const [ip, ts] of hits) { const keep = ts.filter(t => now - t < windowMs); keep.length ? hits.set(ip, keep) : hits.delete(ip); }
      for (const [ip, until] of bans) if (now >= until) bans.delete(ip);
    }, windowMs).unref();
    function memEval(ip) {
      const now = Date.now();
      const banUntil = bans.get(ip);
      if (banUntil && now < banUntil) return [1, banUntil - now];
      const ts = (hits.get(ip) || []).filter(t => now - t < windowMs);
      ts.push(now); hits.set(ip, ts);
      if (ts.length >= hard) { bans.set(ip, now + banMs); hits.delete(ip); return [2, banMs]; }
      if (ts.length > soft) return [3, windowMs];
      return [0, 0];
    }
    return async (req, res, next) => {
      const ip = req.headers['cf-connecting-ip'] || req.ip || req.socket?.remoteAddress || 'unknown';
      let code = 0, retryMs = 0;
      try {
        if (redisEnabled && redisClient) {
          const member = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
          const r = await redisClient.eval(CHAT_RL_LUA, 2, `${name}:win:${ip}`, `${name}:ban:${ip}`,
            Date.now(), windowMs, soft, hard, banMs, member);
          code = Number(r[0]); retryMs = Number(r[1]);
        } else {
          [code, retryMs] = memEval(ip);
        }
      } catch {
        [code, retryMs] = memEval(ip);
      }
      if (code === 1 || code === 2) {
        const mins = Math.ceil(retryMs / 60000);
        return res.status(429).json({ banned: true, retry_after_ms: retryMs,
          error: code === 2 ? `Too many messages — you're temporarily blocked for 1 hour.`
                            : `Too many messages — you're temporarily blocked. Try again in ${mins} minute${mins === 1 ? '' : 's'}.` });
      }
      if (code === 3)
        return res.status(429).json({ retry_after_ms: retryMs, error: 'Slow down — too many messages. Please wait a few seconds.' });
      next();
    };
  }

  return {
    SECURITY_CSP,
    CSP_NONSCRIPT,
    CSP_SCRIPT_HOSTS,
    cspWithNonce,
    sendAuthPage,
    securityHeadersMiddleware,
    makeRateLimit,
    makeChatRateLimit,
    AUTH_PAGE_HTML,
  };
};
