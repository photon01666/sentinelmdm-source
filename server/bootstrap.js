// bootstrap.js — Initializes all services with their dependencies.
// Called once at server startup. Returns all service instances.

const config  = require('./config');
const state   = require('./state');
const crypto  = require('./crypto');

module.exports = function bootstrap({ db, kv, io, redisClient, redisEnabled, log, deviceOwnerInfo, opencodeApiKey }) {
  // ── Initialize commerce service first (notification needs reqClientIp) ──────
  const commerce = require('./services/commerce')({
    db, log, decryptText: crypto.decryptText, kv,
  });

  // ── Initialize notification service ──────────────────────────────────────────
  const notification = require('./services/notification')({
    db, log, decryptText: crypto.decryptText, kv, state, config,
    reqClientIp: commerce.reqClientIp,
  });

  // ── Initialize security middleware ───────────────────────────────────────────
  const security = require('./middleware/security')({
    db, kv, redisClient, redisEnabled, log,
  });

  // ── Initialize surveillance service ─────────────────────────────────────────
  const surveillance = require('./services/surveillance')({
    db, log, decryptText: crypto.decryptText, kv, state, config, notification,
  });

  // ── Initialize device manager ───────────────────────────────────────────────
  const deviceManager = require('./services/device-manager')({
    db, log, decryptText: crypto.decryptText, kv, state,
    config: { ...config, redisEnabled, io },
    notification,
  });

  // ── Initialize per-device settings CRUD (WiFi auto-join / unlock capture / VPN — raw db.prepare)
  const deviceSettings = require('./services/device-settings')({ db });

  return {
    config,
    state,
    crypto,
    notification,
    commerce,
    security,
    surveillance,
    deviceManager,
    deviceSettings,
  };
};
