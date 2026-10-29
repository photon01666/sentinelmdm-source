// state.js — Mutable shared state used across modules.
// Getters/setters allow modules to read/write without circular requires.
// server.js populates these after initialization.

const crypto = require('crypto');

// ── At-rest encryption ────────────────────────────────────────────────────────
let ENC_KEY = null;
let serverUnlocked = false;
let _unlockKeyPair = null;
const ENC_MAGIC = Buffer.from('ENC:');

// Generate ephemeral RSA-OAEP key pair (fresh each startup, never persisted).
(async () => {
  try {
    _unlockKeyPair = await crypto.webcrypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
      true, ['encrypt', 'decrypt']
    );
  } catch (e) { console.warn('RSA unlock key gen failed:', e.message); }
})();

// ── Device socket registry ────────────────────────────────────────────────────
const connectedSockets = new Map();   // deviceId -> socket
const encryptedDevices = new Set();
const deviceStatus = new Map();       // deviceId -> status object

// ── Offline grace timers ──────────────────────────────────────────────────────
const offlineGraceTimers = new Map();
const DEVICE_OFFLINE_GRACE_MS = 5 * 60 * 1000;

// ── Theft mode alert timers ──────────────────────────────────────────────────
const theftModeAlertTimers = new Map();

// ── Surveillance active state ────────────────────────────────────────────────
const SURVEIL_MAX_MS   = 10 * 60 * 1000;
// SURVEIL_ALERT_MS (60 * 1000) retired 2026-08-21 — the recurring 60s "still being monitored"
// pulse was removed from the live-monitoring loop. Kept out of exports; do not reintroduce
// without a product reason (alert fatigue was the driver).

// ── VAPID / FCM ──────────────────────────────────────────────────────────────
let vapidPublicKey = '';
let fcmMessaging = null;

// ── App-layer encryption key ──────────────────────────────────────────────────
let serverEncPrivKey = null;

// ── Prelogin seed cache ──────────────────────────────────────────────────────
let _preloginSeedPromise = null;

module.exports = {
  // ENC_KEY
  get ENC_KEY() { return ENC_KEY; },
  set ENC_KEY(v) { ENC_KEY = v; },
  get serverUnlocked() { return serverUnlocked; },
  set serverUnlocked(v) { serverUnlocked = v; },
  get unlockKeyPair() { return _unlockKeyPair; },
  ENC_MAGIC,
  // Device sockets
  connectedSockets,
  encryptedDevices,
  deviceStatus,
  // Offline grace
  offlineGraceTimers,
  DEVICE_OFFLINE_GRACE_MS,
  // Theft mode
  theftModeAlertTimers,
  // Surveillance
  SURVEIL_MAX_MS,
  // (SURVEIL_ALERT_MS export removed 2026-08-21 with the recurring surveil pulse)
  // VAPID / FCM
  get vapidPublicKey() { return vapidPublicKey; },
  set vapidPublicKey(v) { vapidPublicKey = v; },
  get fcmMessaging() { return fcmMessaging; },
  set fcmMessaging(v) { fcmMessaging = v; },
  // App-layer encryption
  get serverEncPrivKey() { return serverEncPrivKey; },
  set serverEncPrivKey(v) { serverEncPrivKey = v; },
  // Prelogin
  get preloginSeedPromise() { return _preloginSeedPromise; },
  set preloginSeedPromise(v) { _preloginSeedPromise = v; },
};
