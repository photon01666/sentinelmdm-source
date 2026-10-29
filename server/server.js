const { EventEmitter } = require('events');

// Comma-separated environment list helper.
const csvEnv = (key) => (process.env[key] || '').split(',').map((v) => v.trim()).filter(Boolean);
const express    = require('express');
const session    = require('express-session');
const webPush    = require('web-push');
const SqliteStore = require('better-sqlite3-session-store')(session);
const speakeasy  = require('speakeasy');
const QRCode     = require('qrcode');
const bcrypt     = require('bcryptjs');
const http       = require('http');
const WebSocket  = require('ws');
const { Server } = require('socket.io');
const Database   = require('better-sqlite3');
const path       = require('path');
const fs         = require('fs');
const crypto = require('crypto');
const { randomUUID } = crypto;
const { detectAirline, getAirlineProfiles, getAirlineProfile, validateCredentials } = require('./airline-wifi-profiles');
// Redis layer for multi-replica coordination (Socket.IO adapter, sessions, tokens,
// caches, presence). When REDIS_URL is unset this is a no-op and everything falls
// back to single-instance in-process behaviour. See redis.js.
const { enabled: redisEnabled, redis: redisClient, pubClient, subClient, kv } = require('./redis');

// Role split for multi-replica: 'web' replicas serve traffic only; the single 'worker'
// replica runs the global cron/dispatch jobs (DB cleanup, integrity report, scheduled-command
// dispatcher) so they fire ONCE, not once-per-replica. Unset = standalone/single-instance =
// runs everything. Rule: run the jobs unless explicitly ROLE=web.
const ROLE = process.env.ROLE || 'standalone';
const IS_WORKER = ROLE !== 'web';

const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');
const uploadsDir   = path.join(__dirname, 'uploads');
const apkDir       = path.join(__dirname, 'apk');
fs.mkdirSync(uploadsDir, { recursive: true });
fs.mkdirSync(apkDir,     { recursive: true });

const { readSecret } = require('./helpers/read-secret')({ fs });
const { OPENCODE_FALLBACK_MODELS, opencodePrimaryKey, opencodeFallbackKey, opencodeApiKey } = require('./helpers/opencode-keys')({ readSecret });

// ── Cloudflare R2 object storage (for binary files: pulled files + stream recordings) ──
// Reuses Litestream's credentials. Falls back to local disk when not configured.
const R2_KEY    = readSecret('sentinel_litestream_key_id',     'LITESTREAM_ACCESS_KEY_ID');
const R2_SECRET = readSecret('sentinel_litestream_secret_key', 'LITESTREAM_SECRET_ACCESS_KEY');
const R2_BUCKET = 'sentinel-db';
const R2_ENDPOINT = process.env.R2_ENDPOINT || '';
const r2 = (R2_KEY && R2_SECRET) ? new S3Client({
  region: 'auto',
  endpoint: R2_ENDPOINT,
  credentials: { accessKeyId: R2_KEY, secretAccessKey: R2_SECRET },
}) : null;

async function r2Put(key, buf) {
  if (!r2) { fs.writeFileSync(path.join(__dirname, key.replace('/', path.sep)), buf); return; }
  await r2.send(new PutObjectCommand({ Bucket: R2_BUCKET, Key: key, Body: buf }));
}

async function r2Get(key) {
  if (!r2) {
    const p = path.join(__dirname, key.replace('/', path.sep));
    return fs.existsSync(p) ? fs.readFileSync(p) : null;
  }
  try {
    const resp = await r2.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: key }));
    const chunks = [];
    for await (const chunk of /** @type {any} */ (resp.Body)) chunks.push(Buffer.from(chunk));
    return Buffer.concat(chunks);
  } catch (e) {
    if (e.name === 'NoSuchKey' || e.$metadata?.httpStatusCode === 404) return null;
    throw e;
  }
}

async function r2Del(key) {
  if (!r2) { try { fs.unlinkSync(path.join(__dirname, key.replace('/', path.sep))); } catch {} return; }
  try { await r2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: key })); } catch {}
}

async function r2List(prefix) {
  if (!r2) return [];
  const keys = [];
  let token;
  do {
    const resp = await r2.send(new ListObjectsV2Command({
      Bucket: R2_BUCKET, Prefix: prefix, ContinuationToken: token,
    }));
    for (const obj of resp.Contents || []) keys.push(obj.Key);
    token = resp.IsTruncated ? resp.NextContinuationToken : undefined;
  } while (token);
  return keys;
}

const ADMIN_USER     = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS     = readSecret('sentinel_admin_pass', 'ADMIN_PASS');
const APK_UPDATE_PIN = readSecret('sentinel_apk_pin', 'APK_UPDATE_PIN');
if (!ADMIN_PASS) {
  console.error('FATAL: admin password not set — define Docker secret sentinel_admin_pass or env ADMIN_PASS');
  process.exit(1);
}
if (!APK_UPDATE_PIN) {
  console.warn('⚠  APK_UPDATE_PIN not set — update_app command will be disabled until configured');
}

// ── At-rest encryption (AES-256-GCM) ─────────────────────────────────────
// Key is NEVER derived automatically or stored. It must be entered via the
// /unlock web UI after each server start. Until unlocked, the server serves
// only the unlock page — no data is readable or writable.
let ENC_KEY      = null;
let serverUnlocked = false;
// Stamped into sessions at login, checked on every request. When the value changes
// all existing sessions are invalidated (force global re-login). The value is
// persisted in the settings table ('server_generation') so routine restarts reuse
// the same generation — already-authenticated users (WebUI + monitor APK WebViews)
// stay logged in. Bump the value (POST /api/admin/rotate-session-generation or
// direct DB edit) to force a global logout (e.g. after a breaking schema migration
// or security incident).
let serverGeneration = Date.now();

// Ephemeral RSA-OAEP key pair — generated fresh each startup, never persisted.
// Browser encrypts the unlock passphrase with the public key so Cloudflare
// (which terminates TLS) only ever sees RSA ciphertext, not the plaintext passphrase.
let _unlockKeyPair = null;
(async () => {
  try {
    _unlockKeyPair = await crypto.webcrypto.subtle.generateKey(
      { name: 'RSA-OAEP', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
      true, ['encrypt', 'decrypt']
    );
  } catch (e) { console.warn('RSA unlock key gen failed:', e.message); }
})();
const ENC_MAGIC  = Buffer.from('ENC:');

// storedSalt is a base64 string from the settings table (null for legacy deployments).
// iterations: 600k for new databases, 100k for existing (backward compat — can't change without re-encrypting all data).
const { deriveKey, tryUnlock, encryptText, decryptText, encryptBuffer, decryptBuffer, decryptDevice } = require('./helpers/encryption.js')({ ENC_MAGIC, getENC_KEY: () => ENC_KEY });

// TOTP secret — set TOTP_SECRET env var to persist across container restarts.
// If unset, a new secret is generated each startup; scan the QR at /setup-2fa.
let TOTP_SECRET = readSecret('sentinel_totp_secret', 'TOTP_SECRET');
if (!TOTP_SECRET) {
  TOTP_SECRET = speakeasy.generateSecret({ length: 20 }).base32;
  console.log('⚠  TOTP_SECRET not set — generated ephemeral secret: [REDACTED]');
  console.log('   Create a Docker secret named sentinel_totp_secret to persist it.');
  console.log('   Scan the QR code at /setup-2fa after first login step.');
}

// ── Notification system (Signal + Discord — admin-level and per-user) ────────
// Extracted to services/notification.js — initialized via bootstrap after db is created.
// All functions (notifyAdmin, notifyUser, signalSend, discordSend, etc.) are in that module.
// Constants (ZK_EVENT_LABELS, USER_ALERT_CATEGORIES, etc.) are exported from the module.

// ── Live-monitoring (surveillance) alerts + 10-minute hard cap ──────────────────
// Extracted to services/surveillance.js — initialized via bootstrap after db is created.
// Constants (SURVEIL_MAX_MS, SURVEIL_START_CMDS, etc.) and functions (surveilStart, surveilStop)
// are in that module and wired via svc.surveillance after bootstrap.

const CMD_META = {
  // notify:true = high-impact commands that warrant a Signal alert
  wipe_device:        { label: '☠️ Device Wipe Initiated',    notify: true  },
  lock_device:        { label: '🔒 Device Locked',            notify: true  },
  set_password:       { label: '🔑 Device Password Changed',  notify: true  },
  uninstall_agent:    { label: '🗑️ Agent Uninstalled',        notify: true  },
  show_message:       { label: '📣 Message Displayed',        notify: true  },
  update_app:         { label: '⬆️ APK Update Pushed',        notify: true  },
  update_agent:       { label: '⬆️ Agent Update Triggered',   notify: true  },
  install_apk:        { label: '📦 APK Sideloaded',           notify: true  },
  reboot_device:      { label: '🔄 Device Rebooted',          notify: true  },
  // Routine ops — no Signal notification
  take_photo:              { label: '📷 Photo Captured'               },
  start_photo_interval:    { label: '📷 Interval Photos Started'      },
  stop_photo_interval:     { label: '📷 Interval Photos Stopped'      },
  record_audio:            { label: '🎙️ Audio Recorded'               },
  take_screenshot:           { label: '🖥️ Screenshot Taken'            },
  start_screenshot_interval: { label: '🖥️ Interval Screenshots Started'},
  stop_screenshot_interval:  { label: '🖥️ Interval Screenshots Stopped'},
  get_location:       { label: '📍 Location Requested'      },
  start_live_track:   { label: '📡 Live Tracking Started'   },
  stop_live_track:    { label: '📡 Live Tracking Stopped'   },
  get_network:        { label: '📶 Network Info Requested'  },
  list_files:         { label: '📂 File Browser Opened'     },
  get_file:           { label: '📥 File Downloaded'         },
  delete_file:        { label: '🗑️ File Deleted'            },
  get_calls:          { label: '📞 Call Log Accessed'       },
  get_sms:            { label: '💬 SMS Messages Accessed'   },
  start_stream:       { label: '📹 Camera Stream Started'   },
  stop_stream:        { label: '📹 Camera Stream Stopped'   },
  start_audio_stream: { label: '🎙️ Audio Stream Started'    },
  stop_audio_stream:  { label: '🎙️ Audio Stream Stopped'    },
  start_screen_stream:{ label: '🖥️ Screen Stream Started'   },
  stop_screen_stream: { label: '🖥️ Screen Stream Stopped'   },
  find_phone:         { label: '🔔 Find Phone Activated'    },
  stop_find_phone:    { label: '🔔 Find Phone Stopped'      },
  get_monitors:       { label: '🖥️ Monitor List'             },
  uninstall_app:      { label: '🗑️ App Uninstalled'          },
  pull_apk:           { label: '📥 APK Pulled from Device'   },
  hide_app:           { label: '🙈 App Hidden from Launcher' },
  show_app:           { label: '👁️ App Shown in Launcher'    },
  lock_app_permissions: { label: '🔒 App Permissions Locked' },
  get_processes:      { label: '📋 Process List'            },
  kill_process:       { label: '💀 Process Killed'          },
  shell:              { label: '💻 Shell Command'           },
  reg_list:           { label: '🗂️ Registry Browsed'        },
  reg_write:          { label: '✏️ Registry Write'          },
  reg_delete_value:   { label: '🗑️ Registry Value Deleted'  },
  reg_delete_key:     { label: '🗑️ Registry Key Deleted'    },
  get_services:       { label: '⚙️ Services List'           },
  service_control:    { label: '⚙️ Service Controlled'      },
  get_autostarts:     { label: '🚀 Autostarts List'         },
  delete_autostart:   { label: '🗑️ Autostart Deleted'       },
  get_battery_stats:  { label: '🔋 Battery Stats Fetched'   },
  // Inject commands — silent, no notification
  inject_tap:         { label: '👆 Tap Injected'            },
  inject_swipe:       { label: '👆 Swipe Injected'          },
  inject_long_press:  { label: '👆 Long Press Injected'     },
  inject_text:        { label: '⌨️ Text Injected'           },
  inject_key:         { label: '⌨️ Key Injected'            },
  // Windows RA live streaming + remote input
  inject_mouse_down:  { label: '🖱️ Mouse Down'              },
  inject_mouse_up:    { label: '🖱️ Mouse Up'                },
  inject_mouse_click: { label: '🖱️ Mouse Click'             },
  inject_mouse_move:  { label: '🖱️ Mouse Move'              },
  inject_mouse_move_to:{ label: '🖱️ Mouse Move'              },
  inject_mouse_scroll:{ label: '🖱️ Mouse Scroll'            },
  inject_key_down:    { label: '⌨️ Key Down'                 },
  inject_key_up:      { label: '⌨️ Key Up'                   },
  inject_key_combo:   { label: '⌨️ Key Combo'                },
};

const { reqClientIp } = require('./helpers/req-client-ip')();
const { NODERED_ALERT_KEY, notifyAdminLoginNodeRed } = require('./helpers/nodered-alert')({ readSecret, reqClientIp });

// ── Geofence → Node-RED → HASS TTS webhook (spoken announcement on the Pixel 9a etc.) ──
// Same transport as notifyAdminLoginNodeRed (X-Sentinel-Key header, jellyfin_net DNS).
// Cooldown-gated 10 min per (device, fence, transition) — Redis-backed, shared across
// replicas — so boundary enter/exit flip-flop can't spam spoken TTS (the push/Signal
// gate above stays its own 15-min window).
const NODERED_GEOFENCE_URL = (process.env.NODERED_GEOFENCE_URL || 'http://node-red-signal-api_nodered-swarm:1880/sentinel-geofence-tts').trim();
const GEOFENCE_TTS_COOLDOWN_MS = 10 * 60 * 1000;
const _geofTtsFallback = new Map();   // per-process fallback if Redis is unavailable
// Optional allow-list for spoken geofence TTS. Comma-separated device IDs;
// empty disables the TTS flow. Other transitions still push/Signal normally.
const GEOFENCE_TTS_DEVICE_IDS = (process.env.GEOFENCE_TTS_DEVICE_IDS || '')
  .split(',').map((s) => s.trim()).filter(Boolean);
const { notifyGeofenceNodeRed } = require('./helpers/geofence-nodered')({ GEOFENCE_TTS_COOLDOWN_MS, GEOFENCE_TTS_DEVICE_IDS, NODERED_ALERT_KEY, NODERED_GEOFENCE_URL, _geofTtsFallback, kv });

// ── App-layer encryption, device emit, offline grace, theft mode ─────────────
// Extracted to services/device-manager.js — initialized via bootstrap after db is created.
// Functions (deviceEmit, emitToDevice, markOnline, markOffline, cancelOfflineGrace,
// scheduleOfflineGrace, updateDeviceOwner, startTheftModeAlerts, stopTheftModeAlerts)
// and constants (DEVICE_OFFLINE_GRACE_MS, SURVEIL_MAX_MS, etc.) are in that module
// and wired via svc.deviceManager after bootstrap.

const { log } = require('./helpers/log')();

// ── Client-side password pre-hashing ("prehash-v1") ─────────────────────────
// Closes the active-server-compromise gap: with plaintext logins, a tampered server.js could dump
// req.body.password and — combined with the stored zk_salt + zk_encrypted_priv_key — derive the KEK
// and unwrap the user's ZK private key. Clients now send
//   authHash = base64( PBKDF2-SHA256(password, utf8('sentinel-auth-v1|') ‖ auth_salt, 600k, 32B) )
// and the server stores bcrypt(authHash). The wire value is useless for the ZK KEK: the KEK is
// PBKDF2 over zk_salt, this is PBKDF2 over a DOMAIN-PREFIXED auth_salt, and PBKDF2 is one-way — so
// recovering the password from a captured authHash costs a full 600k-iteration offline attack per
// guess (vs zero cost for captured plaintext). auth_salt is per-user random (NOT email-derived, so
// username logins and email changes both work) and served pre-auth by /api/auth/prelogin.
// Legacy plaintext logins (old APKs / pre-migration rows) still verify and upgrade the row in place.
const AUTH_SCHEME_PREHASH = 'prehash-v1';
const AUTH_PREHASH_ITER   = 600000;
const AUTH_PREHASH_DOMAIN = 'sentinel-auth-v1|';
const { computeAuthPrehash, computeAuthPrehashSync, ensureAuthSalt, looksLikeAuthHash, looksLikeAuthSalt, newAuthSalt } = require('./helpers/auth-prehash')({ AUTH_PREHASH_DOMAIN, AUTH_PREHASH_ITER, crypto, getDb: () => db });
// Decoy-salt seed for /api/auth/prelogin (unknown identifiers) — stored in settings so all three
// replicas serve the SAME decoy for the same identifier (a per-process seed would let an attacker
// spot real accounts by their salt being stable across replicas while decoys varied).
let _preloginSeedPromise = null;

// ── Rate limiters + security headers ─────────────────────────────────────────
// Extracted to middleware/security.js — initialized via bootstrap after db is created.
// makeRateLimit, makeChatRateLimit, SECURITY_CSP, cspWithNonce, sendAuthPage,
// securityHeadersMiddleware are in that module and wired via svc.security after bootstrap.
// loginRateLimit, totpRateLimit are created from makeRateLimit in the security middleware.

const app    = express();
app.set('trust proxy', 1);

// ── Security response headers (defense-in-depth; pentest-tools low-sev findings 2026-06-29) ──
// Hide the framework banner (X-Powered-By info disclosure) + set standard hardening headers on
// EVERY response. CSP is permissive on script/style (app uses inline handlers + Bootstrap / Google
// Maps CDNs + blob:/data: ZK media) but locks down the high-value vectors (frame-ancestors,
// object-src, base-uri). Tune the allow-lists here if a future CDN is added.
//
// connect-src (tightened 2026-07-07, XSS defense-in-depth): was `'self' https: wss:`, which let
// any injected/XSS script exfiltrate stolen data to ANY https host via fetch/XHR/beacon. Every
// app data-plane call is same-origin (verified: zero external fetch() in public/), so 'self'
// covers all API + socket.io polling; the ONLY legitimate cross-origin connect consumer is the
// Google Maps JS (device-location maps). `wss:` is kept broad so the critical live Socket.IO
// websocket can't break (it connects same-origin, but 'self'-covers-wss is browser-version-
// dependent and this can't be interactively tested against the WebView). A `report-uri` catches
// anything the tightening blocks in the wild — see POST /api/csp-report.
//
// (2026-07-07) 'unsafe-inline' for <script> ELEMENTS is now DEFEATED on the dashboard document via a
// per-request nonce (cspWithNonce() below): an XSS-injected <script> can't know the nonce, so it
// won't execute — while the ~418 legacy inline on*= handlers keep working via script-src-attr. This
// is the realistic realization of the "nonce endgame": scoped to every first-party HTML page — the
// dashboard ('/', '/chat', '/admin', '/admin/subusers') AND the pre-auth login/register/unlock pages
// (round 2, 2026-07-07, also dropped 'unsafe-eval' from these pages). Remaining follow-up (defense-in-
// depth, not urgent — the output-encoding fix already closed the actual bug): scope wss: to the origin,
// and eventually convert the on*= handlers to addEventListener so script-src-attr can also drop.
app.disable('x-powered-by');
const CSP_SCRIPT_HOSTS = "https://maps.googleapis.com https://maps.gstatic.com https://www.google.com https://www.gstatic.com https://js.stripe.com";
// Every CSP directive EXCEPT the script-src* family — shared by the static header and the nonce'd
// first-party header so the two can never drift on non-script policy.
const CSP_NONSCRIPT = [
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "img-src 'self' data: blob: https:",
  "font-src 'self' data: https://fonts.gstatic.com",
  "media-src 'self' blob:",
  "connect-src 'self' wss: https://maps.googleapis.com https://maps.gstatic.com https://places.googleapis.com https://api.stripe.com https://q.stripe.com",
  "worker-src 'self' blob:",
  "child-src 'self' blob:",
  "frame-src 'self' https://www.google.com https://js.stripe.com",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "object-src 'none'",
  // report-uri is deprecated in CSP3 but still the ONLY reporting mechanism Firefox supports;
  // report-to is the CSP3 replacement (Chromium), paired with the Reporting-Endpoints response
  // header set in the middleware below. Keep BOTH so violations are reported on every browser.
  "report-uri /api/csp-report",
  "report-to csp-endpoint"
];
// Static CSP applied to EVERY response by the middleware below (byte-identical to the pre-2026-07-07
// string). 'unsafe-eval' is retained HERE so static-served pages that may need it (e.g. the
// flash.html web flasher) keep working; our first-party HTML pages OVERRIDE this with cspWithNonce().
const SECURITY_CSP = [
  "default-src 'self'",
  `script-src 'self' 'unsafe-inline' 'unsafe-eval' ${CSP_SCRIPT_HOSTS}`,
  ...CSP_NONSCRIPT
].join('; ');
const { cspWithNonce } = require('./helpers/csp-with-nonce')({ CSP_NONSCRIPT, CSP_SCRIPT_HOSTS });
// Pre-auth HTML pages (login/register/unlock) get the SAME per-request nonce as the dashboard. Read
// once at startup (they carry no other server-side placeholders); being pre-auth they're
// curl-verifiable. ⚠️ A new inline <script> in any of them MUST carry nonce="__CSP_NONCE__" (same
// rule as index.html) or it will be CSP-blocked on modern browsers.
const AUTH_PAGE_HTML = {};
for (const _f of ['login.html', 'register.html', 'unlock.html']) {
  try { AUTH_PAGE_HTML[_f] = fs.readFileSync(path.join(__dirname, 'public', _f), 'utf8'); } catch {}
}
const { sendAuthPage } = require('./helpers/send-auth-page')({ AUTH_PAGE_HTML, cspWithNonce, crypto });
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', SECURITY_CSP);
  // Named endpoint for the CSP `report-to csp-endpoint` directive (CSP3 Reporting API). Set here on
  // every response so it also covers the dashboard/auth pages that later override CSP via cspWithNonce().
  res.setHeader('Reporting-Endpoints', 'csp-endpoint="/api/csp-report"');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});
const server = http.createServer(app);
const SERVER_ORIGIN = process.env.SERVER_ORIGIN || 'http://localhost:3000';
const PUBLIC_SITE_URL = process.env.PUBLIC_SITE_URL || SERVER_ORIGIN;
const { getSupportPresence, setSupportPresence, cors } = require('./helpers/support-presence')();
const io     = new Server(server, {
  cors: { origin: SERVER_ORIGIN },
  // Polling-first is mandatory: it handles Cloudflare proxies correctly and pins to a
  // single replica via Traefik's sticky cookie before upgrading to WS. Websocket-first
  // churns/hangs through Cloudflare across the 3-replica HA tier (see docs/ARCHITECTURE.md invariant).
  transports: ['polling', 'websocket'],
  maxHttpBufferSize: 400 * 1024 * 1024,  // 400 MB — allow pulling large APKs
  // 3 s ping keeps the control socket warm on hostile guest APs that drop idle
  // connections in <10 s. The old 10 s lost the race: an idle control channel got cut
  // every few sec (handshake completes, then TCP dropped), while a live audio stream —
  // continuous traffic on the SAME socket — never dropped (memory control-channel-flap-
  // hostile-guest-wifi). Tiny packet; well within Cloudflare's 100 s idle timeout. If even
  // 3 s still flaps, the app-ping isn't the effective keepalive → agent xray tcpKeepAlive.
  pingInterval: 3000,
  pingTimeout:  20000,  // 20 s — must exceed pingInterval; allows slow CF round-trips
  destroyUpgrade: true,
});

// ── Multi-replica Socket.IO adapter ─────────────────────────────────────────
// With REDIS_URL set, the Redis adapter lets a room emit (io.to(...)) reach a
// socket connected to ANY replica. Per-device monitor rooms (monitor:<id>) and
// the global 'monitors' room therefore fan out across the whole swarm.
if (redisEnabled) {
  const { createAdapter } = require('@socket.io/redis-adapter');
  io.adapter(createAdapter(pubClient, subClient));
  require('./helpers/redis-adapter-rearm')({ io, subClient, log });
  // Cross-replica device delivery: a device's encrypted session key (socket.encKey)
  // lives only on the replica holding its socket, so encryption MUST happen there.
  // emitToDevice() tries the local socket first; if the device is on another replica
  // it broadcasts this server-to-server message and the holder runs deviceEmit() locally.
  io.on('device-emit', ({ deviceId, event, data }) => {
    const local = connectedSockets.get(deviceId);
    if (local) deviceEmit(local, event, data);
  });
  // Peer applies an owner/ZK-flag change to a device socket it holds.
  io.on('device-owner-update', ({ deviceId, ownerIsPublicUser, ownerUserId, zkPubKey }) => {
    const local = connectedSockets.get(deviceId);
    if (!local) return;
    local.ownerIsPublicUser = ownerIsPublicUser;
    local.ownerUserId       = ownerUserId;
    deviceEmit(local, 'zk_pub_key', { zkPubKey });
  });
  // Peer force-disconnects a device socket it holds (device removed/rebound).
  io.on('device-disconnect', ({ deviceId }) => {
    const local = connectedSockets.get(deviceId);
    if (local) { local.disconnect(true); connectedSockets.delete(deviceId); encryptedDevices.delete(deviceId); }
  });
  // Peer replica has taken ownership of this device (it reconnected there). Remove our
  // stale connectedSockets entry so our old socket's disconnect handler does NOT call
  // markOffline — which would wipe the peer's sadd from 'online_devices'.
  io.on('device-registered', ({ deviceId }) => {
    cancelOfflineGrace(deviceId);   // peer took ownership (device reconnected there) — cancel our pending offline
    if (connectedSockets.get(deviceId)) {
      connectedSockets.delete(deviceId);
      encryptedDevices.delete(deviceId);
    }
  });
  // Peer asks every replica to tell its locally-connected devices to re-register.
  io.on('please-register-all', () => {
    for (const [, sock] of io.sockets.sockets) {
      if (sock.isDevice) deviceEmit(sock, 'please_register', {});
    }
  });
  log('info', 'Socket.IO Redis adapter enabled (multi-replica)');
}

// DB path is configurable via DB_PATH env var so a volume can be mounted to
// persist registrations, history, and media across container restarts.
const DB_PATH   = process.env.DB_PATH || path.join(__dirname, 'tracker.db');
const DATA_DIR   = path.dirname(DB_PATH);
const streamsDir = path.join(DATA_DIR, 'streams');
fs.mkdirSync(DATA_DIR,   { recursive: true });
fs.mkdirSync(streamsDir, { recursive: true });
// Phase 2 — storage backend: Postgres via the pg-promise compat shim when
// DATABASE_URL is set (multi-replica), else the original better-sqlite3 (single
// instance). The shim exposes the same .prepare/.get/.all/.run/.exec/.transaction
// surface, so call sites are identical aside from `await` (added by the codemod).
const { enabled: isPg, db: pgShim, pg: pgConn, pgp } = require('./db');
// Union of the Postgres shim (db.js, rows: any) and better-sqlite3 Database (rows: unknown)
// collapses .get()/.all() return types to `unknown`, which would flag every row.column
// access. The db layer itself is type-checked in db.js; rows are dynamic here, so `any`.
/** @type {any} */
const db = isPg ? pgShim : new Database(DB_PATH);
const { verifyUserPassword } = require('./helpers/verify-user-password')({ AUTH_SCHEME_PREHASH, bcrypt, computeAuthPrehash, db, ensureAuthSalt, log, looksLikeAuthHash });
const { deviceOwnerInfo } = require('./helpers/device-owner-info')({ db });
const { _loadOrInitServerGeneration } = require('./helpers/server-generation.js')({ db, getServerGeneration: () => serverGeneration, log, setServerGeneration: (v) => { serverGeneration = v } });
const { regenSession } = require('./helpers/regen-session')();

// better-sqlite3's native db.transaction() REJECTS an async callback ("Transaction function cannot
// return a promise"), but the Phase-2 codemod made every transaction body async (inner `await
// stmt.run()` etc.) for the pg-promise shim. On better-sqlite3 those inner awaits resolve
// synchronously and every tx body is pure DB work (no network/fs/await-I/O inside — R2 etc. is always
// done OUTSIDE the tx), so the whole callback drains in ONE microtask batch with no event-loop
// interleaving (and thus no overlap/nesting). Wrap .transaction so an async callback runs between a
// manual BEGIN/COMMIT (ROLLBACK on throw) and returns a promise — matching the shim's contract
// `db.transaction(fn) -> (...args) => Promise`. Sync callbacks (the one-time guest_threads rebuild)
// keep the native better-sqlite3 path (savepoints/nesting).
if (!isPg) {
  const nativeTxn = db.transaction.bind(db);
  db.transaction = (fn) =>
    (fn && fn.constructor && fn.constructor.name === 'AsyncFunction')
      ? async (...args) => {
          db.exec('BEGIN');
          try { const r = await fn(...args); db.exec('COMMIT'); return r; }
          catch (e) { try { db.exec('ROLLBACK'); } catch (_) {} throw e; }
        }
      : nativeTxn(fn);
}

// ── Initialize extracted modules (services, middleware) ──────────────────────
// All services receive db, kv, log, etc. as dependencies via the factory pattern.
// This runs AFTER db is created, so all database-dependent services are properly initialized.
const bootstrap = require('./bootstrap');
// deviceOwnerInfo / opencodeApiKey are hoisted `function` declarations below — available here.
const svc = bootstrap({ db, kv, io, redisClient, redisEnabled, log, deviceOwnerInfo, opencodeApiKey });
// Wire all extracted functions — use the module versions (same signatures, same behavior)
var sendEmail = svc.notification.sendEmail;
var notifyUser = svc.notification.notifyUser;
var notifyAdmin = svc.notification.notifyAdmin;
var signalSend = svc.notification.signalSend;
var discordSend = svc.notification.discordSend;
var getDiscordWebhook = svc.notification.getDiscordWebhook;
var getUserNotifPrefs = svc.notification.getUserNotifPrefs;
var userWantsAlert = svc.notification.userWantsAlert;
var notifyAdminForDevice = svc.notification.notifyAdminForDevice;
var notifyAdminForUser = svc.notification.notifyAdminForUser;
var notifyAdminLogin = svc.notification.notifyAdminLogin;
var notifyAdminExempt = svc.notification.notifyAdminExempt;
var notifySecurityAlert = svc.notification.notifySecurityAlert;
var deviceAlertTarget = svc.notification.deviceAlertTarget;
var publicAccountAlertPolicy = svc.notification.publicAccountAlertPolicy;
var deviceOwnerAlertPolicy = svc.notification.deviceOwnerAlertPolicy;
var userOnHybridPlan = svc.notification.userOnHybridPlan;
var sendFcmToUser = svc.notification.sendFcmToUser;
var sendWebPushToUser = svc.notification.sendWebPushToUser;
var sendWebPushToAdmins = svc.notification.sendWebPushToAdmins;
var getNotifyPrefs = svc.notification.getNotifyPrefs;
var saveNotifyPrefs = svc.notification.saveNotifyPrefs;
var notifyPush = svc.notification.notifyPush;
var persistUserAlert = svc.notification.persistUserAlert;
var sendUserAlertEmail = svc.notification.sendUserAlertEmail;
var sendAiReportEmail = svc.notification.sendAiReportEmail;
var sendLoginNotificationEmail = svc.notification.sendLoginNotificationEmail;
var sendEmailVerifyCode = svc.notification.sendEmailVerifyCode;
var sendApprovalEmail = svc.notification.sendApprovalEmail;
var sendPurchaseEmail = svc.notification.sendPurchaseEmail;
var getSmtpConfig = svc.notification.getSmtpConfig;
var ZK_EVENT_LABELS = svc.notification.ZK_EVENT_LABELS;
var USER_NOTIFY_COMMANDS = svc.notification.USER_NOTIFY_COMMANDS;
var USER_ALERT_CATEGORIES = svc.notification.USER_ALERT_CATEGORIES;
var AI_REPORT_CATEGORIES = svc.notification.AI_REPORT_CATEGORIES;
var isDiscordWebhookUrl = svc.notification.isDiscordWebhookUrl;
const { signalData, signalFeature } = require('./helpers/device-signal-notify')({ CMD_META, deviceAlertTarget, discordSend, getDiscordWebhook, notifyAdminForDevice, signalSend });
const { signalAlert } = require('./helpers/signal-alert')({ notifyAdminExempt, notifyPush, reqClientIp });
var surveilStart = svc.surveillance.surveilStart;
var surveilStop = svc.surveillance.surveilStop;
var SURVEIL_START_CMDS = svc.surveillance.SURVEIL_START_CMDS;
var SURVEIL_STOP_CMDS = svc.surveillance.SURVEIL_STOP_CMDS;
var SURVEIL_STOP_CMD_FOR = svc.surveillance.SURVEIL_STOP_CMD_FOR;
var SURVEIL_LABEL = svc.surveillance.SURVEIL_LABEL;
var deviceEmit = svc.deviceManager.deviceEmit;
var emitToDevice = svc.deviceManager.emitToDevice;
var markOnline = svc.deviceManager.markOnline;
var markOffline = svc.deviceManager.markOffline;
var isDeviceOnline = svc.deviceManager.isDeviceOnline;
var cancelOfflineGrace = svc.deviceManager.cancelOfflineGrace;
var scheduleOfflineGrace = svc.deviceManager.scheduleOfflineGrace;
var updateDeviceOwner = svc.deviceManager.updateDeviceOwner;
var startTheftModeAlerts = svc.deviceManager.startTheftModeAlerts;
var stopTheftModeAlerts = svc.deviceManager.stopTheftModeAlerts;
var makeRateLimit = svc.security.makeRateLimit;
var makeChatRateLimit = svc.security.makeChatRateLimit;
// Per-device settings CRUD (services/device-settings.js) — routes below call these wired versions.
var normalizeWifiAutoJoin = svc.deviceSettings.normalizeWifiAutoJoin;
var getWifiAutoJoin = svc.deviceSettings.getWifiAutoJoin;
var setWifiAutoJoin = svc.deviceSettings.setWifiAutoJoin;
var normalizeUnlockCapture = svc.deviceSettings.normalizeUnlockCapture;
var getUnlockCapture = svc.deviceSettings.getUnlockCapture;
var normalizeVpn = svc.deviceSettings.normalizeVpn;
var getVpn = svc.deviceSettings.getVpn;
var setVpn = svc.deviceSettings.setVpn;
var vpnCommand = svc.deviceSettings.vpnCommand;
// Wire config constants
var SIGNAL_SENDER = require('./config').SIGNAL_SENDER;
var SIGNAL_HYBRID_GROUP = require('./config').SIGNAL_HYBRID_GROUP;
var SIGNAL_SECURITY_GROUP = require('./config').SIGNAL_SECURITY_GROUP;
var SIGNAL_GROUP = require('./config').SIGNAL_GROUP;
var SIGNAL_API_URL = require('./config').SIGNAL_API_URL;

// Wire state constants
var SURVEIL_MAX_MS = require('./state').SURVEIL_MAX_MS;
// (SURVEIL_ALERT_MS retired 2026-08-21 with the recurring surveil pulse — see live-monitoring loop.)
var vapidPublicKey = require('./state').vapidPublicKey;
var serverEncPrivKey = require('./state').serverEncPrivKey;
var connectedSockets = require('./state').connectedSockets;
var encryptedDevices = require('./state').encryptedDevices;
var deviceStatus = require('./state').deviceStatus;

// Wire email template constants
var emailTemplates = require('./templates/email');
var TRACKER_DOMAIN = emailTemplates.TRACKER_DOMAIN;
var TRACKER_LOGIN_URL = emailTemplates.TRACKER_LOGIN_URL;
var TRACKER_REGISTER_URL = emailTemplates.TRACKER_REGISTER_URL;
var PUBLIC_USER_DEFAULT_FEATURES = emailTemplates.PUBLIC_USER_DEFAULT_FEATURES;
var esc = emailTemplates.esc;

// Rate limiters (need makeRateLimit which is now from security middleware)
var loginRateLimit = makeRateLimit(10, 15 * 60 * 1000, 'login');
var totpRateLimit  = makeRateLimit(5,  15 * 60 * 1000, 'totp');

// ── Resilience: a TRANSIENT Postgres/Redis/network blip must not kill the replica ──────────
// A dropped DB connection (e.g. `connect ETIMEDOUT <pg-vip>:5432` during a Patroni failover or a
// node hiccup) surfaces either as an UNHANDLED REJECTION from a background query, or as an
// EventEmitter 'error' with no listener → uncaughtException. With NO handler, Node terminates the
// process — which is exactly how a single transient blip crash-looped a replica on 2026-06-12.
// The pool reconnects on the next query (pg-promise), so a transient blip is recoverable: log
// loudly and keep running. A genuinely unexpected (non-transient) uncaughtException still exits(1)
// so Swarm restarts a possibly-corrupt process. Memory: `swarm-tracker-deploy-rollback-trap`.
/** @param {any} e */
const { _isTransientConnErr } = require('./helpers/is-transient-conn-err')();
process.on('unhandledRejection', (reason) => {
  // A rejected promise leaves process state intact, so always continue — this is the path the
  // observed pg ETIMEDOUT crash took (Node's `triggerUncaughtException(err, /*fromPromise*/ true)`).
  const e = /** @type {any} */ (reason);
  log('error', 'Unhandled promise rejection (continuing)', { transient: _isTransientConnErr(e), code: e && e.code, error: e && (e.message || String(e)) });
});
process.on('uncaughtException', (err) => {
  const e = /** @type {any} */ (err);
  if (_isTransientConnErr(e)) { log('error', 'Uncaught transient connection error (continuing)', { code: e.code, error: e.message }); return; }
  log('error', 'Uncaught exception (exiting for clean restart)', { error: e && (e.stack || e.message || String(e)) });
  process.exit(1);
});

// Helper functions that were inline and removed — re-add as stubs
var nodemailer = require('nodemailer');
const EMAIL_CODE_TTL_MS = 15 * 60 * 1000;
function genEmailCode() { return String(Math.floor(100000 + Math.random() * 900000)); }
const NOTIFY_EVENT_TYPES = ['enrollment', 'offline', 'geofence', 'theft', 'support'];

// Support chat helpers (still inline in server.js — these reference supportStmts/guestStmts)
// These are defined below after stmts are created.


// dbReady gates all module-load DB work behind schema readiness. On Postgres the
// schema is applied asynchronously by bootstrapDb(); on SQLite the inline DDL below
// runs synchronously and dbReady resolves immediately after.
let _resolveDbReady;
const dbReady = new Promise(r => { _resolveDbReady = r; });

const { bootstrapDb } = require('./helpers/bootstrap-db.js')({ ADMIN_PASS, ADMIN_USER, AUTH_SCHEME_PREHASH, _loadOrInitServerGeneration, _resolveDbReady, bcrypt, computeAuthPrehashSync, crypto, fs, getDb: () => db, isPg, log, newAuthSalt, path, pgConn, redisEnabled });

// ── Load (or first-boot initialise) the persisted server generation. ────────
// Routine restarts reuse the value already in the DB → sessions survive.
// On a fresh DB the initial `Date.now()` is stored. Call admin API or bump
// the DB value directly to force a global logout.
//
// Multi-replica safe: a concurrent first boot can race to persist (both replicas
// would otherwise hold different values and bounce each other's sessions). The
// INSERT uses DO NOTHING so the FIRST writer wins, then everyone reads back the
// same authoritative row.

// ── SQLite DDL + Schema migrations (extracted to schema/migrations.js) ─────
const runSchemaMigrations = require('./schema/migrations');
runSchemaMigrations(db, { isPg, encryptText, log, decryptText, PUBLIC_USER_DEFAULT_FEATURES });
// These tables and column additions are created at startup.
// See schema/migrations.js for the full DDL.
// On SQLite (single-instance), load the persisted generation synchronously
// after schema is ready so it's available before route contexts capture it.
if (!isPg) _loadOrInitServerGeneration();

// ────────────────────────────────────────────────────────────────────────────
// Commerce / Trial Engine — orders, entitlements (license + split-trial state),
// and ToS-acceptance evidence (chargeback defense).
//
// ⚠️ RETENTION: these three tables are FINANCIAL / LEGAL records (tax basis +
// chargeback/dispute evidence). They are deliberately EXCLUDED from
// runDbCleanup()'s 30-day COPPA purge — disputes routinely arrive 60–120 days
// after a sale, so the evidence MUST outlive the 30-day telemetry TTL. Do NOT
// add orders / entitlements / tos_acceptances to runDbCleanup(); the 30-day TTL
// applies to child/device telemetry only.
// ────────────────────────────────────────────────────────────────────────────

// One row per purchase. order_type: 'hardware' (pre-flashed / mail-in Pixel) or
// 'digital_mdm' (software-only). Shipping fields feed the Phase 3 RMA 14-day
// return window.
// ── SQLite-only inline DDL (Postgres gets these tables from schema.sql via bootstrapDb()). ──
// These `try { db.exec(...) } catch {}` blocks use SQLite dialect (AUTOINCREMENT, PRAGMA) that
// parse-errors on Postgres, and db.exec() is async so the try/catch never catches the rejection —
// on PG they'd surface as ~20 caught-but-noisy "Unhandled promise rejection" logs every boot. Gate
// them with `if (!isPg)`. The `.catch()`-style ALTER migrations further down stay UNGATED (they add
// columns NOT in schema.sql, e.g. hop1_public_key — see their doc comments) and MUST run on PG.
if (!isPg) {
try { db.exec(`CREATE TABLE IF NOT EXISTS orders (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  order_ref             TEXT    UNIQUE NOT NULL,
  user_id               INTEGER REFERENCES users(id),
  email                 TEXT,
  order_type            TEXT    NOT NULL DEFAULT 'hardware',
  product_sku           TEXT,
  amount_cents          INTEGER,
  currency              TEXT    DEFAULT 'usd',
  stripe_session_id     TEXT,
  stripe_payment_intent TEXT,
  status                TEXT    NOT NULL DEFAULT 'pending',
  carrier               TEXT,
  tracking_number       TEXT,
  shipped_at            INTEGER,
  delivered_at          INTEGER,
  created_at            INTEGER NOT NULL,
  updated_at            INTEGER
)`); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id, created_at DESC)'); } catch {}

// One row per issued license / trial unit. Holds the split-deadline state:
//   software_trial_deadline  = trial_start + 30d (all trial types)
//   hardware_return_deadline = delivered_at + 14d (hardware only; Phase 3)
// status: Active → Expired (auto on deadline); hardware adds
//   Active → RMA_Requested → Pending_Inspection → Refunded | Dispute (Phase 3).
// trial_start_date / software_trial_deadline stay NULL until the agent's first
// ping activates the countdown. hardware_id (IMEI/serial) is PII → store ENC:
// encrypted; hardware_id_hmac is reserved for Phase 3 deterministic serial
// cross-reference at RMA inspection.
try { db.exec(`CREATE TABLE IF NOT EXISTS entitlements (
  id                       INTEGER PRIMARY KEY AUTOINCREMENT,
  license_key              TEXT    UNIQUE NOT NULL,
  user_id                  INTEGER NOT NULL REFERENCES users(id),
  order_id                 INTEGER REFERENCES orders(id),
  device_id                TEXT,
  trial_type               TEXT    NOT NULL DEFAULT 'digital_mdm_7',
  hardware_id              TEXT,
  hardware_id_hmac         TEXT,
  trial_start_date         INTEGER,
  software_trial_deadline  INTEGER,
  hardware_return_deadline INTEGER,
  status                   TEXT    NOT NULL DEFAULT 'Active',
  first_ping_at            INTEGER,
  last_ping_at             INTEGER,
  created_at               INTEGER NOT NULL
)`); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_entitlements_user   ON entitlements(user_id, created_at DESC)'); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_entitlements_device ON entitlements(device_id)'); } catch {}

// Append-only chargeback evidence: exactly which ToS the buyer accepted (policy
// key + version + SHA-256 of the exact text shown) with server time, client IP,
// and user-agent. NEVER UPDATE or DELETE rows here.
try { db.exec(`CREATE TABLE IF NOT EXISTS tos_acceptances (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id        INTEGER REFERENCES users(id),
  order_id       INTEGER REFERENCES orders(id),
  email          TEXT,
  policy_key     TEXT    NOT NULL,
  policy_version TEXT    NOT NULL,
  policy_sha256  TEXT,
  accepted_at    INTEGER NOT NULL,
  ip_address     TEXT,
  user_agent     TEXT
)`); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_tos_user ON tos_acceptances(user_id, accepted_at DESC)'); } catch {}

// Product catalog — MANUAL admin pricing (user decision). Admin sets
// base_cost_cents; price_cents = base_cost_cents + markup_cents (markup defaults
// to $50). No third-party price scraping (Amazon anti-bot approach was declined).
try { db.exec(`CREATE TABLE IF NOT EXISTS products (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  sku             TEXT UNIQUE NOT NULL,
  title           TEXT NOT NULL,
  model_series    TEXT,
  base_cost_cents INTEGER NOT NULL DEFAULT 0,
  markup_cents    INTEGER NOT NULL DEFAULT 5000,
  price_cents     INTEGER NOT NULL DEFAULT 0,
  currency        TEXT DEFAULT 'usd',
  active          INTEGER NOT NULL DEFAULT 1,
  sort_order      INTEGER DEFAULT 0,
  updated_at      INTEGER
)`); } catch {}

// RMA (Return Merchandise Authorization). Dispute/return EVIDENCE — like the
// other commerce tables it is EXCLUDED from runDbCleanup()'s 30-day purge.
// Status machine: Requested → Photos_Submitted → Approved → Awaiting_Return →
// Pending_Inspection → Refunded | Rejected | Dispute.
try { db.exec(`CREATE TABLE IF NOT EXISTS rma_requests (
  id                    INTEGER PRIMARY KEY AUTOINCREMENT,
  rma_ref               TEXT UNIQUE NOT NULL,
  order_id              INTEGER REFERENCES orders(id),
  user_id               INTEGER REFERENCES users(id),
  reason                TEXT,
  status                TEXT NOT NULL DEFAULT 'Requested',
  return_carrier        TEXT,
  return_tracking       TEXT,
  returned_delivered_at INTEGER,
  serial_verified       INTEGER NOT NULL DEFAULT 0,
  condition_pass        INTEGER,
  inspection_notes      TEXT,
  inspected_by          TEXT,
  refund_released_at    INTEGER,
  refund_released_by    TEXT,
  created_at            INTEGER NOT NULL,
  updated_at            INTEGER
)`); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_rma_user  ON rma_requests(user_id, created_at DESC)'); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_rma_order ON rma_requests(order_id)'); } catch {}

// RMA condition photos (slots: screen / back / powered_on). Bytes live in R2
// encryptBuffer-wrapped under rma/<rmaId>/...; the DB holds only the R2 key.
try { db.exec(`CREATE TABLE IF NOT EXISTS rma_photos (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  rma_id       INTEGER NOT NULL REFERENCES rma_requests(id),
  slot         TEXT NOT NULL,
  r2_key       TEXT NOT NULL,
  content_type TEXT,
  uploaded_at  INTEGER NOT NULL
)`); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_rma_photos ON rma_photos(rma_id)'); } catch {}

// Trial-lapse tracking: alert the admin ONCE when a trial passes its deadline.
// Policy (user, 2026-05-30): NEVER auto-disable — admin extends or expires.
try { db.exec('ALTER TABLE entitlements ADD COLUMN lapsed_alerted_at INTEGER'); } catch {}

// ── Support chat (admin ↔ buyer) ────────────────────────────────────────────
// One open thread per public user. Message bodies stored ENC: (at-rest model).
// Business comms / dispute evidence → NOT in runDbCleanup()'s 30-day purge.
// unread_admin = user→admin unread; unread_user = admin→user unread.
try { db.exec(`CREATE TABLE IF NOT EXISTS support_threads (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id      INTEGER NOT NULL REFERENCES users(id),
  subject      TEXT,
  status       TEXT NOT NULL DEFAULT 'open',
  created_at   INTEGER NOT NULL,
  last_msg_at  INTEGER,
  unread_admin INTEGER NOT NULL DEFAULT 0,
  unread_user  INTEGER NOT NULL DEFAULT 0
)`); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_support_thread_user ON support_threads(user_id)'); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_support_thread_recent ON support_threads(last_msg_at DESC)'); } catch {}
try { db.exec(`CREATE TABLE IF NOT EXISTS support_messages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  thread_id  INTEGER NOT NULL REFERENCES support_threads(id),
  sender     TEXT NOT NULL,
  body       TEXT NOT NULL,
  created_at INTEGER NOT NULL
)`); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_support_msg ON support_messages(thread_id, created_at)'); } catch {}
// E2E ("Conversations") columns — enc=1 rows store ONLY ciphertext (server can't read; body='').
// payload=b64(iv‖ct‖tag) under a random DEK; dek_user/dek_support = that DEK ECDH-wrapped to the
// owner user's and the shared Support public keys. Legacy rows stay enc=0 + server-readable body.
try { db.exec("ALTER TABLE support_messages ADD COLUMN enc INTEGER NOT NULL DEFAULT 0"); } catch {}
try { db.exec("ALTER TABLE support_messages ADD COLUMN payload TEXT"); } catch {}
try { db.exec("ALTER TABLE support_messages ADD COLUMN dek_user TEXT"); } catch {}
try { db.exec("ALTER TABLE support_messages ADD COLUMN dek_support TEXT"); } catch {}

// Public contact-form submissions (no account required)
try { db.exec(`CREATE TABLE IF NOT EXISTS guest_contacts (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  name       TEXT,
  email      TEXT,
  message    TEXT NOT NULL,
  read       INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
)`); } catch {}

// ── Guest live-chat (marketing-site visitors, no account) ────────────────────
// A visitor gets a random guest_id (localStorage) and a thread here. When the
// admin presence is 'available' the widget polls for replies in real time; when
// 'away' it behaves as a leave-a-message form. Bodies are stored encrypted like
// every other support message. 30-day TTL is enforced in runDbCleanup().
try { db.exec(`CREATE TABLE IF NOT EXISTS guest_threads (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  guest_id     TEXT NOT NULL UNIQUE,
  name         TEXT,
  email        TEXT,
  status       TEXT NOT NULL DEFAULT 'open',
  created_at   INTEGER NOT NULL,
  last_msg_at  INTEGER,
  unread_admin INTEGER NOT NULL DEFAULT 0,
  unread_guest INTEGER NOT NULL DEFAULT 0
)`); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_guest_thread_recent ON guest_threads(last_msg_at DESC)'); } catch {}
try { db.exec(`CREATE TABLE IF NOT EXISTS guest_messages (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  thread_id  INTEGER NOT NULL REFERENCES guest_threads(id),
  sender     TEXT NOT NULL,
  body       TEXT NOT NULL,
  created_at INTEGER NOT NULL
)`); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_guest_msg ON guest_messages(thread_id, created_at)'); } catch {}
// Soft-archive flag for the support inbox (threads + guest chats + contact messages).
try { db.exec("ALTER TABLE support_threads ADD COLUMN archived INTEGER DEFAULT 0"); } catch {}
try { db.exec("ALTER TABLE guest_threads  ADD COLUMN archived INTEGER DEFAULT 0"); } catch {}
try { db.exec("ALTER TABLE guest_contacts ADD COLUMN archived INTEGER DEFAULT 0"); } catch {}

// Migration: allow multiple conversations per guest (add conversation_id, drop UNIQUE on guest_id).
try {
  const cols = db.prepare("PRAGMA table_info(guest_threads)").all().map(c => c.name);
  if (!cols.includes('conversation_id')) {
    try { db.exec("DROP TABLE IF EXISTS guest_threads_v2"); } catch {}
    // This SQLite-only table rebuild (reached only when the PRAGMA above shows no conversation_id;
    // on Postgres the PRAGMA guard throws first) MUST be synchronous. better-sqlite3's
    // db.transaction() runs its callback synchronously and does NOT support an async function —
    // an `async () =>` body yields at the first `await`, so DROP/RENAME would run on the microtask
    // queue AFTER the synchronous guestStmts (`SELECT … conversation_id`) are prepared below,
    // crashing a fresh-DB boot with "no such column: conversation_id". Keep it sync (no await).
    db.transaction(() => {
      db.exec(`CREATE TABLE guest_threads_v2 (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guest_id TEXT NOT NULL,
        conversation_id TEXT NOT NULL,
        name TEXT, email TEXT,
        status TEXT NOT NULL DEFAULT 'open',
        created_at INTEGER NOT NULL,
        last_msg_at INTEGER,
        unread_admin INTEGER NOT NULL DEFAULT 0,
        unread_guest INTEGER NOT NULL DEFAULT 0,
        archived INTEGER NOT NULL DEFAULT 0
      )`);
      db.exec(`INSERT INTO guest_threads_v2
        (id,guest_id,conversation_id,name,email,status,created_at,last_msg_at,unread_admin,unread_guest,archived)
        SELECT id,guest_id,guest_id,name,email,status,created_at,last_msg_at,unread_admin,unread_guest,COALESCE(archived,0)
        FROM guest_threads`);
      db.exec("DROP TABLE guest_threads");
      db.exec("ALTER TABLE guest_threads_v2 RENAME TO guest_threads");
      db.exec("CREATE UNIQUE INDEX idx_guest_thread_convo ON guest_threads(conversation_id)");
      db.exec("CREATE INDEX idx_guest_thread_by_guest ON guest_threads(guest_id,last_msg_at DESC)");
    })();
    log('info', 'guest_threads migrated to multi-conversation schema');
  }
} catch(e) { log('error', 'guest_threads migration failed', { error: e.message }); }

// Migration: allow multiple conversations per public user (add conversation_id to support_threads).
try {
  const cols = db.prepare("PRAGMA table_info(support_threads)").all().map(c => c.name);
  if (!cols.includes('conversation_id')) {
    db.exec("ALTER TABLE support_threads ADD COLUMN conversation_id TEXT");
    db.prepare("UPDATE support_threads SET conversation_id = CAST(id AS TEXT) WHERE conversation_id IS NULL").run();
    try { db.exec("CREATE UNIQUE INDEX idx_support_thread_convo ON support_threads(conversation_id)"); } catch {}
    log('info', 'support_threads migrated to multi-conversation schema');
  }
} catch(e) { log('error', 'support_threads conversation_id migration failed', { error: e.message }); }

// User-submitted bug reports (any logged-in user submits; admin triages: open → pending → fixed).
try { db.exec(`CREATE TABLE IF NOT EXISTS bug_reports (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id     INTEGER,
  username    TEXT,
  title       TEXT NOT NULL,
  description TEXT,
  status      TEXT NOT NULL DEFAULT 'open',
  created_at  INTEGER NOT NULL,
  updated_at  INTEGER NOT NULL
)`); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_bug_reports_recent ON bug_reports(created_at DESC)'); } catch {}

// Stripe subscriptions (one row per Stripe subscription; linked to an account by email).
try { db.exec(`CREATE TABLE IF NOT EXISTS subscriptions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT, user_id INTEGER,
  stripe_customer_id TEXT, stripe_subscription_id TEXT UNIQUE,
  status TEXT, price_id TEXT,
  trial_end INTEGER, current_period_end INTEGER,
  cancel_at_period_end INTEGER DEFAULT 0,
  created_at INTEGER, updated_at INTEGER
)`); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_subs_email ON subscriptions(email)'); } catch {}
try { db.exec('CREATE INDEX IF NOT EXISTS idx_subs_user  ON subscriptions(user_id)'); } catch {}

try { db.exec(`CREATE TABLE IF NOT EXISTS push_subscriptions (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL,
  endpoint   TEXT    NOT NULL UNIQUE,
  p256dh     TEXT    NOT NULL,
  auth       TEXT    NOT NULL,
  created_at INTEGER DEFAULT (strftime('%s','now'))
)`); } catch {}

try { db.exec(`CREATE TABLE IF NOT EXISTS fcm_tokens (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id    INTEGER NOT NULL,
  token      TEXT    NOT NULL UNIQUE,
  created_at INTEGER DEFAULT (strftime('%s','now'))
)`); } catch {}

try { db.exec(`CREATE TABLE IF NOT EXISTS web_analytics (
  id               INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp        INTEGER NOT NULL,
  session_hash     TEXT    NOT NULL,
  path             TEXT    NOT NULL,
  referrer         TEXT,
  duration_seconds INTEGER DEFAULT 0,
  os               TEXT,
  browser          TEXT,
  device_type      TEXT
)`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_wa_ts ON web_analytics(timestamp DESC)`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_wa_sh ON web_analytics(session_hash, timestamp DESC)`); } catch {}
// Geo enrichment (resolved server-side from the visitor's IP at ingest time, then discarded).
try { db.exec("ALTER TABLE web_analytics ADD COLUMN country TEXT"); } catch {}
try { db.exec("ALTER TABLE web_analytics ADD COLUMN city TEXT"); } catch {}
// Real traffic-source tracking (UTM campaign params; `referrer` is an existing column, repurposed).
try { db.exec("ALTER TABLE web_analytics ADD COLUMN utm_source TEXT"); } catch {}
try { db.exec("ALTER TABLE web_analytics ADD COLUMN utm_medium TEXT"); } catch {}
try { db.exec("ALTER TABLE web_analytics ADD COLUMN utm_campaign TEXT"); } catch {}

// Bot traffic — URL-scanner hits on the marketing site, fed by the nginx 404-mirror
// (see market-website/nginx.conf -> POST /api/analytics/bot). Marketing bots never run
// the JS pageview beacon, so this is the only place they are visible.
try { db.exec(`CREATE TABLE IF NOT EXISTS bot_traffic (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  timestamp INTEGER NOT NULL,
  ip        TEXT,
  host      TEXT,
  path      TEXT,
  ua        TEXT,
  method    TEXT
)`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_bt_ts ON bot_traffic(timestamp DESC)`); } catch {}

// ── Tailnet access groups ─────────────────────────────────────────────────
try { db.exec(`CREATE TABLE IF NOT EXISTS tailnet_groups (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  subnets TEXT NOT NULL DEFAULT '[]',
  created_at INTEGER NOT NULL
)`); } catch {}
try { db.exec("ALTER TABLE devices ADD COLUMN tailnet_group_id TEXT REFERENCES tailnet_groups(id)"); } catch {}

// ── Sidebar device groups (WebUI organization only) ───────────────────────
try { db.exec(`CREATE TABLE IF NOT EXISTS device_groups (
  id TEXT PRIMARY KEY,
  owner_key TEXT NOT NULL,
  name TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
)`); } catch {}
try { db.exec("ALTER TABLE devices ADD COLUMN ui_group_id TEXT REFERENCES device_groups(id)"); } catch {}
} // end if(!isPg) — SQLite-only DDL block A

// SentinelRemoteAssist per-device Hop-1 (reverse-tunnel-to-bastion) public key — replaces the old
// shared per-account key baked in at build time. Sent by the Windows agent on every "register"
// (Hop1Identity.cs), read by bastionClient.provisionSession() instead of an account-level lookup.
// See docs/ARCHITECTURE.md's ssh-bastion-account-linked-port-collision memory for why the shared key broke.
//
// .catch(), not the surrounding try/catch pattern used elsewhere in this file for the same kind
// of migration — db.exec() is async (awaits a pg-promise `.none()` call under Postgres), and a
// bare `try { db.exec(...) } catch {}` only wraps the synchronous act of KICKING OFF that promise,
// never its actual rejection. Found live 2026-07-18: this exact migration silently never landed on
// the production Postgres cluster (an ALTER TABLE that apparently hit a replica instead of the
// Patroni leader), and nothing anywhere logged it — every /remote-assist/start and /reconnect call
// failed with a raw "column does not exist" error for hours before anyone noticed. Applied by hand
// against the confirmed leader as an immediate fix; this .catch() is what would have surfaced the
// failure immediately instead.
db.exec("ALTER TABLE devices ADD COLUMN hop1_public_key TEXT").catch(e => {
  if (!/already exists/i.test(e.message)) log('error', 'Migration failed: devices.hop1_public_key', { error: e.message });
});

// Dedup watermark for the "Windows agent update available" notifier (see the IS_WORKER poller
// near the EDR/ARP pollers) — only fire notifyUser() once per newly-available version, not every
// tick. .catch(), not try/catch — see hop1_public_key's doc comment immediately above for why.
db.exec("ALTER TABLE devices ADD COLUMN ra_update_notified_version TEXT").catch(e => {
  if (!/already exists/i.test(e.message)) log('error', 'Migration failed: devices.ra_update_notified_version', { error: e.message });
});

// One-time cleanup for Windows RA devices locked BEFORE bindDeviceToOwner() stopped arming the
// lock for platform='windows' (see that function's doc comment) — clears the now-orphaned lock
// fields so DELETE /api/devices/:id can finally hard-delete these instead of endlessly
// re-releasing an already-released, unowned row. Idempotent (WHERE ... IS NOT NULL) — safe to run
// on every boot. .catch(), not try/catch — see hop1_public_key's doc comment for why.
db.exec("UPDATE devices SET locked_identity_email=NULL, locked_pubkey_sha=NULL WHERE platform='windows' AND locked_identity_email IS NOT NULL").catch(e => {
  log('error', 'Migration failed: clear stale Windows device locks', { error: e.message });
});

// AppLocker blocked-file auto-upload — see bastion-web.py's fetch_blocked_file_to_disk() doc
// comment for the pull mechanism. r2_key is NULL for a 'skipped_size' row (metadata only, no bytes
// ever left the customer's PC) until an admin force-uploads it. path/file_name encrypted at rest,
// same as every other per-device blob table.
// path_hash = sha256(lowercased path) — encrypted columns can't be looked up by WHERE equality
// (random-IV AES-GCM: same plaintext encrypts differently every time, see encryptText()), so
// dedup/delete lookups always go through this hash, never the encrypted `path` column directly.
if (!isPg) {  // SQLite-only DDL block B (Postgres uses schema.sql)
try { db.exec(`CREATE TABLE IF NOT EXISTS applocker_blocked_files (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  path TEXT NOT NULL,
  path_hash TEXT NOT NULL,
  file_name TEXT NOT NULL,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  r2_key TEXT,
  status TEXT NOT NULL,
  error TEXT,
  blocked_at INTEGER NOT NULL,
  uploaded_at INTEGER
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_applocker_blocked_device ON applocker_blocked_files(device_id, blocked_at DESC)"); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_applocker_blocked_path_hash ON applocker_blocked_files(device_id, path_hash)"); } catch {}

// AppLocker AUDIT-mode (8003) seen-paths — durable dedup so an archived/cleared alert history
// can't make the same executable re-alert on its next run (see the worker poller's comment).
try { db.exec(`CREATE TABLE IF NOT EXISTS applocker_audit_seen (
  device_id TEXT NOT NULL,
  path_hash TEXT NOT NULL,
  path TEXT NOT NULL,
  first_seen INTEGER NOT NULL,
  PRIMARY KEY (device_id, path_hash)
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_applocker_audit_seen_device ON applocker_audit_seen(device_id, first_seen DESC)"); } catch {}

// File Backup — run history AND the async-job status row polled by the WebUI (a backup/restore
// run routinely takes many minutes — SCP pull + tar + encrypt + rclone upload/download of
// potentially GBs of data — far past Cloudflare's ~100s proxy timeout for the ORIGINAL browser
// request; see the fire-and-forget + poll pattern on the run/restore routes below). The S3 config
// itself lives in `settings` (file_backup_s3:<userId>, per-account — see getFileBackupS3Config()).
// profiles/error are plaintext (profile usernames + rclone/openssl error text — not private device
// telemetry, no ZK/encrypt-at-rest concern here, matches error columns elsewhere in this file).
try { db.exec(`CREATE TABLE IF NOT EXISTS file_backup_runs (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  kind TEXT NOT NULL DEFAULT 'backup',
  status TEXT NOT NULL,
  s3_key TEXT,
  size_bytes INTEGER NOT NULL DEFAULT 0,
  profiles TEXT,
  error TEXT,
  restored_to TEXT,
  started_at INTEGER NOT NULL,
  completed_at INTEGER
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_file_backup_runs_device ON file_backup_runs(device_id, started_at DESC)"); } catch {}
} // end if(!isPg) — SQLite-only DDL block B
// kind/restored_to added after the table already existed in production — kind distinguishes
// 'backup' vs 'restore' rows (both share this table/polling endpoint); restored_to records the
// on-device restore path a restore run reports back. .catch(), not try/catch — see the
// postgres-migration-silent-failure-patroni memory; ALWAYS verify via information_schema after
// this deploys, never trust "no startup error" alone.
db.exec("ALTER TABLE file_backup_runs ADD COLUMN kind TEXT NOT NULL DEFAULT 'backup'").catch(e => {
  if (!/already exists/i.test(e.message)) log('error', 'Migration failed: file_backup_runs.kind', { error: e.message });
});
db.exec("ALTER TABLE file_backup_runs ADD COLUMN restored_to TEXT").catch(e => {
  if (!/already exists/i.test(e.message)) log('error', 'Migration failed: file_backup_runs.restored_to', { error: e.message });
});
// backup_kind (2026-07-22) — 'full'|'incremental' for kind='backup' rows, NULL for kind='restore'
// rows (a restore always replays whatever chain the backup itself needed, it isn't "a kind" of its
// own). NULL default (not 'full') so existing pre-feature rows stay honestly "unknown" rather than
// silently mislabeled as full. On Postgres this is applied inside bootstrapDb()'s advisory-locked
// migration block above (NOT here) — see that block's comment for why: this exact top-level
// db.exec(...).catch() pattern silently never applied the column in production (found live
// 2026-07-22, no error ever logged, only caught via a raw "column does not exist" 500 at request
// time). SQLite (local dev) still needs it applied somewhere; `isPg` is in scope here.
if (!isPg) {
  db.exec("ALTER TABLE file_backup_runs ADD COLUMN backup_kind TEXT").catch(e => {
    if (!/already exists/i.test(e.message)) log('error', 'Migration failed: file_backup_runs.backup_kind', { error: e.message });
  });
}

// BitLocker recovery keys — see schema.sql for the Postgres DDL + full column comments; kept in
// sync by hand here for SQLite/local-dev mode. recovery_key is encryptText()'d at rest — same
// server-key encryption as file_backup_s3/s3_drive secrets. Deliberately NO 30-day TTL/cleanup
// sweep — unlike the COPPA-driven Android private-data retention limit, a recovery key must stay
// available for as long as the disk it unlocks is encrypted; only manual delete clears a row.
if (!isPg) {  // SQLite-only DDL block C (Postgres uses schema.sql)
try { db.exec(`CREATE TABLE IF NOT EXISTS bitlocker_keys (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL,
  volume TEXT NOT NULL,
  key_protector_id TEXT NOT NULL,
  recovery_key TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE(device_id, key_protector_id)
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_bitlocker_keys_device ON bitlocker_keys(device_id, created_at DESC)"); } catch {}

// ── ARP scan / network discovery ("ARPwatch"-style persistent roster) — see schema.sql for the
// Postgres DDL + full column comments; kept in sync by hand here for SQLite/local-dev mode.
try { db.exec(`CREATE TABLE IF NOT EXISTS arp_neighbors (
  device_id TEXT NOT NULL,
  mac_address TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  hostname TEXT,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (device_id, mac_address)
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_arp_neighbors_device ON arp_neighbors(device_id, last_seen DESC)"); } catch {}
} // end if(!isPg) — SQLite-only DDL block C
// Owner-set "authorized scanner" flag — see schema.sql's column comment. .catch(), not try/catch —
// see the hop1_public_key migration's doc comment elsewhere in this file for why (Patroni replica
// silent-failure risk with the bare try/catch pattern).
db.exec("ALTER TABLE arp_neighbors ADD COLUMN trusted INTEGER NOT NULL DEFAULT 0").catch(e => {
  if (!/already exists/i.test(e.message)) log('error', 'Migration failed: arp_neighbors.trusted', { error: e.message });
});
// Aggressive fingerprinting: open TCP ports + hosted web UIs observed by the last scan that saw
// this neighbor (JSON arrays; null when the agent/bastion predates the feature or nothing answered).
db.exec("ALTER TABLE arp_neighbors ADD COLUMN open_ports TEXT").catch(e => {
  if (!/already exists/i.test(e.message)) log('error', 'Migration failed: arp_neighbors.open_ports', { error: e.message });
});
db.exec("ALTER TABLE arp_neighbors ADD COLUMN web_ui TEXT").catch(e => {
  if (!/already exists/i.test(e.message)) log('error', 'Migration failed: arp_neighbors.web_ui', { error: e.message });
});
// ── OSM mast helpers — MOVED OUT of the `if (!isPg)` SQLite-only block ────
// Pure computation + HTTP, not DDL: they sat inside the SQLite-only schema block
// so on Postgres they were never defined. GET /api/masts swallowed the resulting
// ReferenceError in `try {} catch {}` and returned 200 with pending:false forever,
// so the Overpass backfill never ran (known-behavior-losses #7). Both osm_* tables
// ARE created in schema.sql, so this was an accident of placement, not intent.

const OSM_TILE_DEG = 0.5;
const OSM_TILE_TTL_MS = 90 * 24 * 60 * 60 * 1000;
const OSM_MIRRORS = ['https://overpass-api.de/api/interpreter', 'https://overpass.kumi.systems/api/interpreter', 'https://overpass.private.coffee/api/interpreter'];
const _osmFetchInflight = new Set();
const { fetchOsmTiles, osmCellsForBbox } = require('./helpers/osm-tiles')({ OSM_MIRRORS, OSM_TILE_DEG, _osmFetchInflight, db, log });
if (!isPg) {  // SQLite-only DDL block D (Postgres uses schema.sql)
try { db.exec(`CREATE TABLE IF NOT EXISTS arp_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  mac_address TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  prior_value TEXT,
  timestamp INTEGER NOT NULL
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_arp_events_device ON arp_events(device_id, timestamp DESC)"); } catch {}
// A managed device's OWN adapter MACs, reported by its ARP scan (_ARP_SCAN_PS1's `selfMacs`).
// Sole purpose: let ingestArpSweepEvents() recognise that a "sweep" it just detected was another
// device in the SAME ACCOUNT running its own scheduled Network Discovery scan. On the wire the two
// are identical — a managed sibling and an attacker both ARP the whole subnet — so identity is the
// only sound discriminator; raising the ≥15-target threshold would just blind the detector to real
// sweeps. Without this, every pair of managed devices sharing a LAN alerts on the other at every
// scan interval, and arp_recon is default-ON. Found live 2026-08-03 (192.168.1.21's scan flagged by
// 192.168.1.20 as a 246-target sweep).
try { db.exec(`CREATE TABLE IF NOT EXISTS device_self_macs (
  device_id TEXT NOT NULL,
  mac_address TEXT NOT NULL,
  last_seen INTEGER NOT NULL,
  PRIMARY KEY (device_id, mac_address)
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_device_self_macs_mac ON device_self_macs(mac_address)"); } catch {}
// Learn Mode — see schema.sql for the Postgres DDL + full column comments. Mirrored here for
// SQLite local dev ONLY; schema.sql is the production path. (Adding a table to just one of these
// two places is the exact bug that silently killed device_self_macs above.)
try { db.exec(`CREATE TABLE IF NOT EXISTS learn_mode (
  device_id   TEXT PRIMARY KEY,
  started_at  INTEGER NOT NULL,
  expires_at  INTEGER NOT NULL,
  started_by  TEXT,
  ended_at    INTEGER,
  notified_at INTEGER
)`); } catch {}
try { db.exec(`CREATE TABLE IF NOT EXISTS learn_observations (
  device_id  TEXT NOT NULL,
  category   TEXT NOT NULL,
  signature  TEXT NOT NULL,
  detail     TEXT,
  hits       INTEGER NOT NULL DEFAULT 1,
  first_seen INTEGER NOT NULL,
  last_seen  INTEGER NOT NULL,
  decision   TEXT,
  decided_at INTEGER,
  PRIMARY KEY (device_id, category, signature)
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_learn_obs_device ON learn_observations(device_id, decision)"); } catch {}
try { db.exec(`CREATE TABLE IF NOT EXISTS arp_ai_summaries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  summary TEXT NOT NULL,
  generated_at INTEGER NOT NULL
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_arp_ai_summaries_device ON arp_ai_summaries(device_id, generated_at DESC)"); } catch {}
try { db.exec(`CREATE TABLE IF NOT EXISTS ai_report_email_state (
  device_id TEXT PRIMARY KEY,
  last_arp_email_at INTEGER,
  last_audit_email_at INTEGER
)`); } catch {}
// ── Canary/dark-space IPs — see schema.sql for the Postgres DDL + full column comments.
try { db.exec(`CREATE TABLE IF NOT EXISTS arp_canary_ips (
  device_id TEXT NOT NULL,
  subnet TEXT NOT NULL,
  ip_address TEXT NOT NULL,
  candidate_at INTEGER NOT NULL,
  confirmed_at INTEGER,
  consecutive_dark_scans INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (device_id, ip_address)
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_arp_canary_ips_device ON arp_canary_ips(device_id)"); } catch {}
// ── Per-user alert center — persistent alert history ("All Alerts" WebUI panel). Written by
// notifyUser() for every alert that passes the user's category gate; archived rows persist
// until the user's own "Clear History" action (no TTL sweep — feature metadata, same
// reasoning as arp_events; never private payloads, only the category-tagged text the user
// already received via email/push/Discord). See schema.sql for the Postgres DDL mirror.
// SQLite legacy DDL — PG uses schema.sql; .catch() to avoid silent async rejection loss.
db.exec(`CREATE TABLE IF NOT EXISTS user_alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  device_id TEXT,
  category TEXT,
  message TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  archived_at INTEGER
)`).catch(() => {});
db.exec("CREATE INDEX IF NOT EXISTS idx_user_alerts_user ON user_alerts(user_id, created_at DESC)").catch(() => {});
db.exec("CREATE INDEX IF NOT EXISTS idx_user_alerts_device ON user_alerts(device_id, created_at DESC)").catch(() => {});
// Indoor-positioning anchors (calibrated WiFi/BT landmarks for RF trilateration on the
// Location tab — see schema.sql for the Postgres mirror). user_id scopes to the placer.
db.exec(`CREATE TABLE IF NOT EXISTS proximity_anchors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  kind TEXT NOT NULL,
  address TEXT NOT NULL,
  name TEXT,
  lat REAL NOT NULL,
  lng REAL NOT NULL,
  ref_rssi INTEGER NOT NULL,
  created_at INTEGER NOT NULL
)`).catch(() => {});
db.exec("CREATE INDEX IF NOT EXISTS idx_proximity_anchors_user ON proximity_anchors(user_id)").catch(() => {});
db.exec("CREATE INDEX IF NOT EXISTS idx_proximity_anchors_addr ON proximity_anchors(address)").catch(() => {});
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS uq_proximity_anchors_user_addr ON proximity_anchors(user_id, address)").catch(() => {});
db.exec("ALTER TABLE proximity_anchors ADD COLUMN origin TEXT DEFAULT 'manual'").catch(() => {});
// Learned cell-tower positions for cellular triangulation (see schema.sql mirror).
db.exec(`CREATE TABLE IF NOT EXISTS cell_towers (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   mcc INTEGER NOT NULL,
   mnc INTEGER NOT NULL,
   tac INTEGER NOT NULL,
   cid INTEGER NOT NULL,
   lat REAL NOT NULL,
   lng REAL NOT NULL,
   ref_dbm INTEGER NOT NULL,
   samples INTEGER NOT NULL DEFAULT 0,
   spread_m REAL NOT NULL DEFAULT 0,
   source TEXT NOT NULL DEFAULT 'learned',
   updated_at INTEGER NOT NULL
)`).catch(() => {});
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_cell_towers_key ON cell_towers(mcc, mnc, tac, cid)").catch(() => {});
// Fleet-learned tower positions (GPS votes; see voteTowerPositions). Kept ALONGSIDE the
// OpenCellID columns — never overwrites them, so OCID-vs-learned disagreement stays visible.
db.exec("ALTER TABLE cell_towers ADD COLUMN learned_lat REAL").catch(() => {});
db.exec("ALTER TABLE cell_towers ADD COLUMN learned_lng REAL").catch(() => {});
db.exec("ALTER TABLE cell_towers ADD COLUMN learned_samples INTEGER NOT NULL DEFAULT 0").catch(() => {});
db.exec("ALTER TABLE cell_towers ADD COLUMN learned_spread REAL NOT NULL DEFAULT 0").catch(() => {});
db.exec("ALTER TABLE cell_towers ADD COLUMN learned_at INTEGER NOT NULL DEFAULT 0").catch(() => {});
db.exec("ALTER TABLE cell_towers ADD COLUMN learned_snapped INTEGER NOT NULL DEFAULT 0").catch(() => {});
// Operator-placed truth (drag/click-to-move on the map). Wins over learned and OCID.
db.exec("ALTER TABLE cell_towers ADD COLUMN manual_lat REAL").catch(() => {});
db.exec("ALTER TABLE cell_towers ADD COLUMN manual_lng REAL").catch(() => {});
db.exec("ALTER TABLE cell_towers ADD COLUMN manual_at INTEGER NOT NULL DEFAULT 0").catch(() => {});
// Physical tower structures from OpenStreetMap (man_made=mast/tower/antenna). OSM knows
// WHERE steel is, not which cell ID lives on it — used to snap/validate learned positions
// and to show the nearest plausible structure, never as a cell-ID position source.
db.exec(`CREATE TABLE IF NOT EXISTS osm_masts (
   id INTEGER PRIMARY KEY AUTOINCREMENT,
   osmid TEXT NOT NULL,
   kind TEXT NOT NULL,
   lat REAL NOT NULL,
   lng REAL NOT NULL,
   tags TEXT,
   updated_at INTEGER NOT NULL
)`).catch(() => {});
db.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_osm_masts_osmid ON osm_masts(osmid)").catch(() => {});
db.exec("CREATE INDEX IF NOT EXISTS idx_osm_masts_latlng ON osm_masts(lat, lng)").catch(() => {});
// OSM tile coverage (global, on-demand). The corridor import seeded home ground, but
// devices roam: any /api/masts bbox touching an unfetched (or >90d stale) 0.5° tile
// triggers a background Overpass fetch for the missing tiles. Requests always return
// cached rows immediately (+ pending:true); the client's next refresh picks up steel.
db.exec(`CREATE TABLE IF NOT EXISTS osm_tiles (
   cell TEXT PRIMARY KEY,
   fetched_at INTEGER NOT NULL
)`).catch(() => {});
// Known WiFi AP positions (BSSID → lat/lng). Served from cache; misses resolve against
// the WiGLE wardriving database when WIGLE_API_KEY is configured (same pattern as the
// OCID tower lookups). Used as fallback anchors when no calibrated anchor is in range.
db.exec(`CREATE TABLE IF NOT EXISTS wifi_aps (
   bssid TEXT PRIMARY KEY,
   ssid TEXT,
   lat REAL NOT NULL,
   lng REAL NOT NULL,
   accuracy_m INTEGER NOT NULL DEFAULT 100,
   source TEXT NOT NULL DEFAULT 'wigle',
   updated_at INTEGER NOT NULL
)`).catch(() => {});
// Migration: add columns to existing user_alerts (SQLite -- PG uses the final schema.sql).
// db.exec() is async; use .catch() instead of try/catch to avoid silently losing rejections.
db.exec("ALTER TABLE user_alerts ADD COLUMN device_id TEXT").catch(() => {});
db.exec("ALTER TABLE user_alerts ADD COLUMN audit_result TEXT").catch(() => {});
db.exec("ALTER TABLE user_alerts ADD COLUMN proposed_fix TEXT").catch(() => {});
// USB Lockdown approval history — durable audit trail of every approve action (see schema.sql).
// The live "allowed devices" snapshot on the box is transient; this persists server-side.
try { db.exec(`CREATE TABLE IF NOT EXISTS usblock_approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  instance_id TEXT NOT NULL,
  friendly_name TEXT,
  class TEXT,
  approved_at INTEGER NOT NULL
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_usblock_approvals_device ON usblock_approvals(device_id, approved_at DESC)"); } catch {}
// Migration: vid_pid column — the vendor:product id (XXXX:XXXX) that the agent-side approved.txt
// allowlist is keyed on. Needed by the Remove button (history rows are keyed by usbguard numeric
// instance_id, which renumbers on replug, so removal must match by vid:pid instead).
try { db.exec("ALTER TABLE usblock_approvals ADD COLUMN vid_pid TEXT"); } catch (_) {}
// EDR "mark safe" — admin dismissals of individual EDR findings (see schema.sql). Annotated onto
// the /edr/events response and hidden from the default feed; never affects alerting of NEW events.
try { db.exec(`CREATE TABLE IF NOT EXISTS edr_safe_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  event_id INTEGER NOT NULL,
  rule TEXT,
  reason TEXT,
  image TEXT,
  time TEXT,
  marked_at INTEGER NOT NULL,
  UNIQUE (device_id, event_id, rule)
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_edr_safe_events_device ON edr_safe_events(device_id)"); } catch {}

// ── AI Auto-Audit on Alerts (new tables) ──
try { db.exec(`CREATE TABLE IF NOT EXISTS alert_auto_audits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  alert_id INTEGER NOT NULL,
  device_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  audit_verdict TEXT,
  ai_analysis TEXT,
  false_positive INTEGER NOT NULL DEFAULT 0,
  suppression_signature TEXT,
  alert_handled INTEGER NOT NULL DEFAULT 0,
  started_at INTEGER,
  completed_at INTEGER,
  created_at INTEGER NOT NULL
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_alert_auto_audits_device ON alert_auto_audits(device_id, created_at DESC)"); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_alert_auto_audits_alert ON alert_auto_audits(alert_id)"); } catch {}

try { db.exec(`CREATE TABLE IF NOT EXISTS device_ai_memory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  user_id TEXT NOT NULL,
  event_type TEXT NOT NULL,
  summary TEXT NOT NULL,
  ai_verdict TEXT,
  root_cause TEXT,
  action_taken TEXT,
  raw_analysis TEXT,
  created_at INTEGER NOT NULL
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_device_ai_memory_device ON device_ai_memory(device_id, created_at DESC)"); } catch {}

try { db.exec(`CREATE TABLE IF NOT EXISTS account_ai_memory (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,
  summary TEXT NOT NULL,
  created_at INTEGER NOT NULL
)`); } catch {}
try { db.exec("CREATE INDEX IF NOT EXISTS idx_account_ai_memory_user ON account_ai_memory(user_id, created_at DESC)"); } catch {}
} // end if(!isPg) — SQLite-only DDL block D

// Kick off schema readiness. On Postgres this runs schema.sql + bootstrap then
// resolves dbReady; on SQLite the inline block above already ran, so it resolves now.
bootstrapDb();

// ── Web Analytics helpers ─────────────────────────────────────────────────
const { parseUA } = require('./helpers/parse-ua')();

// Deterministic daily salt: HMAC(session_secret, 'analytics-YYYY-MM-DD').
// Rotates at UTC midnight. Survives server restarts within the same day.
const _analyticsSaltBase = readSecret('sentinel_session_secret', 'SESSION_SECRET') || 'sentinel-analytics-v1';
const { getDailySalt } = require('./helpers/get-daily-salt')({ _analyticsSaltBase, crypto });

// Bot-traffic UA classification — presentation/analytics only, NOT a security control
// (contrast the honeypot's FCrDNS-verified crawler exemption, used for actual ban decisions
// in a different stack). A legitimate search-engine crawler hitting a stale/removed URL should
// not read the same as a malicious vulnerability scanner in the "Bot Traffic" panel.
const CRAWLER_UA_SUBSTRINGS = ['googlebot', 'bingbot', 'duckduckbot', 'slurp', 'baiduspider',
  'yandexbot', 'applebot', 'facebookexternalhit', 'twitterbot', 'ahrefsbot', 'semrushbot', 'mj12bot'];
const { classifyBotUA } = require('./helpers/classify-bot-ua')({ CRAWLER_UA_SUBSTRINGS });

// Web Analytics — best-effort geo enrichment. Mirrors this file's OWN existing
// fetchChannelBuild()/_osUpstreamCache pattern (timeout-guarded fetch, try/catch -> null,
// in-process cache) applied to the free keyless ip-api.com lookup. Runs strictly AFTER the
// pageview beacon's 204 response (never adds latency / couples beacon reliability to a
// 3rd-party API). CRITICAL: `ip` is used only as the cache key + URL param below — it must
// NEVER be passed into any db.prepare(...) call, preserving web_analytics' existing
// "no raw IP retained" privacy property (only the resolved country/city strings are stored).
const GEO_LOOKUP_ENABLED = process.env.ANALYTICS_GEO_DISABLED !== '1'; // opt-out valve
const GEO_RATE_BUDGET_PER_MIN = 40; // ip-api.com free tier caps at 45/min per calling IP
const _geoCache = new Map(); // ip -> {country,city}; RAM-only, bounded, cleared past 20k entries
const { resolveGeoAndBackfill } = require('./helpers/geo-backfill')({ GEO_LOOKUP_ENABLED, GEO_RATE_BUDGET_PER_MIN, _geoCache, db, kv });

// ── Commerce / Trial helpers ────────────────────────────────────────────────
const DAY_MS     = 24 * 60 * 60 * 1000;
// NOTE: keys are stored as `trial_type` strings in the entitlements table — do NOT rename them
// (the "_7" suffix is now historical; all trials grant 30 days as of 2026-06-19).
const TRIAL_DAYS = { digital_mdm_7: 30, hardware_software_30: 30, os_flash_7: 30 };

const { daysRemaining, genLicenseKey } = require('./helpers/license-key')({ DAY_MS, crypto, getDb: () => db });

// ── Canonical policy texts ───────────────────────────────────────────────────
// The authoritative text + version for every policy a user can accept. The SHA-256 stored in
// tos_acceptances is computed from THESE strings, never from a client-supplied policy_text — a
// hash of text the client handed us only proves what the client claimed was on screen, which is
// close to worthless as evidence against a user who later disputes the agreement. Each string is
// the exact acceptance statement rendered in the UI, so the record reflects what was actually
// shown. The full agreements live at the linked URLs and must be published at an IMMUTABLE
// versioned path — editing a document in place silently invalidates every prior hash.
// ⚠️ Changing any text here REQUIRES bumping that key's version. Same text + same version is what
// makes a record reproducible; mutating text under a fixed version breaks every earlier row.
const POLICY_TEXTS = {
  msa: { version: '1', text:
    `Master Service Agreement v1, ${PUBLIC_SITE_URL}/legal/msa — `
    + 'I have read and agree to the Master Service Agreement, the Terms of Service, and the Privacy Policy.' },
  // v2 (2026-08-03) removed the "continued use constitutes acceptance" browsewrap clause from
  // section 9 and replaced it with explicit versioned re-acceptance, matching MSA v1 section 19.2.
  // v1 is frozen at {PUBLIC_SITE_URL}/legal/terms-v1 — rows already recorded against v1 keep
  // their own hash and stay reproducible, which is the entire reason superseded versions are
  // archived rather than edited in place.
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

const { recordPolicyAcceptances, recordTosAcceptance } = require('./helpers/policy-accept')({ POLICY_TEXTS, crypto, db, log, reqClientIp });

// Prepared statements for trial hot-paths.
// ── Prepared statements (extracted to statements.js) ────────────────────────
const createStatements = require('./statements');
const { trialStmts, shopStmts, supportStmts, guestStmts, stmts } = createStatements(db);
const { _canSendUserNotif, surveilNotify, maybeAlertTrialLapse, genRef, getOrCreateThread, supportMsgOut, isValidWrapEnvelope, _isWrapObj, parseEncMsg, actingUserRow, staffZkLoginFields, buildSupportContext, getSmtpConfigFn, saveSmtpConfig, getEmailTemplate, saveEmailTemplate, notifyOwnerForCommand } = require('./helpers/support-user-notif-helpers')({ USER_NOTIFY_COMMANDS, db, decryptText, emailTemplates, encryptText, log, notifyAdmin, notifyUser, randomUUID, stmts, supportStmts, svc });

// ── Phase-2 init: shared helpers that need stmts (not available at bootstrap) ──
const DEMO_DEVICE_TABLES = ['locations', 'media', 'network_events', 'call_logs', 'sms_messages', 'app_lists', 'notifications'];
const createDeviceHelpers = require('./services/device-helpers');
const deviceHelpers = createDeviceHelpers({ db, DEMO_DEVICE_TABLES, deviceStatus, encryptText, kv, log, stmts });
const { demoWifiCurrent, demoStatusPayload, createDemoDeviceForUser, removeDemoDeviceForUser,
  ALL_ROWS, zkRowLimit, maybeRespondWithZkPayloads,
  EDR_ALERT_SUPPRESS_MS, getEdrEnabled, setEdrEnabled, getEdrIsolated, setEdrIsolated,
  getEdrLastSeen, setEdrLastSeen, getEdrAlertSuppressedUntil, setEdrAlertSuppressedUntil } = deviceHelpers;

// ── Migrate flat permissions → device-scoped permissions ───────────────────
// Old format: { "location": true, "photos": false, ... }
// New format: { "<deviceId>": { "location": true, ... }, ... }
(async function migratePermissions() {
  await dbReady;
  const PERM_KEYS = ['location','photos','audio','network','files','calls','sms','apps','stream','screenshots','commands'];
  const devices = (await stmts.allDevices.all());
  if (!devices.length) return;
  const users = (await stmts.allUsers.all());
  let count = 0;
  for (const u of users) {
    const permsStr = u.permissions || '{}';
    if (permsStr.startsWith('ENC:')) continue; // encrypted — handled after unlock in runMigration
    const raw = JSON.parse(permsStr);
    const isOldFormat = PERM_KEYS.some(k => k in raw && typeof raw[k] === 'boolean');
    if (!isOldFormat) continue;
    const newPerms = {};
    for (const d of devices) {
      newPerms[d.id] = {};
      for (const k of PERM_KEYS) newPerms[d.id][k] = !!raw[k];
    }
    (await stmts.updateUserPerms.run(JSON.stringify(newPerms), u.id));
    count++;
  }
  if (count) log('info', `Migrated ${count} user(s) to device-scoped permissions`);
})();

// ── Device key authentication helpers ─────────────────────────────────────

const { authenticateDeviceRequest, runMigration, verifyDeviceSignature, verifyWithPublicKey } = require('./helpers/device-signature.js')({ ENC_MAGIC, PUBLIC_USER_DEFAULT_FEATURES, createDemoDeviceForUser, crypto, decryptText, encryptBuffer, encryptText, fs, getDb: () => db, getNormIdent: (s) => normIdent(s), getSha256hex: (s) => sha256hex(s), log, notifyAdmin, path, stmts, uploadsDir });

// ── NOWPayments crypto billing ────────────────────────────────────────────────
const NOWPAYMENTS_API_KEY    = readSecret('nowpayments_api_key',    'NOWPAYMENTS_API_KEY');
const NOWPAYMENTS_IPN_SECRET = readSecret('nowpayments_ipn_secret', 'NOWPAYMENTS_IPN_SECRET');
// USD price per period for each plan (crypto = one-time prepaid, no auto-renewal).
// Per-device plans (Per Device $3/device, Hybrid Managed $15/device) are billed as
// usd × device-count — the checkout endpoints multiply by the requested `devices` count
// and encode it in the order SKU (`plan:devices`) so the IPN can materialize the right
// device slots. 5 Devices entries are kept for legacy pending orders only.
const CRYPTO_PLAN_PRICES = {
  '1device_monthly':   { usd: 14.99,  label: 'SentinelMDM FamilySafe 5 Devices — 1 Month'   },
  '1device_annual':    { usd: 149.90, label: 'SentinelMDM FamilySafe 5 Devices — 1 Year'    },
  'unlimited_monthly': { usd: 3,      label: 'SentinelMDM Per Device — 1 Month'             },
  'unlimited_annual':  { usd: 30,     label: 'SentinelMDM Per Device — 1 Year'              },
  'hybrid_monthly':    { usd: 15,     label: 'SentinelMDM Hybrid Managed — Per Device, 1 Month' },
  'hybrid_annual':     { usd: 150,    label: 'SentinelMDM Hybrid Managed — Per Device, 1 Year'  },
};
// A confirmed crypto payment is prepaid + one-time (no auto-renew), so it can't live in the
// `subscriptions` table the way a Stripe sub does. Instead we materialize the paid period as a
// fixed-window complimentary ("comp") entitlement on the users row — which userHasActiveSubscription
// / trialLockState / runTrialSweep already honor — so the buyer is exempt from the trial lock + 48h
// auto-wipe for exactly the period they paid for. Maps the order SKU → { comp plan, period months }.
// Per-device SKUs arrive as `plan:devices` — grantCryptoCompForOrder parses the suffix and writes
// the device-slot settings row so the comp's cap = devices (not unlimited).
const CRYPTO_SKU_COMP = {
  '1device_monthly':   { plan: '1device',   months: 1  },
  '1device_annual':    { plan: '1device',   months: 12 },
  'unlimited_monthly': { plan: 'unlimited', months: 1  },
  'unlimited_annual':  { plan: 'unlimited', months: 12 },
  'hybrid_monthly':    { plan: 'hybrid', months: 1  },
  'hybrid_annual':     { plan: 'hybrid', months: 12 },
};
if (!NOWPAYMENTS_API_KEY) log('warn', 'NOWPayments not configured (no nowpayments_api_key) — crypto checkout disabled');

// ── Stripe billing (subscriptions + 30-day trial) ─────────────────────────────
// ── Stripe mode: STRIPE_TEST_MODE=1 swaps in test-mode keys + prices so the in-app
// subscription flow can be exercised with test cards (4242...) without real charges.
// Env-driven; prod must stay 0/absent. When flipping, keep the OTHER keys consistent
// (test webhook secret is optional — with it unset, test webhooks are rejected and the
// direct upsert in create-payment is what mirrors the subscription into the DB).
const STRIPE_TEST_MODE = process.env.STRIPE_TEST_MODE === '1';
const STRIPE_SECRET_KEY = STRIPE_TEST_MODE
  ? readSecret('stripe_test_secret_key', 'STRIPE_TEST_SECRET_KEY', '')
  : readSecret('stripe_secret_key', 'STRIPE_SECRET_KEY');
const STRIPE_WEBHOOK_SECRET = STRIPE_TEST_MODE
  ? readSecret('stripe_test_webhook_secret', 'STRIPE_TEST_WEBHOOK_SECRET', '')
  : readSecret('stripe_webhook_secret', 'STRIPE_WEBHOOK_SECRET');
const STRIPE_PUBLISHABLE_KEY = STRIPE_TEST_MODE
  ? readSecret('stripe_test_publishable_key', 'STRIPE_TEST_PUBLISHABLE_KEY', '')
  : readSecret('stripe_publishable_key', 'STRIPE_PUBLISHABLE_KEY', '');
const STRIPE_TRIAL_DAYS     = parseInt(process.env.STRIPE_TRIAL_DAYS || '30', 10);
// Per-account FREE trial (app-managed; the clock starts on the account's first device connect).
// This is the ONLY free trial — the marketing site offers trial signup only; paying happens in the
// dashboard. After it expires with no subscription: lock+warn for 48h, then auto-wipe the account.
const TRIAL_DAYS_ACCOUNT  = parseInt(process.env.TRIAL_DAYS || '30', 10);   // 30-day free trial
const TRIAL_WIPE_GRACE_MS = 48 * 60 * 60 * 1000;                            // wipe this long after expiry
// Device cap for free-trial / no-live-paid-subscription accounts. The paid "1 Device" plan stays at
// 1 (see deviceLimitForUser); the free trial gets this more generous cap — 10, matching the device
// count the Hybrid Managed base tier includes, so a trial can realistically evaluate a full fleet.
// Env-overridable.
const TRIAL_DEVICE_LIMIT  = parseInt(process.env.TRIAL_DEVICE_LIMIT || '10', 10);

// ── Storage quota (public accounts) ────────────────────────────────────────────
// 1 GB cap per account. New media (photos, audio, screenshots, screen captures,
// recordings) is blocked when the account is at or over this limit. The quota is
// calculated on-demand by summing storage across the media, files, zk_payloads,
// and applocker_blocked_files tables for every device owned by the user.
const STORAGE_QUOTA_BYTES = parseInt(process.env.STORAGE_QUOTA_BYTES || '21474836480', 10);  // 20 GB
const { calculateStorageBytes, checkStorageQuota } = require('./helpers/storage-quota')({ STORAGE_QUOTA_BYTES, db });

// Stripe plan key -> price ID. Configure via STRIPE_PRICE_* environment variables or
// Docker secrets; empty values disable billing until you supply your own prices.
const STRIPE_PLANS = {
  'unlimited_monthly': readSecret('stripe_price_unlimited_monthly', 'STRIPE_PRICE_UNLIMITED_MONTHLY', ''),
  'unlimited_annual':  readSecret('stripe_price_unlimited_annual',  'STRIPE_PRICE_UNLIMITED_ANNUAL',  ''),
  'hybrid_monthly':    readSecret('stripe_price_hybrid_monthly',    'STRIPE_PRICE_HYBRID_MONTHLY',    ''),
  'hybrid_annual':     readSecret('stripe_price_hybrid_annual',     'STRIPE_PRICE_HYBRID_ANNUAL',     ''),
};
const HYBRID_INCLUDED_DEVICES    = 1;
const HYBRID_EXTRA_DEVICE_AMOUNT = 1500;
const HYBRID_EXTRA_DEVICE_PRICE  = readSecret('stripe_price_hybrid_extra_device', 'STRIPE_PRICE_HYBRID_EXTRA_DEVICE', '');
const HYBRID_EXTRA_DEVICE_ANNUAL_PRICE = readSecret('stripe_price_hybrid_extra_device_annual', 'STRIPE_PRICE_HYBRID_EXTRA_DEVICE_ANNUAL', '');
const HYBRID_LEGACY_EXTRA_DEVICE_PRICE  = process.env.STRIPE_PRICE_HYBRID_LEGACY_EXTRA_DEVICE || '';
const HYBRID_LEGACY9_EXTRA_DEVICE_PRICE = process.env.STRIPE_PRICE_HYBRID_LEGACY9_EXTRA_DEVICE || '';
const UNLIMITED_INCLUDED_DEVICES    = 1;
const UNLIMITED_EXTRA_DEVICE_AMOUNT = 300;
const UNLIMITED_EXTRA_DEVICE_PRICE  = readSecret('stripe_price_unlimited_extra_device', 'STRIPE_PRICE_UNLIMITED_EXTRA_DEVICE', '');
const UNLIMITED_EXTRA_DEVICE_ANNUAL_PRICE = readSecret('stripe_price_unlimited_extra_device_annual', 'STRIPE_PRICE_UNLIMITED_EXTRA_DEVICE_ANNUAL', '');
const THREE_DEVICE_EXTRA_AMOUNT = 500;
const THREE_DEVICE_EXTRA_PRICE  = readSecret('stripe_price_3device_extra', 'STRIPE_PRICE_3DEVICE_EXTRA', '');
const HYBRID_LEGACY_PRICE = process.env.STRIPE_PRICE_HYBRID_LEGACY || '';
const HYBRID_FLAT_LEGACY_PRICES = new Set(csvEnv('STRIPE_PRICE_HYBRID_FLAT_LEGACY'));
const UNLIMITED_LEGACY_MONTHLY_PRICE = process.env.STRIPE_PRICE_UNLIMITED_LEGACY_MONTHLY || '';
const UNLIMITED_LEGACY_ANNUAL_PRICE  = process.env.STRIPE_PRICE_UNLIMITED_LEGACY_ANNUAL || '';
const UNLIMITED_FLAT_LEGACY_PRICES = new Set(csvEnv('STRIPE_PRICE_UNLIMITED_FLAT_LEGACY'));
const ONEDEVICE_LEGACY_PRICES = new Set(csvEnv('STRIPE_PRICE_ONEDEVICE_LEGACY'));
// Keyed by Stripe price id; skip any plan whose price id is unset (e.g. hybrid_monthly before its
// Stripe price exists) so an empty-string key can't collide across plans.
const PLAN_META = {};
for (const [planKey, meta] of [
  ['unlimited_monthly', { label: 'Per Device',      amount: 300,    interval: 'month' }],
  ['unlimited_annual',  { label: 'Per Device',      amount: 3000,   interval: 'year'  }],
  ['hybrid_monthly',    { label: 'Hybrid Managed',  amount: 1500,   interval: 'month' }],
  ['hybrid_annual',     { label: 'Hybrid Managed',  amount: 15000,  interval: 'year'  }],
]) {
  const pid = STRIPE_PLANS[planKey];
  if (pid) PLAN_META[pid] = meta;
}
// Legacy flat prices — resolvable so existing subscribers still see their plan + cap correctly.
if (HYBRID_LEGACY_PRICE)
  PLAN_META[HYBRID_LEGACY_PRICE] = { label: 'Hybrid Managed (legacy)', amount: 9999, interval: 'month' };
if (UNLIMITED_LEGACY_MONTHLY_PRICE)
  PLAN_META[UNLIMITED_LEGACY_MONTHLY_PRICE] = { label: 'Unlimited (legacy)', amount: 2499, interval: 'month' };
if (UNLIMITED_LEGACY_ANNUAL_PRICE)
  PLAN_META[UNLIMITED_LEGACY_ANNUAL_PRICE]  = { label: 'Unlimited (legacy)', amount: 24990, interval: 'year' };
const stripe = STRIPE_SECRET_KEY ? require('stripe')(STRIPE_SECRET_KEY) : null;
if (!stripe) log('warn', 'Stripe not configured (no stripe_secret_key / STRIPE_SECRET_KEY) — checkout & cancel disabled');
const { invalidPlanMessage } = require('./helpers/invalid-plan-message')();

const { hasSupportAccessGranted } = require('./helpers/has-support-access-granted')({ db });
const HYBRID_REQUIRES_SUPPORT_ACCESS_MSG =
  'Hybrid Managed requires support access first. Click the 🛟 life-preserver icon in the top toolbar, ' +
  'choose "Grant support access," then come back here and subscribe.';

const PLAN_KEY_BY_PRICE = Object.fromEntries(Object.entries(STRIPE_PLANS).filter(([, v]) => v).map(([k, v]) => [v, k]));
// Legacy flat prices resolve to the same plan keys so caps/labels keep working for
// grandfathered subscribers (deviceLimitForUser distinguishes flat vs per-device by price id).
for (const pid of HYBRID_FLAT_LEGACY_PRICES) PLAN_KEY_BY_PRICE[pid] = 'hybrid_monthly';
for (const pid of UNLIMITED_FLAT_LEGACY_PRICES) PLAN_KEY_BY_PRICE[pid] = 'unlimited_monthly';
// 5 Devices legacy: monthly → '1device_monthly', annual → '1device_annual' (business-mode
// qualification is annual-sensitive, so the two must resolve to their original keys).

const { compSlotRow, hybridExtraDevices, slotRowCount, threeDeviceExtraDevices, unlimitedExtraDevices } = require('./helpers/extra-device-slots')({ db });

// Admin-granted complimentary ("comp") subscription plans. A comp is a FREE override an admin
// applies to a public account (see compPlanFor() / the /api/users/:id/comp-sub routes): the
// account is treated as if it held a live paid plan — exempt from the trial lock + 48h auto-wipe,
// with its device cap set by the plan. 'unlimited'/'hybrid' = per-device (cap = device slots on
// the account, or unlimited for admin comps with no slot row); '1device' caps at 5 (+ extra slots).
const COMP_PLANS = new Set(['unlimited', '1device', 'hybrid']);
const COMP_PLAN_LABEL = {
  unlimited: 'Per Device (complimentary)', '1device': '5 Devices (complimentary)',
  hybrid: 'Hybrid Managed (complimentary)',
};

const { getUserSubscriptionRow, sessionUserEmail, stripeSubOut, upsertStripeSubscription } = require('./helpers/stripe-subscription')({ HYBRID_EXTRA_DEVICE_ANNUAL_PRICE, HYBRID_EXTRA_DEVICE_PRICE, HYBRID_LEGACY9_EXTRA_DEVICE_PRICE, HYBRID_LEGACY_EXTRA_DEVICE_PRICE, PLAN_KEY_BY_PRICE, PLAN_META, THREE_DEVICE_EXTRA_PRICE, UNLIMITED_EXTRA_DEVICE_ANNUAL_PRICE, UNLIMITED_EXTRA_DEVICE_PRICE, db, decryptText });

// Stripe webhook (raw body, above express.json) — routes/stripe-webhook.js
require('./routes/stripe-webhook')({ app, STRIPE_WEBHOOK_SECRET, express, log, notifyAdminForUser, sendPurchaseEmail, stripe, upsertStripeSubscription });

app.use(express.json({ limit: '150mb' }));
// Session store: Redis (shared across replicas) when REDIS_URL is set, else the
// SQLite store for single-instance/offline use. The session secret MUST be shared
// across replicas — a per-replica random secret makes cookies fail on other replicas.
const _sessSecret = readSecret('sentinel_session_secret', 'SESSION_SECRET');
if (redisEnabled && !_sessSecret)
  log('warn', 'Multi-replica mode but sentinel_session_secret is unset — sessions will NOT validate across replicas. Set the secret.');
const sessionStore = redisEnabled
  ? new (require('connect-redis').default)({ client: redisClient, prefix: 'sess:' })
  : new SqliteStore({ client: db });
const sessionMiddleware = session({
  store: sessionStore,
  secret: _sessSecret || randomUUID(),
  resave: false,
  saveUninitialized: false,
  // Production default: secure + strict (HTTPS only). Local HTTP debugging sets
  // COOKIE_INSECURE=1 so the cookie is sent over http://localhost; production is
  // unchanged unless that env var is explicitly present.
  cookie: { httpOnly: true,
            secure:   process.env.COOKIE_INSECURE === '1' ? false : true,
            sameSite: process.env.COOKIE_INSECURE === '1' ? 'lax' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 }
});
app.use(sessionMiddleware);
// Make session available to Socket.IO so the session cookie can be used as
// a fallback auth method — survives container restarts without page refresh.
io.engine.use(sessionMiddleware);

// CSRF: reject cross-origin state-changing requests from authenticated sessions.
// Origin/Referer are set by browsers on all cross-origin requests; native device
// clients (OkHttp, no browser) don't set them so this check is safely skipped.
app.use((req, res, next) => {
  if (!['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) return next();
  if (!req.session?.authenticated) return next();
  const check = req.headers.origin || req.headers.referer;
  if (!check) return next();
  try {
    if (new URL(check).host !== req.headers.host)
      return res.status(403).json({ error: 'CSRF check failed' });
  } catch {
    return res.status(403).json({ error: 'CSRF check failed' });
  }
  next();
});

// ── Block web UI on device subdomain ──────────────────────────────────────
const DEVICE_HOST = process.env.DEVICE_HOST || '';
app.use((req, res, next) => {
  if (!DEVICE_HOST || req.hostname !== DEVICE_HOST) return next();
  if (req.path.startsWith('/socket.io/') || req.path.startsWith('/api/')) return next();
  res.redirect(301, `${SERVER_ORIGIN}${req.path}`);
});

// ── Health endpoint — before requireUnlocked so Swarm can probe during boot ──
app.get('/health', (_req, res) => {
  if (serverUnlocked) return res.json({ ok: true });
  res.status(503).json({ ok: false, reason: 'locked' });
});

// CSP violation report intake — routes/csp-violation-report.js
require('./routes/csp-violation-report')({ app, express, log, makeRateLimit });

// ── Unlock middleware & routes ─────────────────────────────────────────────
const unlockRateLimit = makeRateLimit(5, 15 * 60 * 1000, 'unlock');
const STATIC_EXT_RE  = /\.(js|mjs|css|png|jpg|jpeg|ico|svg|woff2?|ttf|map|webmanifest|json|txt)$/i;

const { requireUnlocked } = require('./helpers/require-unlocked.js')({ STATIC_EXT_RE, getServerUnlocked: () => serverUnlocked });

// Sleep-check + bastion internal RA access — routes/sleep-check-and-internal-ra-access.js
require('./routes/sleep-check-and-internal-ra-access')({ app, authenticateDeviceRequest, db, deviceOwnerInfo, express });

app.use(requireUnlocked);

// Unlock passphrase page (GET /unlock) — routes/unlock-page.js
require('./routes/unlock-page')({ app, sendAuthPage });

app.get('/api/unlock-pubkey', async (_req, res) => {
  if (!_unlockKeyPair) return res.status(503).json({ error: 'Key not ready' });
  const jwk = await crypto.webcrypto.subtle.exportKey('jwk', _unlockKeyPair.publicKey);
  res.json(jwk);
});

app.post('/api/unlock', unlockRateLimit, async (req, res) => {
  let passphrase;
  if (req.body.encryptedPassphrase) {
    if (!_unlockKeyPair) return res.status(503).json({ error: 'Encryption key not ready — retry in a moment' });
    try {
      const buf = Buffer.from(req.body.encryptedPassphrase, 'base64');
      const dec = await crypto.webcrypto.subtle.decrypt({ name: 'RSA-OAEP' }, _unlockKeyPair.privateKey, buf);
      passphrase = new TextDecoder().decode(dec);
    } catch {
      return res.status(400).json({ error: 'Decryption failed' });
    }
  } else {
    passphrase = req.body.passphrase;
  }
  if (!passphrase) return res.status(400).json({ error: 'Passphrase required' });
  const sentinelRow   = (await db.prepare(`SELECT value FROM settings WHERE key='enc_sentinel'`).get());
  const saltRow       = (await db.prepare(`SELECT value FROM settings WHERE key='enc_salt'`).get());
  const iterationsRow = (await db.prepare(`SELECT value FROM settings WHERE key='enc_iterations'`).get());
  // Fresh install → 600k. Existing install without stored count → 100k (backward compat).
  const iterations = iterationsRow ? parseInt(iterationsRow.value) : (sentinelRow ? 100_000 : 600_000);
  const result = tryUnlock(passphrase, sentinelRow?.value || null, saltRow?.value || null, iterations);
  if (!result) {
    (await signalAlert('🔴 Failed Unlock Attempt', 'Wrong encryption passphrase entered', req));
    return res.status(401).json({ error: 'Wrong passphrase' });
  }
  ENC_KEY = result.key;
  require('./state').ENC_KEY = ENC_KEY;
  serverUnlocked = true;
  require('./state').serverUnlocked = true;   // keep state.js's accessor in sync (see known-behavior-losses #5)
  if (result.firstRun) {
    const newSalt = crypto.randomBytes(32).toString('base64');
    // result.key was derived with the DEFAULT salt (storedSalt was null on first
    // run). Re-derive with the salt we are about to persist BEFORE writing the
    // sentinel, or subsequent unlocks (which use the stored salt) won't match.
    ENC_KEY = deriveKey(passphrase, newSalt, iterations);
    require('./state').ENC_KEY = ENC_KEY;
    (await db.prepare(`INSERT INTO settings (key,value) VALUES ('enc_salt',?)`).run(newSalt));
    (await db.prepare(`INSERT INTO settings (key,value) VALUES ('enc_iterations',?)`).run(String(iterations)));
    (await db.prepare(`INSERT INTO settings (key,value) VALUES ('enc_sentinel',?)`).run(encryptText('SentinelMDM-unlock-v1')));
    log('info', `Encryption passphrase configured (first run, ${iterations} PBKDF2 iterations)`);
  } else {
    log('info', `Server unlocked via web UI (${iterations} PBKDF2 iterations)`);
  }
  (await runMigration());
  scheduleCleanup();
  // Notify any devices that connected before unlock so they re-register now.
  // Local devices + (multi-replica) ask peer replicas to re-register theirs too.
  for (const [, sock] of io.sockets.sockets) {
    if (sock.isDevice) deviceEmit(sock, 'please_register', {});
  }
  if (redisEnabled) io.serverSideEmit('please-register-all');
  res.json({ ok: true });
});

// ── Re-key (change encryption passphrase) ─────────────────────────────────

const { _reEncryptBuffer, _reEncryptText } = require('./helpers/re-encrypt')({ ENC_MAGIC, crypto });

app.post('/api/admin/rekey', async (req, res) => {
  if (!req.session?.authenticated) return res.status(401).json({ error: 'Not authenticated' });
  if (req.session?.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  if (!ENC_KEY) return res.status(503).json({ error: 'Server not unlocked' });

  // Decrypt new passphrase (RSA-encrypted from browser, same key as unlock form)
  let newPassphrase;
  if (req.body.encryptedNewPassphrase) {
    if (!_unlockKeyPair) return res.status(503).json({ error: 'RSA key not ready — retry' });
    try {
      const buf = Buffer.from(req.body.encryptedNewPassphrase, 'base64');
      const dec = await crypto.webcrypto.subtle.decrypt({ name: 'RSA-OAEP' }, _unlockKeyPair.privateKey, buf);
      newPassphrase = new TextDecoder().decode(dec);
    } catch { return res.status(400).json({ error: 'Decryption failed' }); }
  } else {
    newPassphrase = req.body.newPassphrase;
  }
  if (!newPassphrase || newPassphrase.length < 8)
    return res.status(400).json({ error: 'New passphrase must be at least 8 characters' });

  const oldKey   = ENC_KEY;
  const newSalt  = crypto.randomBytes(32).toString('base64');
  const newIter  = 600_000;
  const newKey   = crypto.pbkdf2Sync(newPassphrase, Buffer.from(newSalt, 'base64'), newIter, 32, 'sha256');

  // 1. Re-key R2 objects before touching the DB (still on old key)
  let r2Done = 0, r2Fail = 0;
  try {
    const keys = await r2List('');
    for (const k of keys) {
      try {
        const raw = await r2Get(k);
        if (!raw) continue;
        const rekeyed = _reEncryptBuffer(raw, oldKey, newKey);
        await r2Put(k, rekeyed);
        r2Done++;
      } catch { r2Fail++; }
    }
  } catch (e) { log('warn', 'rekey: R2 list failed:', e.message); }

  // 2. Re-key all DB encrypted columns in a single transaction
  const COLS = [
    { table: 'devices',        cols: ['name','model','android_version','last_lat','last_lng'] },
    { table: 'locations',      cols: ['data'] },
    { table: 'media',          cols: ['data'] },
    { table: 'network_events', cols: ['data'] },
    { table: 'call_logs',      cols: ['data'] },
    { table: 'sms_messages',   cols: ['data'] },
    { table: 'app_lists',      cols: ['data'] },
    { table: 'files',          cols: ['remote_path'] },
    { table: 'users',          cols: ['permissions'] },
    { table: 'keylog_entries',      cols: ['data'] },
    { table: 'screen_text_entries', cols: ['data'] },
  ];
  let dbRows = 0;
  (await db.transaction(async () => {
    for (const { table, cols } of COLS) {
      const rows = (await db.prepare(`SELECT rowid,${cols.join(',')} FROM ${table}`).all());
      const upd  = db.prepare(`UPDATE ${table} SET ${cols.map(c => `${c}=?`).join(',')} WHERE rowid=?`);
      for (const row of rows) {
        (await upd.run(...cols.map(c => _reEncryptText(row[c], oldKey, newKey)), row.rowid));
        dbRows++;
      }
    }
    // Update salt and iterations; sentinel is regenerated below with new key
    (await db.prepare(`UPDATE settings SET value=? WHERE key='enc_salt'`).run(newSalt));
    (await db.prepare(`UPDATE settings SET value=? WHERE key='enc_iterations'`).run(String(newIter)));
    (await db.prepare(`DELETE FROM settings WHERE key='enc_sentinel'`).run());
  })());

  // 3. Activate new key and write new sentinel
  ENC_KEY = newKey;
  require('./state').ENC_KEY = ENC_KEY;
  (await db.prepare(`INSERT INTO settings (key,value) VALUES ('enc_sentinel',?)`).run(encryptText('SentinelMDM-unlock-v1')));

  log('info', `Re-key complete — DB rows: ${dbRows}, R2 ok: ${r2Done}, R2 fail: ${r2Fail}`);
  res.json({ ok: true, dbRows, r2Done, r2Fail });
});

// ── Auth middleware ────────────────────────────────────────────────────────

const { isLoopbackPeer } = require('./helpers/is-loopback-peer')();

// ── Support delegate: LIVE permission map (never the grant-time snapshot) ────────────────────
// POST /api/account/support-access snapshots the owner's device list into the delegate's stored
// `permissions` blob. For a TEAM sub-user that snapshot is the whole point (a curated per-device
// grant); for the support delegate it is a bug — the delegate is defined as FULL access to every
// device the owner owns, so a device enrolled after the grant was invisible to the delegate AND
// to an admin impersonating it. Found live 2026-08-03: an owner with 5 devices rendered only the
// 2 that existed when support access was granted.
//
// Resolved here, in the one middleware every authenticated route passes through, rather than at
// each session-load site — so it holds no matter which login path built the session (password,
// TOTP, passkey, impersonation) and picks up a device enrolled MID-session without a re-login.
// Assigning the map back onto req.session is what makes the ~12 downstream `session.permissions`
// gates (/api/devices, requirePerm, requireDeviceAccess, the inline blob checks, subscribe_monitor)
// correct with no change to any of them. `resave:false` means an identical-content reassignment
// does NOT write the session store — only a real device-set change costs a write.
//
  // Membership is read from the DB, not a session flag, so it cannot go stale or be missed by a
  // login path that forgot to set it. Revocation is unaffected by the cache: DELETE support-access
  // removes the user row AND calls revokeUserSessions(), so a revoked delegate never reaches here.
  // The session flag below is set from the same DB read so endpoints checking
  // req.session.is_support_delegate (storage meter, wipe-media) work even for sessions
  // created before the flag existed at login — self-heals without requiring re-login.
const _supportDelegateCache = new Map();   // userId -> { ts, isDelegate, perms }
const SUPPORT_DELEGATE_PERMS_TTL_MS = 15000;

const { applySupportDelegatePerms } = require('./helpers/support-delegate-perms')({ SUPPORT_DELEGATE_PERMS_TTL_MS, _supportDelegateCache, getDb: () => db, getSupportDelegateFullPerms: () => SUPPORT_DELEGATE_FULL_PERMS });

// Unauthenticated-access alert gate: one alert per (path, IP) per window, so a polling
// client with an orphaned session (each server restart destroys sessions — the phone app's
// dashboard keeps 401ing every 10s until re-login) can't page on every request. Same
// Redis-backed, shared-across-replicas pattern as geofenceAlertDue; entries are pruned on
// write so a scanner hitting many paths can't bloat the record.
const UNAUTH_ALERT_COOLDOWN_MS = 30 * 60 * 1000;   // 30 min per path+IP
const _unauthAlertFallback = new Map();            // per-process fallback if Redis is unavailable
const { unauthAlertDue } = require('./helpers/unauth-alert-due')({ UNAUTH_ALERT_COOLDOWN_MS, _unauthAlertFallback, kv });

// Only page for unauthenticated requests that map to a real route. Bots spray junk paths
// (/.env, /wp-login.php, /Alvin9999/https/<url>, /officialsite) at every public host; the
// catch-all auth redirect makes them look identical to a real access attempt, but paging on
// internet noise is useless. Real routes still alert; unknown paths get a local log line.
// The pattern list is built once from Express's route layers, so new routes are covered
// automatically. (/login and /admin/login register before requireAuth and stay public, so
// they never reach this check.)
let _realPathRegexes = null;
const { requireAuth, requireAdmin } = require('./helpers/auth-middleware.js')({ STATIC_EXT_RE, applySupportDelegatePerms, getRealPathRegexes: () => _realPathRegexes, getServerGeneration: () => serverGeneration, isLoopbackPeer, log, reqClientIp, setRealPathRegexes: (v) => { _realPathRegexes = v }, setServerGeneration: (v) => { serverGeneration = v }, signalAlert, unauthAlertDue });

// ── Manual session-generation rotation (force global logout) ───────────────
// Bumps the persisted serverGeneration to a new value. requireAuth() rejects every
// session stamped with the OLD generation on its next request (destroys it and
// redirects to /login), so this logs out all currently-authenticated users —
// WebUI tabs and monitor-APK WebViews alike. The calling admin's session is
// re-stamped so they stay in. Use after a breaking schema migration, compromised
// credentials, or any other incident requiring a global re-login. On the next
// restart the new generation is reused, so this does NOT re-trigger on boot.
app.post('/api/admin/rotate-session-generation', requireAdmin, async (req, res) => {
  const next = Date.now();
  try {
    await db.prepare("INSERT INTO settings (key,value) VALUES ('server_generation',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(String(next));
  } catch (e) {
    log('warn', 'Failed to persist rotated server_generation — generation will reset on next boot', { err: e.message });
    return res.status(500).json({ error: 'Failed to persist new generation' });
  }
  serverGeneration = next;
  if (req.session) req.session.serverGeneration = next;  // keep the calling admin signed in
  log('info', 'Session generation rotated — all other sessions invalidated', { generation: next });
  res.json({ ok: true, generation: next, note: 'All other sessions will be logged out on their next request' });
});

const { BUSINESS_MODE_QUALIFYING_PLANS } = require('./helpers/business-mode-plans')();
const { compPlanFor, compSubInfo, userHasActiveSubscription } = require('./helpers/comp-subscription')({ COMP_PLAN_LABEL, db, decryptText });
const { TRIAL_LEN_MS } = require('./helpers/trial-len-ms')({ TRIAL_DAYS_ACCOUNT });
const { trialInfo } = require('./helpers/trial-info')({ TRIAL_LEN_MS });
const { businessModeQualifies, trialLockState } = require('./helpers/business-mode')({ BUSINESS_MODE_QUALIFYING_PLANS, PLAN_KEY_BY_PRICE, TRIAL_WIPE_GRACE_MS, compPlanFor, decryptText, getDb: () => db, trialInfo, userHasActiveSubscription });
const { requireDeviceAccess, requirePerm } = require('./helpers/device-access')({ db, trialLockState });


const { deviceOwnerEmail } = require('./helpers/device-owner-email')({ db, decryptText, deviceOwnerInfo });

// Short-lived cache for deviceOwnerInfo — a DB round-trip on every mouse/keyboard event
// in the Live Desktop control loop adds ~20-50 ms per event. 1 s TTL keeps ownership
// changes visible within one second while collapsing rapid-fire injection commands.
const _devinfoCache = new Map();
const { cachedDeviceOwnerInfo } = require('./helpers/cached-device-owner-info')({ _devinfoCache, deviceOwnerInfo });

const { requireDeviceController } = require('./helpers/require-device-controller')({ deviceOwnerInfo });

const { preloginFakeSeed } = require('./helpers/prelogin-fake-seed')({ crypto, db, getPreloginSeedPromise: () => _preloginSeedPromise, setPreloginSeedPromise: (v) => { _preloginSeedPromise = v } });
// ════ Login routes (prelogin + admin login + TOTP) — routes/login.js ════
require('./routes/login')({ app, db, decryptText, log, makeRateLimit, notifyAdmin,
  notifyAdminLogin, notifyAdminLoginNodeRed, notifyUser, sendLoginNotificationEmail,
  signalAlert, stmts, totpRateLimit, verifyUserPassword, ADMIN_USER, TOTP_SECRET,
  loginRateLimit, session, ensureAuthSalt, AUTH_SCHEME_PREHASH, AUTH_PREHASH_ITER,
  preloginFakeSeed, sendAuthPage, staffZkLoginFields, crypto, bcrypt,
  getServerGeneration: () => serverGeneration, regenSession });
// ════ Device-side ADMIN/SUB login — routes/device-login.js ════
require('./routes/device-login')({ app, ADMIN_USER, TOTP_SECRET, db, decryptText, log,
  loginRateLimit, notifyAdminLogin, notifyAdminLoginNodeRed, notifyUser,
  sendLoginNotificationEmail, signalAlert, stmts, totpRateLimit, verifyUserPassword,
  session, crypto, getServerGeneration: () => serverGeneration, regenSession });
// ════ Passkeys / WebAuthn — routes/passkeys.js ════
require('./routes/passkeys')({ app, ADMIN_USER, QRCode, TOTP_SECRET, actingUserRow,
  db, decryptText, log, loginRateLimit, makeRateLimit, notifyAdminLogin, path, requireAuth,
  signalAlert, session, getServerGeneration: () => serverGeneration, regenSession });
// Rate limiters shared between register, support-guest, analytics
const contactRateLimit      = makeRateLimit(5,  60 * 60 * 1000, 'contact');
const guestChatRateLimit    = makeChatRateLimit();
const analyticsRateLimit    = makeRateLimit(300, 60 * 60 * 1000, 'analytics');
const guestReadRateLimit    = makeRateLimit(2000, 60 * 60 * 1000, 'guestread');
const botLogRateLimit       = makeRateLimit(600, 60 * 60 * 1000, 'botlog',
  req => (req.headers['x-bot-ip'] || '').toString().trim() || 'botlog');
const sha256hex = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const { HWID_KEY } = require('./helpers/hwid-key')({ readSecret });
const { hwidHmac } = require('./helpers/hwid-hmac')({ HWID_KEY, crypto });
// ════ Public registration — routes/register.js ════
require('./routes/register')({ app, AUTH_SCHEME_PREHASH, EMAIL_CODE_TTL_MS,
  PUBLIC_USER_DEFAULT_FEATURES, QRCode, bcrypt, computeAuthPrehash,
  createDemoDeviceForUser, crypto, db, decryptText, encryptText, genEmailCode,
  genRef, hwidHmac, log, looksLikeAuthHash, looksLikeAuthSalt, makeChatRateLimit,
  makeRateLimit, newAuthSalt, notifyAdminForUser, notifyPush,
  recordPolicyAcceptances, recordTosAcceptance, sendApprovalEmail, sendAuthPage,
  sendEmailVerifyCode, sha256hex, shopStmts, stmts, totpRateLimit,
  contactRateLimit, guestChatRateLimit, analyticsRateLimit,
  guestReadRateLimit, botLogRateLimit });
// ── Optional passkey enrollment at the END of registration (pre-auth) ────────
// APK download — before auth wall so devices can fetch with a one-time token
const { apkBuildR2Key, getActiveApkBuild, getActiveBuildId, getApkBuildById, getApkBuilds, mintApkToken, saveApkBuilds, setActiveBuildId } = require('./helpers/apk-build-store')({ getDb: () => db, kv, randomUUID });
// ════ APK downloads, agent provisioning, license trial — routes/provisioning.js ════
require('./routes/provisioning')({ R2_BUCKET, SERVER_ORIGIN, app, crypto, db,
  decryptBuffer, getActiveApkBuild, kv, log, makeRateLimit, r2, r2Del, r2Get,
  requireAuth, requireUnlocked, stmts, session });
// SentinelOS agent software trial ping — routes/license-trial-ping.js
require('./routes/license-trial-ping')({ app, authenticateDeviceRequest, daysRemaining, DAY_MS, log, maybeAlertTrialLapse, requireUnlocked, trialStmts, TRIAL_DAYS });

const guestMsgOut = (m) => ({ id: m.id, sender: m.sender, body: decryptText(m.body), created_at: m.created_at });
const MAX_SUPPORT_MSG = 4000;

// ════ Public contact form + guest live chat — routes/support-guest.js ════
require('./routes/support-guest')({ app, cors, db, decryptText, encryptText, getSupportPresence,
  guestChatRateLimit, guestMsgOut, guestReadRateLimit, guestStmts,
  io, log, notifyAdmin, notifyPush, MAX_SUPPORT_MSG });

// ════ Checkout completion (marketing funnel) — routes/checkout.js ════
require('./routes/checkout')({ app, CRYPTO_PLAN_PRICES, CRYPTO_SKU_COMP,
  HYBRID_EXTRA_DEVICE_AMOUNT, HYBRID_EXTRA_DEVICE_ANNUAL_PRICE, HYBRID_EXTRA_DEVICE_PRICE,
  HYBRID_FLAT_LEGACY_PRICES, HYBRID_INCLUDED_DEVICES, HYBRID_LEGACY_EXTRA_DEVICE_PRICE,
  HYBRID_LEGACY9_EXTRA_DEVICE_PRICE, HYBRID_REQUIRES_SUPPORT_ACCESS_MSG,
  NOWPAYMENTS_API_KEY, NOWPAYMENTS_IPN_SECRET,
  PLAN_KEY_BY_PRICE, PLAN_META, STRIPE_PLANS, STRIPE_TRIAL_DAYS,
  THREE_DEVICE_EXTRA_AMOUNT, THREE_DEVICE_EXTRA_PRICE, TRIAL_DAYS_ACCOUNT,
  TRIAL_WIPE_GRACE_MS, TRACKER_DOMAIN,
  UNLIMITED_EXTRA_DEVICE_AMOUNT, UNLIMITED_EXTRA_DEVICE_ANNUAL_PRICE, UNLIMITED_EXTRA_DEVICE_PRICE,
  UNLIMITED_FLAT_LEGACY_PRICES, UNLIMITED_INCLUDED_DEVICES,
  businessModeQualifies, compSlotRow, compSubInfo,
  contactRateLimit, cors, crypto, db, decryptText, express, genRef,
  getUserSubscriptionRow, hasSupportAccessGranted, hybridExtraDevices,
  invalidPlanMessage, log, notifyAdmin, notifyAdminForUser, notifyPush,
  requireAuth, sendPurchaseEmail, sessionUserEmail, shopStmts, slotRowCount, stripe,
  STRIPE_PUBLISHABLE_KEY, stripeSubOut, threeDeviceExtraDevices, trialInfo, unlimitedExtraDevices, upsertStripeSubscription });
// Web Push VAPID key + self-install enrollment token — routes/vapid-key-and-enrollment-token.js
require('./routes/vapid-key-and-enrollment-token')({ app, db, decryptText, express, loginRateLimit, stmts, vapidPublicKey, verifyUserPassword });

// ── Public (self-install) APK — served without auth so end-users can download ─
const PUBLIC_APK_R2_KEY = 'apk/public/self-install.apk';
const { getPublicApkMeta, savePublicApkMeta } = require('./helpers/public-apk-meta')({ db });
// Public APK download (meta + file) — routes/public-apk-download.js
require('./routes/public-apk-download')({ app, GetObjectCommand, PUBLIC_APK_R2_KEY, R2_BUCKET, getPublicApkMeta, r2 });

// ── SentinelClient (companion app) APK — served without auth ─────────────────
const CLIENT_APK_R2_KEY = 'apk/public/sentinel-client.apk';
const { getClientApkMeta, saveClientApkMeta } = require('./helpers/client-apk-meta')({ db });
// Client APK download (meta + file) — routes/client-apk-download.js
require('./routes/client-apk-download')({ app, CLIENT_APK_R2_KEY, GetObjectCommand, R2_BUCKET, getClientApkMeta, r2 });

// ── Pre-auth public surface: mobile-login, analytics, sw.js, webauthn client — routes/preauth-public.js ──
require('./routes/preauth-public')({ app, analyticsRateLimit, botLogRateLimit, cors, crypto, db, express, getDailySalt, kv, parseUA, path, reqClientIp, resolveGeoAndBackfill, getServerGeneration: () => serverGeneration, regenSession });

// ── Pre-auth static assets (vendored CDN replacements + page chrome) ─────────
// The login/register/unlock pages are served pre-auth: any asset they reference must be
// reachable WITHOUT a session cookie, or requireAuth 302s it to /login and the page renders
// unstyled (this was the original bug — pfBlockerNG sinkholed cdn.jsdelivr.net, and the
// Bootstrap CSS had no local fallback). Now all Bootstrap/icons/fonts/JS are vendored under
// /vendor (versioned URLs → immutable, cacheable a year) and the four image files the auth
// pages reference (favicon.png, favicon.ico, icon-192.png, logo.png — all public-safe, no
// secrets) are served openly like /sw.js and /webauthn-client.js. Mounted BEFORE
// app.use(requireAuth) on purpose; nothing sensitive lives under /vendor.
app.use('/vendor', express.static(path.join(__dirname, 'public', 'vendor'), {
  immutable: true,
  maxAge: '365d',
}));
// ── Pre-auth page chrome, assetlinks, device re-home — routes/preauth-assets-and-rehome.js ──
// NOTE: normIdent is a const arrow defined at L4349, AFTER this require site, so it is
// injected LAZILY (s => normIdent(s)) following the getServerGeneration precedent at L3557.
// Passing it by value would throw a TDZ ReferenceError at boot.
require('./routes/preauth-assets-and-rehome')({ app, EMAIL_CODE_TTL_MS, authenticateDeviceRequest, db, decryptText, genEmailCode, log, normIdent: s => normIdent(s), path, requireUnlocked, sendEmailVerifyCode, sha256hex, signalAlert });

// ── Operator API tokens (sentinel-adb CLI etc.) ─────────────────────────────────
// Mounted globally BEFORE app.use(requireAuth): a valid Bearer token for an explicitly
// allowed route synthesizes an admin session for that request only — everything else
// falls through to session auth untouched. Tokens are minted out-of-band
// (tools/mint-operator-token.js), sha256-hashed at rest, shown once, revocable via
// the revoked flag (checked per request). Every use is logged with the token name.
const OPERATOR_TOKEN_ROUTES = [
  // SSH-style shell: send commands + read back output + resolve device IDs.
  { re: /^\/api\/devices\/[^/]+\/command$/, scope: 'shell', methods: ['POST'], commands: ['shell_exec', 'shell_stop'] },
  { re: /^\/api\/devices\/[^/]+\/shell-sessions$/, scope: 'shell', methods: ['GET'] },
  { re: /^\/api\/devices$/, scope: 'shell', methods: ['GET'] },
];
const { operatorTokenAuth } = require('./helpers/operator-token-auth.js')({ OPERATOR_TOKEN_ROUTES, db, getServerGeneration: () => serverGeneration, log });
app.use(operatorTokenAuth);

app.use(requireAuth);

// ── Marketing analytics dashboard + purge (admin) — routes/admin-analytics.js ──
require('./routes/admin-analytics')({ app, db, requireAdmin, classifyBotUA, isPg });

// ── Web Push subscription endpoints (authed) — extracted to routes/push.js ──────
require('./routes/push')({ app, db });

// ── Push notification preferences (admin only) ───────────────────────────────
// ── Admin config: notification prefs + SMTP + email templates — routes/admin-config.js ──
require('./routes/admin-config')({
  app, db, log, requireAdmin, decryptText,
  getNotifyPrefs, saveNotifyPrefs, getSmtpConfig, saveSmtpConfig, getEmailTemplate, saveEmailTemplate,
  NOTIFY_EVENT_TYPES,
});

// Inject Maps API key at serve time so it's never baked into the image
const MAPS_KEY = readSecret('sentinel_maps_key', 'MAPS_KEY');
const { assetVer } = require('./helpers/asset-ver')({ crypto, fs, path });
// NOTE: replaceAll, not replace — index.html stamps __JS_VER__ on BOTH app.js and
// webauthn-client.js; .replace() only hit the first, so webauthn-client.js shipped with a
// literal "?v=__JS_VER__" that never cache-busted.
const _deployVer = assetVer('app.js');  // single source of truth for deploy fingerprint
const indexHtml = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8')
  .replaceAll('__MAPS_KEY__', MAPS_KEY)
  .replaceAll('__JS_VER__',  _deployVer)
  .replaceAll('__WA_VER__',  assetVer('webauthn-client.js'))
  .replaceAll('__CSS_VER__', assetVer('style.css'))
  .replaceAll('__DEPLOY_VER__', _deployVer);
// ── App shell: /, /chat, /admin, /admin/subusers, /sw.js — routes/app-shell.js ──
require('./routes/app-shell')({ app, crypto, cspWithNonce, indexHtml, kv, path, randomUUID });
app.use(express.static(path.join(__dirname, 'public')));

// Customer license register + trial status — routes/customer-license-trial.js
require('./routes/customer-license-trial')({ app, daysRemaining, genLicenseKey, log, TRIAL_DAYS, trialStmts });

// ── Phase 2: WebUSB OS flasher — hardware-id binding + 30-day OS trial ─────────
// The browser-based fastboot flasher (Pixel-only, integrated SentinelOS path)
// lives at /flash (server/public/flash.html) — session-authenticated because it
// is served by the static handler AFTER app.use(requireAuth). Before flashing,
// the device's hardware id (serial) is bound to the logged-in account so the
// 30-day OS software trial can be tracked.

// Deterministic, keyed index over the hardware serial so we can dedup/look up a
// device without storing the raw serial in the clear. The raw serial is stored
// ENC:-encrypted in hardware_id; this HMAC is the searchable handle (also the
// Phase-3 RMA serial cross-reference key). Keyed by a stable server secret.

// Bind a device's hardware id to this account and start the 30-day OS trial.
// Called by /flash just before flashing begins. Idempotent per (user, hardware).
// ════ OS-flash trial (bind, status, admin-assist) — routes/flash.js ════
require('./routes/flash')({ app, DAY_MS, TRIAL_DAYS, daysRemaining, db, encryptText, genLicenseKey, hwidHmac, log, notifyAdminForUser, recordTosAcceptance });

// ════ E-commerce pricing + RMA pipeline + catalog + orders — routes/commerce.js ════
const { computePrice, rmaWindowState } = require('./helpers/price-rma')({ DAY_MS });
require('./routes/commerce')({ app, DAY_MS, db, encryptBuffer, genRef, log, notifyAdminForUser,
  r2Put, recordTosAcceptance, shopStmts, computePrice, rmaWindowState, RETURN_WINDOW_DAYS: 14 });
// ════ ADMIN — products / orders / RMA / trials — routes/admin-commerce.js ════
require('./routes/admin-commerce')({ app, db, shopStmts, requireAdmin, CRYPTO_PLAN_PRICES, DAY_MS, PLAN_META, STRIPE_PLANS, computePrice, daysRemaining, decryptBuffer, decryptText, hwidHmac, log, notifyAdmin, r2Get, rmaWindowState });

// ════ SUPPORT chat (admin ↔ buyer) + E2E keys + guest admin — routes/support.js ════
require('./routes/support')({ app, db, decryptText, encryptText, getOrCreateThread, getSupportPresence,
  guestMsgOut, guestStmts, io, log, notifyAdminForUser, notifyUser, parseEncMsg, randomUUID,
  requireAdmin, requireAuth, setSupportPresence, supportMsgOut, supportStmts,
  _isWrapObj, actingUserRow, buildSupportContext,
  makeRateLimit, speakeasy, verifyUserPassword, TOTP_SECRET });

// ════ Bug reports (submit, list, thread, admin triage) — routes/bug-reports.js ════
require('./routes/bug-reports')({ app, db, decryptText, encryptText, io, log, notifyAdminForUser, requireAdmin, requireAuth, sendWebPushToUser });

// REST API: session, me, device list — routes/session-and-device-list.js
const HONEYPOT_MGMT_KEY = (readSecret('sentinel_hp_mgmt_key', 'HONEYPOT_MGMT_KEY') || '').trim();
require('./routes/session-and-device-list')({ ADMIN_USER, HONEYPOT_MGMT_KEY, app, connectedSockets, crypto, db, decryptText, deviceStatus, encryptedDevices, kv, redisEnabled, stmts });

// ── Zero-knowledge device data guard ─────────────────────────────────────────
// When a device is assigned to a public (registered) user, the admin may see
// only metadata (device list, name, model, battery, online status).
// All content endpoints return 403 to enforce the zero-knowledge boundary.
//
// Allowlisted sub-paths that remain accessible to admin even on ZK-owned devices:
//   PUT  /name         — rename
//   DELETE /           — remove device record entirely
//   PATCH /owner        — (re-)assign owner
//   POST  /deep-sleep   — fleet management
//   POST  /theft-mode   — fleet management
//   POST  /update-apk   — fleet APK update
//   GET   /sleep-check  — heartbeat monitoring
app.use('/api/devices/:id', (req, res, next) => {
  // Admin can read ZK-encrypted blobs from any device (they cannot decrypt them,
  // but they can see the ciphertext records — ZK guarantee is maintained by the
  // encryption, not by API access control).
  next();
});

// ── Permanent device↔account lock helpers ──────────────────────────────────
const { normIdent } = require('./helpers/norm-ident')();

const { checkTrialLineageAbuse } = require('./helpers/check-trial-lineage-abuse')({ db, decryptText, hwidHmac, log, normIdent, notifyAdmin });
const { userIdentityEmail } = require('./helpers/user-identity-email')({ getNormIdent: (s) => normIdent(s) });

const { deviceLockState, isDeviceLocked } = require('./helpers/device-lock-state')({ decryptText, normIdent, stmts });

const { bindDeviceToOwner } = require('./helpers/device-bind')({ db, decryptText, encryptText, log, removeDemoDeviceForUser, sha256hex, stmts, userIdentityEmail });

// ── Demo device seeding ─────────────────────────────────────────────────────
// Every public (FamilySafe) user gets ONE synthetic placeholder device, id `demo-<userId>`,
// populated with sample telemetry so their dashboard isn't empty before they enroll a real
// device (see finishPublicRegistration() and the runMigration() backfill). It is deliberately
// NOT real hardware: it never goes through the ticket/socket-handshake enrollment path, so it
// must be excluded everywhere that path's invariants matter — see the is_demo guards in
// maybeRespondWithZkPayloads(), GET /api/devices, GET /api/devices/search, the plan device-count
// check in POST /api/enrollment/ticket, and wipeUserAccount(). Removed the instant the owner's
// first real device is bound (bindDeviceToOwner(), above).


// Device helpers (demoWifiCurrent, demoStatusPayload, createDemoDeviceForUser,
// removeDemoDeviceForUser, ALL_ROWS, zkRowLimit, maybeRespondWithZkPayloads)
// moved to services/device-helpers.js — initialized in phase-2 after stmts is created.



// ── Device media / locations / ZK payloads + streams — routes/device-media-zk.js ──
require('./routes/device-media-zk')({ app, STORAGE_QUOTA_BYTES, calculateStorageBytes, db, decryptText, deviceOwnerInfo, io, log, maybeRespondWithZkPayloads, r2Del, requireAuth, requireDeviceAccess, requirePerm, stmts, updateDeviceOwner });

const { findDeviceNameConflict } = require('./helpers/find-device-name-conflict')({ db, decryptText });

const { pushDeviceDisplayNameToBastion } = require('./helpers/push-device-display-name')({ db });

const { syncDeviceDisplayNameToBastion } = require('./helpers/sync-device-display-name')({ db, decryptText, pushDeviceDisplayNameToBastion });

// ── Device ownership lifecycle: rename / archive / enrollment ticket / claim / owner / self-delete / delete — routes/device-ownership-lifecycle.js ──
const { deviceLimitForUser } = require('./helpers/device-limit-for-user')({ HYBRID_FLAT_LEGACY_PRICES, HYBRID_INCLUDED_DEVICES, PLAN_KEY_BY_PRICE, TRIAL_DEVICE_LIMIT, UNLIMITED_FLAT_LEGACY_PRICES, UNLIMITED_INCLUDED_DEVICES, compPlanFor, compSlotRow, db, decryptText, hybridExtraDevices, slotRowCount, threeDeviceExtraDevices, unlimitedExtraDevices });
require('./routes/device-ownership-lifecycle')({ PLAN_KEY_BY_PRICE, app, connectedSockets, crypto, db, decryptText, deviceLimitForUser, deviceLockState, deviceStatus, encryptText, encryptedDevices, findDeviceNameConflict, getUserSubscriptionRow, io, isDeviceLocked, log, markOffline, pushDeviceDisplayNameToBastion, r2Del, redisEnabled, requireAdmin, requireAuth, requireDeviceAccess, requireDeviceController, requireUnlocked, signalAlert, stmts, updateDeviceOwner, userIdentityEmail });

// Business Account compliance mode: commands permanently blocked once a device's OWNER has
// business_mode=1 — regardless of who issues the command (owner or a business sub-user). Manual
// photo capture is blocked; the automatic unlock_photo capture is a separate device-initiated
// socket event (never routed through this endpoint) and is unaffected.
const BUSINESS_MODE_BLOCKED_COMMANDS = new Set([
  'record_audio', 'stop_record_audio', 'start_audio_stream', 'stop_audio_stream', 'set_talkback_volume',
  'start_stream', 'stop_stream',
  'start_screen_stream', 'stop_screen_stream',
  'take_screenshot', 'start_screenshot_interval', 'stop_screenshot_interval',
  'start_keylog', 'stop_keylog',
  'start_screen_text', 'stop_screen_text',
  'take_photo', 'start_photo_interval', 'stop_photo_interval',
]);

// Which permission(s) are sufficient for each command.
// Users with any listed perm (or admin role) may send it.
const COMMAND_PERMS = {
  get_location:        ['location'],
  start_live_track:    ['location'],
  stop_live_track:     ['location'],
  take_photo:              ['photos'],
  start_photo_interval:    ['photos'],
  stop_photo_interval:     ['photos'],
  start_stream:        ['stream'],
  stop_stream:         ['stream'],
  take_screenshot:           ['screenshots'],
  start_screenshot_interval: ['screenshots'],
  stop_screenshot_interval:  ['screenshots'],
  record_audio:        ['audio'],
  stop_record_audio:   ['audio'],
  start_audio_stream:    ['audio'],
  stop_audio_stream:     ['audio'],
  set_talkback_volume:   ['audio'],
  get_network:         ['network'],
  list_files:          ['files'],
  get_file:            ['files'],
  delete_file:         ['files'],
  get_apps:            ['apps'],
  get_battery_stats:   ['apps'],
  get_calls:            ['calls'],
  get_sms:             ['sms'],
  // Windows-specific (most require 'commands' permission)
  get_monitors:        ['screenshots'],
  uninstall_agent:     ['commands'],
  update_agent:        ['commands'],
  get_processes:       ['commands'],
  kill_process:        ['commands'],
  shell:               ['commands'],
  reg_list:            ['commands'],
  reg_write:           ['commands'],
  reg_delete_value:    ['commands'],
  reg_delete_key:      ['commands'],
  get_services:        ['commands'],
  service_control:     ['commands'],
  get_autostarts:          ['commands'],
  delete_autostart:        ['commands'],
  set_device_restriction:  ['commands'],
  reboot_device:           ['commands'],
  lock_app_permissions:    ['commands'],
  update_app:              ['commands'],
  install_apk:             ['commands'],
  uninstall_app:           ['commands'],
  pull_apk:                ['files'],
  set_password:            ['commands'],
  hide_app:                ['commands'],
  show_app:                ['commands'],
  get_app_permissions:     ['commands'],
  set_app_permission:      ['commands'],
  suspend_app:             ['commands'],
  collect_logs:            ['commands'],
  start_keylog:            ['keylogs'],
  stop_keylog:             ['keylogs'],
  start_screen_text:       ['screentext'],
  stop_screen_text:        ['screentext'],
  connect_wifi:            ['commands'],
  captive_portal_submit:   ['commands'],
  bypass_captive_portal:   ['commands'],
  test_airline_login:      ['commands'],
  get_install_filter:      ['commands'],
  set_install_filter_mode: ['commands'],
  add_install_filter:      ['commands'],
  remove_install_filter:   ['commands'],
  get_uninstall_blocked:   ['commands'],
  set_uninstall_blocked:   ['commands'],
  get_contacts:            ['contacts'],
  get_calendar:            ['contacts'],
  shell_exec:              ['shell'],
  shell_stop:              ['shell'],
  start_logcat:            ['logcat'],
  stop_logcat:             ['logcat'],
  // Windows RA live streaming + remote input
  inject_mouse_down:   ['commands'],
  inject_mouse_up:     ['commands'],
  inject_mouse_click:  ['commands'],
  inject_mouse_move:   ['commands'],
  inject_mouse_move_to:['commands'],
  inject_mouse_scroll: ['commands'],
  inject_key_down:     ['commands'],
  inject_key_up:       ['commands'],
  inject_key_combo:    ['commands'],
  inject_text:         ['commands'],
};

// Live injection commands that need minimal latency (RA Live Desktop mouse/keyboard).
// The command handler skips the heavy post-emit operations (decryptDevice, signalFeature,
// notifyOwnerForCommand, per-event logging) for these and uses a 1 s TTL cached owner-info query.
const LIVE_INPUT_COMMANDS = new Set([
  'inject_mouse_down', 'inject_mouse_up', 'inject_mouse_click',
  'inject_mouse_move', 'inject_mouse_move_to', 'inject_mouse_scroll',
  'inject_key_down', 'inject_key_up', 'inject_key_combo', 'inject_text',
]);

// ── Device power/security config + airline WiFi — routes/device-config.js ──
require('./routes/device-config')({ app, db, decryptDevice, detectAirline, emitToDevice, getAirlineProfile, getAirlineProfiles, getUnlockCapture, getWifiAutoJoin, io, log, normalizeUnlockCapture, normalizeWifiAutoJoin, requireAuth, requireDeviceAccess, requireDeviceController, requireUnlocked, setWifiAutoJoin, startTheftModeAlerts, stmts, stopTheftModeAlerts, validateCredentials });

// ── Auto-VPN on open WiFi (+ manual "route all traffic" toggle) ──────────────
// Routes ALL device traffic through the agent's existing VLESS+REALITY tunnel — either automatically
// while the device is on an OPEN WiFi network (`enabled`), or always/on every network via the manual
// WebUI toggle (`force`). Stored in settings 'vpn:<id>', pushed on change + on every reconnect.
// ⚠️ The egress UUID is a SERVER SECRET (sentinel_xray_vpn_uuid) — pushed to the device over the
// encrypted control channel, NEVER returned to the browser or shipped in the APK, so the REALITY node
// can't be abused as an open proxy by anyone decompiling the agent. Default OFF.
const XRAY_VPN_UUID    = readSecret('sentinel_xray_vpn_uuid',     'XRAY_VPN_UUID');

// Tailnet access — UUID for the tailnet@sentinel REALITY user (routes to the TS relay sidecar).
// Server-side secret, never returned to the browser, pushed to devices over the encrypted channel.
const TAILNET_UUID     = readSecret('sentinel_xray_tailnet_uuid', 'TAILNET_UUID');
// Tailscale OAuth client secret (tskey-client-...) for the device-picker API proxy.
const TS_API_TOKEN     = readSecret('sentinel_ts_api_token',      'TS_API_TOKEN');
const TS_TAILNET       = process.env.TS_TAILNET || '-';   // '-' = OAuth client's own tailnet

// Cached Tailscale API bearer token (short-lived; exchanged from OAuth client_credentials).
let _tsTokenCache = { token: null, expiresAt: 0 };
const { getTsApiToken } = require('./helpers/ts-api-token.js')({ TS_API_TOKEN, getTsTokenCache: () => _tsTokenCache, log, setTsTokenCache: (v) => { _tsTokenCache = v } });
// Device VPN get/set — routes/device-vpn.js
require('./routes/device-vpn')({ app, XRAY_VPN_UUID, emitToDevice, getVpn, io, log, normalizeVpn, requireAuth, requireDeviceAccess, requireDeviceController, requireUnlocked, setVpn, vpnCommand });

// ── SentinelRemoteAssist — Windows remote-support agent integration ─────────
// A `remote_assist` device is a Windows PC running the (consensual — visible consent dialog +
// on-screen session indicator + ephemeral local admin account, unchanged) SentinelRemoteAssist
// tool, logged into the SentinelMDM account system and reachable over the xray REALITY :443
// transport, exactly like an Android agent. See docs/ARCHITECTURE.md's "SentinelRemoteAssist" plan doc.
//
// Access control reuses requireDeviceController() UNCHANGED (no new middleware needed — it
// already implements exactly the required rule): on a ZK-owned device (public-user-claimed,
// `lineage_kind` default `'public'`) only the owning public user or their business sub-users pass
// — admin gets a hard 403, no fallback. On an admin-fleet device (`lineage_kind='admin'`, claimed
// via the admin/sub-user login build) it falls through to normal admin/perm access — full control,
// mirroring Android admin-fleet devices. Layered on top of requireDeviceAccess exactly like every
// other device-command route (deep-sleep, theft-mode, vpn, …).
//
// ⚠️ Every route below ALSO checks `agent_kind==='remote_assist'` so these can never be reached on
// an Android or reserved-future native-Windows-agent device (see the `agent_kind` migration note).
const XRAY_REMOTEASSIST_UUID = readSecret('sentinel_xray_remoteassist_uuid', 'XRAY_REMOTEASSIST_UUID');

// Per-device cooldown for the auto-reconnect-on-socket-register path below — pushing the transport
// command reconfigures the agent's xray, which itself drops the control channel (a fresh reconnect
// follows within seconds). Without a cooldown, that reconnect would see "still not connected yet"
// (Hop-1 setup takes a few seconds) and re-provision again, which can cascade. 45s is comfortably
// longer than one xray-reconfig+tunnel-bringup cycle but short enough that a genuinely-dead tunnel
// gets retried on the very next real reconnect. In-memory/per-replica is fine — a device's socket
// lives on exactly one tracker replica at a time.
const raAutoProvisionAttempts = new Map();
const RA_AUTO_PROVISION_COOLDOWN_MS = 45000;

const { requireRemoteAssistDevice } = require('./helpers/require-remote-assist-device')({ db });

const { remoteAssistTransportCommand } = require('./helpers/remote-assist-transport-command')({ XRAY_REMOTEASSIST_UUID });

const { emitRemoteAssistProvision } = require('./helpers/emit-remote-assist-provision')({ XRAY_REMOTEASSIST_UUID, deviceEmit, emitToDevice, log, remoteAssistTransportCommand });

// ── Shared OpenCode (DeepSeek) API client — used by IT Mode Audit + screen-text AI analysis ────
// Independent caller of the SAME external API/secret bastion-web.py's _call_opencode_analysis()
// already uses for IT Mode Audit — these calls live entirely server-side (tracker/worker), never
// routed through the bastion. (The former AI Live Chat feature was purged 2026-09-11; the shared
// client + `opencode_api_key` secret remain because the IT-audit and screen-text AI features use them.)
// The `opencode_api_key` secret is mounted by portainer-stack.yml + portainer-stack-ha.yml
// (tracker + tracker-worker) and ssh-bastion.yml.
const OPENCODE_API_URL = process.env.OPENCODE_API_URL || 'https://opencode.ai/zen/go/v1/chat/completions';
const OPENCODE_MODEL = process.env.OPENCODE_MODEL || 'mimo-v2.5';

// Shared OpenCode POST with KEY failover: the primary account may be dead (out of
// credits → 401/403) while a fallback key is configured — retry once with the fallback
// instead of failing every model in the chain. A short in-memory "primary dead" flag
// skips the doomed first attempt for a while (per process; each replica decides alone).
// ⚠️ OpenCode Go (zen/go/v1) REQUIRES the x-opencode-session header (docs updated
// 2026-09-06-ish): without it every call 400s "MissingSessionID" — this silently
// killed the scheduled screen-text analysis fleet-wide. Send a stable per-conversation
// session id (generated by the caller; defaults to a fresh UUID per request).
let _opencodePrimaryDeadUntil = 0;
// How long the primary key stays "dead" before being re-checked. Env-tunable
// (OPENCODE_PRIMARY_RETRY_MS) so the operator can set the balance re-check cadence
// without a code change; default = every 10 minutes.
const OPENCODE_PRIMARY_DEAD_TTL_MS = Number(process.env.OPENCODE_PRIMARY_RETRY_MS) || 10 * 60 * 1000;
const { postOpencode } = require('./helpers/post-opencode.js')({ OPENCODE_API_URL, OPENCODE_PRIMARY_DEAD_TTL_MS, getOpencodePrimaryDeadUntil: () => _opencodePrimaryDeadUntil, log, opencodeFallbackKey, opencodePrimaryKey, setOpencodePrimaryDeadUntil: (v) => { _opencodePrimaryDeadUntil = v } });

// ── OpenCode primary-balance probe ─────────────────────────────────────────────
// The primary `opencode_api_key` can be exhausted (CreditsError 401) while a fallback
// key keeps serving. This probe periodically re-tests the PRIMARY directly with a
// minimal 1-token completion so the instant its balance is topped up the fleet switches
// back to it automatically — no waiting for a chance 401 on a real request to rediscover
// it. While the primary is still dead each probe is a FREE 401; the moment it recovers it
// costs ~1 token. Runs ONLY in worker/standalone processes (ROLE=web tracker replicas
// still re-check lazily on their next real call after the dead window expires), and only
// while a dead flag is actually set.
let _opencodeProbeInFlight = false;
const { probeOpenCodePrimary } = require('./helpers/opencode-probe.js')({ OPENCODE_API_URL, OPENCODE_MODEL, OPENCODE_PRIMARY_DEAD_TTL_MS, getOpencodePrimaryDeadUntil: () => _opencodePrimaryDeadUntil, getOpencodeProbeInFlight: () => _opencodeProbeInFlight, log, opencodePrimaryKey, setOpencodePrimaryDeadUntil: (v) => { _opencodePrimaryDeadUntil = v }, setOpencodeProbeInFlight: (v) => { _opencodeProbeInFlight = v } });
setInterval(() => {
  if (ROLE === 'web') return;                    // worker (or standalone) owns the probe
  if (!_opencodePrimaryDeadUntil) return;        // primary not flagged dead — nothing to probe
  if (Date.now() < _opencodePrimaryDeadUntil) return;   // still inside the dead window
  if (_opencodeProbeInFlight) return;            // one probe at a time
  probeOpenCodePrimary();
}, Math.max(60 * 1000, Math.min(OPENCODE_PRIMARY_DEAD_TTL_MS, 15 * 60 * 1000)));

// ── Remote-Assist session lifecycle + persistent Hop-2 key — routes/remote-assist/remote-assist-session.js ──
require('./routes/remote-assist/remote-assist-session')({ app, XRAY_REMOTEASSIST_UUID, crypto, db, decryptText, deviceOwnerInfo, emitRemoteAssistProvision, emitToDevice, encryptText, log, randomUUID, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked, syncDeviceDisplayNameToBastion });

const { raUpdateTargetForDevice } = require('./helpers/ra-update-target-for-device')({ db });

// Remote-assist agent update & nuke — routes/remote-assist/remote-assist-agent-update-and-nuke.js
require('./routes/remote-assist/remote-assist-agent-update-and-nuke')({ app, db, log, raUpdateTargetForDevice, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked });

// Sticky auto-start flag: when 'connected', the server auto-provisions the bastion Hop-1 tunnel
// on every agent (re)connect. Set by clicking "Start Auto" in the dashboard; cleared by toggling
// it off or by clicking "Stop" / "Disconnect".
// ── ARP-canary subnet math: CIDR normalisation + host-range picks — helpers/canary-ips.js ──
// Zero dependencies: these are pure functions of their arguments, so the factory takes no ctx.
const { normalizeSubnetCidr, pickCanaryCandidateIps } = require('./helpers/canary-ips')();
const { EDR_NEVER_SUPPRESS_RULES, LEARN_CRITICAL, LEARN_LEARNABLE_CATEGORIES, LEARN_WINDOW_CACHE_MS, _learnWindowCache } = require('./helpers/learn-mode-guards')();

const { learnIsCritical } = require('./helpers/learn-is-critical')({ LEARN_CRITICAL });

const { learnGate, learnInvalidate, learnNormalizeDetail } = require('./helpers/learn-mode-core')({ LEARN_LEARNABLE_CATEGORIES, LEARN_WINDOW_CACHE_MS, _learnWindowCache, getDb: () => db, learnIsCritical, log });

const { ingestArpScanResult } = require('./helpers/arp-scan')({ db, decryptText, deviceOwnerInfo, learnGate, log, normalizeSubnetCidr, notifyUser, pickCanaryCandidateIps });
const { getWinUpdateForceActive, setWinUpdateForceActive, getUsbLockdownEnabled, setUsbLockdownEnabled } = require('./helpers/win-update-usb-lockdown')({ db });
const { getArpSweepWatchEnabled, setArpSweepWatchEnabled, getSentryEnabled, setSentryEnabled, getScreenTextEnabled, setScreenTextEnabled } = require('./helpers/device-feature-flags')({ db });
// ════ Remote Assist features (auto, status, IT audit, forensics, appcontrol, winupdate, telemetry, sentry, USB lockdown, defender, EDR, arp-scan) — routes/remote-assist/remote-assist-features.js ════
require('./routes/remote-assist/remote-assist-features')({ app, db, emitToDevice, ingestArpScanResult, log, requireAuth, requireAdmin, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked, setSentryEnabled, setScreenTextEnabled, setUsbLockdownEnabled, setWinUpdateForceActive });

// ── Learn Mode: observation windows, per-observation review, fleet start/stop — routes/learn-mode.js ──
const { groupOwnerKey } = require('./helpers/group-owner-key')();
const { fleetControllableRemoteAssistDeviceIds } = require('./helpers/fleet-controllable-ra-devices')({ db, deviceOwnerInfo, groupOwnerKey });
const { requireFleetAccess } = require('./helpers/require-fleet-access')();
require('./routes/learn-mode')({ app, db, express, fleetControllableRemoteAssistDeviceIds, learnInvalidate, log, requireAuth, requireDeviceAccess, requireDeviceController, requireFleetAccess, requireUnlocked });



// ARP sweep watch get/set — routes/device-arp-sweep-watch.js
require('./routes/device-arp-sweep-watch')({ app, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked, setArpSweepWatchEnabled });


// ── Learn Mode ───────────────────────────────────────────────────────────────────────────────
// One gate — learnGate() — sits in front of every noisy-heuristic detector page. It answers a
// single question: "should this alert be suppressed?" Three ways it says yes:
//   1. an ACCEPTED baseline entry exists for this exact signature (permanent, survives the window)
//   2. a learn window is currently open for this device (record it, stay silent)
//   3. …that's it — otherwise the alert goes out exactly as before.
//
// Suppression is ALERT-ONLY, matching the established doctrine of arp_neighbors.trusted: the
// underlying arp_events / EDR feed / Sentry outbox rows are still written unconditionally, so the
// roster, the AI summaries and the audit history stay complete. Learn Mode hides pages, never
// evidence.
//
// ⚠️ Critical rules are NEVER suppressible (see LEARN_CRITICAL below) — the ransomware trio and
// the defense-evasion/sensor-blinding signals. Those are the cases where a false negative is
// catastrophic and irreversible, so no amount of "I clicked accept" may silence them. Everything
// else is learnable BECAUSE the human review step at window close is the safeguard.
// arp_sweep events are DRAINED (not diffed like the roster above) — each one is a genuinely fresh
// detection from a distinct ~4-second pktmon capture window, so every drained event is recorded
// into arp_events for the daily AI summary's benefit even back-to-back (shows the full pattern of
// activity, not just the first sighting). The INSTANT ALERT is what's rate-limited instead: only
// the first sighting of a given source MAC within ARP_SWEEP_ALERT_SUPPRESS_MS pages the owner — an
// ongoing multi-minute sweep from the same attacker would otherwise fire an alert for every few
// seconds' worth of drained backlog (the worker poller drains every ~15 min, so a sustained sweep
// can arrive as dozens of queued events in one batch).
const ARP_SWEEP_ALERT_SUPPRESS_MS = 30 * 60 * 1000;
const { ingestArpSweepEvents } = require('./helpers/arp-sweep')({ ARP_SWEEP_ALERT_SUPPRESS_MS, db, decryptText, deviceOwnerInfo, learnGate, log, notifyUser });

// ── AppLocker blocked-file auto-upload ────────────────────────────────────────────────────────
// Auto-uploads the ACTUAL BINARY the first time a given path is seen blocked (dedup is per unique
// path, not per block-event — the same repeatedly-retried blocked file only ever gets captured
// once, matching the ask: "the blocked item auto uploaded", not "every retry re-uploaded"). R2 key
// format mirrors the uploads/ convention elsewhere in this file.
const APPLOCKER_AUTO_UPLOAD_MAX_BYTES = 500 * 1024 * 1024; // 500MB — admin can force past this in the UI

async function uploadBlockedFile(deviceId, path, blockedAt, { force = false } = {}) {
  const id = randomUUID();
  const pathHash = sha256hex(path.toLowerCase());
  const fileName = path.replace(/\\/g, '/').split('/').pop() || 'blocked-file.bin';
  // Storage quota: block new files when the account is over 1 GB.
  const ownerUserId = (await db.prepare('SELECT owner_user_id FROM devices WHERE id=?').get(deviceId))?.owner_user_id;
  if (ownerUserId) {
    const quota = await checkStorageQuota(ownerUserId, 0); // check current usage without adding new bytes
    if (!quota.ok) {
      log('warn', 'AppLocker blocked-file upload blocked — storage quota exceeded', { deviceId, ownerUserId, used: quota.used });
      return { id, status: 'quota_exceeded', error: 'Storage quota exceeded', size: 0 };
    }
  }
  const bastionClient = require('./bastionClient');
  const result = (await bastionClient.fetchBlockedFile(deviceId, path, APPLOCKER_AUTO_UPLOAD_MAX_BYTES, force));
  if (!result.ok) {
    const status = result.needsForce ? 'skipped_size' : 'failed';
    (await db.prepare(
      'INSERT INTO applocker_blocked_files (id,device_id,path,path_hash,file_name,size_bytes,status,error,blocked_at) VALUES (?,?,?,?,?,?,?,?,?)'
    ).run(id, deviceId, encryptText(path), pathHash, encryptText(fileName), result.size || 0, status, result.error || null, blockedAt));
    log(status === 'skipped_size' ? 'info' : 'warn', 'AppLocker blocked-file upload not captured', { deviceId, path, status, error: result.error });
    return { id, status, error: result.error, size: result.size };
  }
  if (!result.buffer || !result.buffer.length) {
    (await db.prepare(
      'INSERT INTO applocker_blocked_files (id,device_id,path,path_hash,file_name,size_bytes,status,error,blocked_at) VALUES (?,?,?,?,?,?,?,?,?)'
    ).run(id, deviceId, encryptText(path), pathHash, encryptText(fileName), 0, 'failed', 'empty file received', blockedAt));
    return { id, status: 'failed', error: 'empty file received' };
  }
  const r2Key = `applocker-blocked/${deviceId}/${id}_${fileName}`;
  await r2Put(r2Key, encryptBuffer(result.buffer));
  (await db.prepare(
    'INSERT INTO applocker_blocked_files (id,device_id,path,path_hash,file_name,size_bytes,r2_key,status,blocked_at,uploaded_at) VALUES (?,?,?,?,?,?,?,?,?,?)'
  ).run(id, deviceId, encryptText(path), pathHash, encryptText(fileName), result.buffer.length, r2Key, 'uploaded', blockedAt, Date.now()));
  log('info', 'AppLocker blocked-file uploaded', { deviceId, path, size: result.buffer.length });
  return { id, status: 'uploaded', size: result.buffer.length };
}

// ── AppLocker blocked-file captures (list/download/delete/force-upload) — routes/applocker-blocked-files.js ──
require('./routes/applocker-blocked-files')({ app, db, decryptBuffer, decryptText, log, r2Del, r2Get, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked, sha256hex, uploadBlockedFile });

// ── File Backup ───────────────────────────────────────────────────────────────────────────────
// PER-ACCOUNT, not global-shared: every account (admin or public/business_sub) configures its OWN
// S3 bucket/credentials/bandwidth AND its own encryption password (settings table,
// file_backup_s3:<userId> / file_backup_enc_pw:<userId>). "Global for all devices" means global
// relative to that ONE account's own device fleet — a public user who owns 3 devices sets this
// once and it applies to all 3 — never a single platform-wide bucket shared across accounts (a
// public user could otherwise overwrite the credentials backing every other customer's backups).
// A device's backup always uses its OWNER's config, never the calling admin's — see
// resolveFileBackupSettings(). This is what makes it safe for run/list/restore to use the same
// requireDeviceAccess/requireDeviceController() chain as every other per-device RA route
// (owner-or-admin), with no separate admin-only config endpoint at all.
// accessKey/secretKey/encryption passwords are encrypted at rest and NEVER round-tripped back to
// the browser in plaintext — GET returns only booleans for whether each secret is set; POST leaves
// a secret field untouched unless a new value is sent.
// ── File Backup: per-account S3 config + encryption-password accessors — helpers/file-backup-settings.js ──
// Consumed below by the scheduled-job path and routes/file-backup.js. Both field lists are
// private to the module; FILE_BACKUP_S3_SECRET_FIELDS has no reader anywhere and was carried
// over unchanged rather than dropped, to keep this a pure move.
const { getFileBackupEncryptionPassword, getFileBackupS3Config, resolveFileBackupSettings,
        resolveFileBackupSettingsForOwner, setFileBackupEncryptionPassword, setFileBackupS3Config } =
  require('./helpers/file-backup-settings')({ db, decryptText, encryptText });

// Schedule/retention — PER DEVICE (unlike S3 config/password, which are per-account): different
// devices under the same account may reasonably want different cadences. TWO independent cadences
// (2026-07-22, minutes-based): fullScheduleMinutes for full backups, incrementalScheduleMinutes for
// the (much cheaper, changed-files-only) incrementals in between — mirrors real backup-tool design
// (e.g. "full weekly, incremental every 15 min"). 0 means off for either (default — opt-in, matching
// every other RA background feature). A configured incremental interval floors to
// FILE_BACKUP_MIN_SCHEDULE_MINUTES (5), same "floor at the tick's own resolution" pattern as the
// ARP scan schedule. retentionDays/retentionCount are independent limits, ENFORCED AS A UNION (a
// backup is pruned if it violates EITHER one) — see pruneFileBackups(); 0 for either = no limit on
// that axis. Back-compat: a pre-2026-07-22 row only has `scheduleHours` (hours-only, no
// incremental concept at all) — read-time migration folds it into fullScheduleMinutes so an
// existing device's schedule isn't silently reset to "off" the first time this loads.
const FILE_BACKUP_MIN_SCHEDULE_MINUTES = 5;
const { getFileBackupSchedule } = require('./helpers/get-file-backup-schedule')({ db });
// File backup schedule get/set — routes/file-backup-schedule.js
require('./routes/file-backup-schedule')({ FILE_BACKUP_MIN_SCHEDULE_MINUTES, app, db, getFileBackupSchedule, log, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked });

// Which folders a device's backup includes — the well-known personal folders (subset of
// FILE_BACKUP_KNOWN_FOLDERS, pulled once PER real user profile) plus admin-picked custom absolute
// paths (from the folder-browser modal, pulled once each — see bastion-web.py's run_file_backup
// doc comment for why the two are treated differently). Per-device (not per-account like the S3
// config) since different devices have different filesystems worth browsing.
const FILE_BACKUP_KNOWN_FOLDERS = ['Desktop', 'Documents', 'Pictures', 'Videos', 'Music', 'Downloads'];
const FILE_BACKUP_MAX_CUSTOM_PATHS = 20;
const { getFileBackupFolders } = require('./helpers/get-file-backup-folders')({ FILE_BACKUP_KNOWN_FOLDERS, db });
// ── File backup: folders / browse / path-size / recent — routes/file-backup-folders-and-recent.js ──
require('./routes/file-backup-folders-and-recent')({ FILE_BACKUP_KNOWN_FOLDERS, FILE_BACKUP_MAX_CUSTOM_PATHS, app, db, decryptText, getFileBackupFolders, log, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked });

// Deletes whatever backups violate the device's retentionDays/retentionCount — called after every
// SUCCESSFUL run (manual or scheduled), never on a failed run (nothing new landed, so nothing
// should be pruned). Best-effort: a prune failure must never be treated as the backup itself
// having failed — the backup already succeeded and is sitting safely in S3 either way.
async function pruneFileBackups(deviceId, s3) {
  const { retentionDays, retentionCount } = (await getFileBackupSchedule(deviceId));
  if (!retentionDays && !retentionCount) return;
  const bastionClient = require('./bastionClient');
  const listResult = (await bastionClient.fileBackupList(deviceId, s3));
  if (!listResult?.ok || !Array.isArray(listResult.backups)) return;
  const sorted = [...listResult.backups].sort((a, b) => (Date.parse(b.modTime) || 0) - (Date.parse(a.modTime) || 0));
  const toDelete = new Map();
  if (retentionCount > 0 && sorted.length > retentionCount) {
    for (const b of sorted.slice(retentionCount)) toDelete.set(b.key, b);
  }
  if (retentionDays > 0) {
    const cutoff = Date.now() - retentionDays * 24 * 60 * 60 * 1000;
    for (const b of sorted) {
      const t = Date.parse(b.modTime || '');
      if (t && t < cutoff) toDelete.set(b.key, b);
    }
  }
  // Chain safety: restoring any incremental replays [full, incr1, ..., target] in full — pruning
  // ANY intermediate entry between a chain's full and its newest surviving entry would silently
  // make that surviving entry unrestorable even though it's itself still within retention. Group
  // entries into chains (a full + every incremental up to the next full), then for each chain
  // protect everything from the full up through the LATEST entry retention would otherwise keep,
  // regardless of what retention wants to do with anything in between.
  const ascending = [...sorted].sort((a, b) => (a.ts || 0) - (b.ts || 0));
  const chains = [];
  let currentChain = null;
  for (const b of ascending) {
    if (b.kind === 'full') {
      currentChain = [b];
      chains.push(currentChain);
    } else if (currentChain) {
      currentChain.push(b);
    } // an incremental with no preceding full at all has nothing to chain-protect
  }
  for (const chain of chains) {
    let lastSurvivingIdx = -1;
    for (let i = 0; i < chain.length; i++) {
      if (!toDelete.has(chain[i].key)) lastSurvivingIdx = i;
    }
    for (let i = 0; i <= lastSurvivingIdx; i++) toDelete.delete(chain[i].key);
  }
  for (const b of toDelete.values()) {
    try {
      (await bastionClient.fileBackupDelete(s3, b.key));
      log('info', 'File Backup pruned (retention)', { deviceId, key: b.key });
    } catch (e) {
      log('warn', 'File Backup prune delete failed', { deviceId, key: b.key, error: e.message });
    }
  }
}

// Core fire-and-forget run — shared by the manual "Backup Now"/"Incremental Backup Now" routes and
// the scheduled poller below, so retention pruning + history tracking behave identically either
// way. kind='incremental' can come back from bastion as an ACTUAL 'full' (no prior backup to chain
// from yet, or the prior one has no readable manifest) — backup_kind always records what bastion
// actually ran, never what was requested, so the history/list UI is never misleading. A skipped
// incremental (no changes since the last backup) is tracked as its own 'skipped' status rather than
// 'completed' (no S3 object was created) or 'failed' (nothing went wrong) — see the UI's rendering
// for how that's surfaced.
async function startFileBackupRun(deviceId, userId, kind) {
  const requestedKind = kind === 'incremental' ? 'incremental' : 'full';
  const { s3, encryptionPassword } = (await resolveFileBackupSettingsForOwner(userId));
  if (!s3.bucket || !s3.accessKey || !s3.secretKey)
    return { ok: false, error: "Set up this device owner's S3 bucket in the File Backup tab first" };
  if (!encryptionPassword) return { ok: false, error: 'Set your backup encryption password first' };
  const already = (await db.prepare("SELECT id FROM file_backup_runs WHERE device_id=? AND kind='backup' AND status='running'").get(deviceId));
  if (already) return { ok: false, error: 'A backup is already running for this device', runId: already.id };
  const bastionClient = require('./bastionClient');
  const runId = randomUUID();
  const folders = (await getFileBackupFolders(deviceId));
  (await db.prepare("INSERT INTO file_backup_runs (id,device_id,kind,status,started_at,backup_kind) VALUES (?,?,'backup','running',?,?)").run(runId, deviceId, Date.now(), requestedKind));
  bastionClient.fileBackupRun(deviceId, { ...s3, encryptionPassword }, folders, requestedKind)
    .then(async result => {
      const status = !result.ok ? 'failed' : (result.skipped ? 'skipped' : 'completed');
      const actualKind = result.kind || requestedKind;
      (await db.prepare('UPDATE file_backup_runs SET status=?,s3_key=?,size_bytes=?,profiles=?,error=?,completed_at=?,backup_kind=? WHERE id=?')
        .run(status, result.key || null, result.size || 0,
             result.profiles ? JSON.stringify(result.profiles) : null,
             !result.ok ? (result.error || 'unknown error') : (result.skipped ? (result.reason || 'no changes since last backup') : null),
             Date.now(), actualKind, runId));
      log(result.ok ? 'info' : 'warn', 'File Backup run finished', { deviceId, ok: result.ok, key: result.key, kind: actualKind, skipped: !!result.skipped, error: result.error, detail: result.detail });
      if (result.ok && !result.skipped) {
        try { (await pruneFileBackups(deviceId, s3)); }
        catch (e) { log('warn', 'File Backup prune failed', { deviceId, error: e.message }); }
      }
    })
    .catch(async e => {
      (await db.prepare('UPDATE file_backup_runs SET status=?,error=?,completed_at=? WHERE id=?').run('failed', e.message, Date.now(), runId));
      log('error', 'File Backup run failed', { deviceId, error: e.message });
    });
  return { ok: true, runId, status: 'running', kind: requestedKind };
}

// ── File backup (account keys/S3 config, per-device run/restore/download) — routes/file-backup.js ──
require('./routes/file-backup')({ app, db, getFileBackupEncryptionPassword, getFileBackupS3Config, log, randomUUID, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked, resolveFileBackupSettings, setFileBackupEncryptionPassword, setFileBackupS3Config, startFileBackupRun });

// ── S3 Bucket Network Drive (Private + Public shares, direct-to-S3, NEVER routed through the
// server or bastion) ─────────────────────────────────────────────────────────────────────────
// Two independently-scoped encryption passwords (explicit design choice, not a mistake to unify):
//   - Public: ACCOUNT-WIDE, one WebUI field per account — settings['s3_drive_public_enc_pw:'+userId],
//     same UX/shape as getFileBackupEncryptionPassword. Every device under the account uses the
//     same password + the same fixed `public/` prefix, so they can all read/write each other's files.
//   - Private: PER-DEVICE, set on that specific device's own WebUI page —
//     settings['s3_drive_private_enc_pw:'+deviceId]. Isolated from other devices both functionally
//     (each device's client only ever syncs its own prefix) AND cryptographically (a different
//     password per device, unless the owner deliberately reuses one on purpose).
// The S3 bucket/endpoint/access-key/secret-key CONNECTION config is account-wide (one bucket for
// both shares) — settings['s3_drive_s3:'+userId], same shape as FILE_BACKUP_S3_FIELDS.
// Config/secrets are pushed to the device over its own Socket.IO control channel (`set_s3_drive`
// command) exactly like set_vpn/vpnCommand — rclone then runs ON the Windows box and talks to S3
// directly. This feature never touches bastionClient.js/bastion-web.py at all.
// ── S3 bucket network drive — per-account + per-device settings — helpers/s3-drive-settings.js ──
// All twelve accessors are consumed below (routes/s3-drive.js, sockets/connection.js);
// S3_DRIVE_S3_FIELDS and resolveS3DriveSettingsForOwner stay private to the module.
const { buildS3DriveCommand, getS3DriveConfig, getS3DriveEnabled, getS3DrivePrivatePassword,
        getS3DrivePrivatePrefixOverride, getS3DrivePublicPassword, resolveS3DriveOwnerUserId,
        setS3DriveConfig, setS3DriveEnabled, setS3DrivePrivatePassword, setS3DrivePrivatePrefixOverride,
        setS3DrivePublicPassword } =
  require('./helpers/s3-drive-settings')({ db, decryptText, encryptText });

// ── S3 bucket network drive (per-device + account config) — routes/s3-drive.js ──
require('./routes/s3-drive')({ app, buildS3DriveCommand, db, decryptText, emitToDevice, getS3DriveConfig, getS3DriveEnabled, getS3DrivePrivatePassword, getS3DrivePublicPassword, log, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked, resolveS3DriveOwnerUserId, setS3DriveConfig, setS3DriveEnabled, setS3DrivePrivatePassword, setS3DrivePrivatePrefixOverride, setS3DrivePublicPassword });

// ── BitLocker remote enable + recovery-key vault — routes/bitlocker.js ──
const { ingestBitlockerResult } = require('./helpers/ingest-bitlocker-result')({ db, encryptText, log, randomUUID });

require('./routes/bitlocker')({ app, db, decryptText, encryptText, ingestBitlockerResult, log, randomUUID, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked });

// ── SRP / AppLocker audit + deploy — routes/srp.js ──
// ── SRP wildcard-folder guard. Shared by the srp deploy route (injected) and the fleet
// what-ran/approve route below, so it stays in server.js (hoisted function decls). ──
// Mirrors bastion-web.py's _is_dangerous_wildcard_folder() -- defense in depth (the bastion is
// the authoritative enforcement point, since it's the one actually building the AppLocker policy,
// but never rely on a single layer for something this consequential). A folder-wildcard string
// entry (as opposed to a {type:'publisher',...} dict, which is always safe regardless of location)
// targeting Desktop/Downloads/Public/the bare Temp root gets stripped before it ever reaches the
// bastion. Matched on the exact final path component only, same reasoning as the bastion-side copy.
const DANGEROUS_WILDCARD_FOLDER_BASENAMES = new Set(['desktop', 'downloads', 'public', 'temp']);
const { stripDangerousWildcardFolders } = require('./helpers/dangerous-wildcard-folders')({ DANGEROUS_WILDCARD_FOLDER_BASENAMES });

const { fleetFanOut } = require('./helpers/fleet-fan-out')({ decryptText, fleetControllableRemoteAssistDeviceIds });
require('./routes/srp')({ app, fleetFanOut, log, requireAuth, requireDeviceAccess, requireDeviceController, requireFleetAccess, requireRemoteAssistDevice, requireUnlocked, stripDangerousWildcardFolders });

// Remote-assist PowerShell exec & hop2 command — routes/remote-assist/remote-assist-powershell-and-hop2.js
require('./routes/remote-assist/remote-assist-powershell-and-hop2')({ app, db, log, requireAuth, requireDeviceAccess, requireDeviceController, requireRemoteAssistDevice, requireUnlocked });





require('./routes/windows-fleet')({ app, db, decryptText, fleetFanOut, log, raUpdateTargetForDevice, requireAdmin, requireAuth, requireFleetAccess, requireUnlocked, stripDangerousWildcardFolders });

// ── Remote Assist fleet actions (IT audit, winupdate, telemetry, sentry, defender, EDR, arp, powershell) — routes/remote-assist/remote-assist-fleet-actions.js ──
require('./routes/remote-assist/remote-assist-fleet-actions')({ app, emitToDevice, fleetFanOut, ingestArpScanResult, log, requireAuth, requireFleetAccess, requireUnlocked, setArpSweepWatchEnabled, setEdrEnabled, setWinUpdateForceActive });

// ── Tailnet: admin group management + per-device assignment — routes/tailnet.js ──
const { sanitizeSubnet, sanitizeSubnets, tailnetCommand } = require('./helpers/tailnet-helpers')({ TAILNET_UUID, db });

require('./routes/tailnet')({ TAILNET_UUID, TS_TAILNET, app, db, deviceOwnerInfo, emitToDevice, express, getTsApiToken, io, log, requireAdmin, requireAuth, requireUnlocked, sanitizeSubnet, sanitizeSubnets, tailnetCommand });
// Device groups CRUD — routes/device-groups.js
require('./routes/device-groups')({ app, crypto, db, deviceOwnerInfo, express, groupOwnerKey });

// Public-user daily audio-recording quota (3 hours/account/day). The agent uploads record_audio in
// ~60s segments as it captures them (AudioHelper.recordAudio -> SocketManager.sendAudioSegment) —
// but the recording's TOTAL requested duration is still approved/rejected as a whole before capture
// even starts (there's no natural mid-flight metering point: rejecting a session after it's already
// 45 minutes in would strand a partial clip for no benefit), so the cap is enforced at REQUEST time
// against the requested `duration`. Rolling 24h window from first use (mirrors makeRateLimit's
// fixed-window-from-first-hit design elsewhere in this file), keyed per ACCOUNT — not per device —
// since the limit is "N hours per account per day", and a public account's devices share one owner.
const PUBLIC_AUDIO_DAILY_CAP_SEC = 3 * 60 * 60;
const { checkPublicAudioQuota, fmtHm } = require('./helpers/public-audio-quota')({ PUBLIC_AUDIO_DAILY_CAP_SEC, kv });

// Public-user daily recording cap for the Stream (camera) and Screen Clips auto-recordings
// (1 hour/account/day each, tracked as two SEPARATE pools — not a shared budget). Unlike
// record_audio, these are open-ended live sessions with no known duration up front and
// recording is auto-tied to the stream's lifecycle (no separate record on/off control), so
// there's no natural request-time value to pre-charge. Instead this is debited incrementally
// by the surveillance worker loop below, 30s per tick, for whichever of 'camera'/'screen' is
// active on a public-owned device — reusing the same loop that already knows which
// devices/types are live and already force-stops sessions for the (unrelated) 10-min cap.
const PUBLIC_STREAM_REC_DAILY_CAP_SEC = 60 * 60;

// ── Device commands & enrollment approval — routes/device-commands-and-enrollment.js ──
const { audiorecCmdKey, setAudioRecActive, clearAudioRecActive } = require('./helpers/audio-rec-marker')({ io, kv });

// ── User management API (admin only) ──────────────────────────────────────
// Business Account mode is gated behind any ANNUAL plan, the UNLIMITED plan (i.e. everything
// except the cheapest 1device_monthly tier), OR an active/pending free trial (not yet expired) —
// so a trialing account can try it before committing to a paid plan. Mirrors deviceLimitForUser's
// plan-resolution but with a different qualifying set. Admin comps of 'unlimited' or 'hybrid'
// qualify (comp has no monthly/annual distinction, so it's treated as its tier); comp '1device'
// does not by itself, but still qualifies via an active trial if one is running.
// ── User management (admin) + business mode + subusers — routes/user-management.js ──
const { revokeUserSessions } = require('./helpers/revoke-user-sessions')({ log, redisClient, redisEnabled, db });
require('./routes/user-management')({ app, AUTH_SCHEME_PREHASH, COMP_PLANS, COMP_PLAN_LABEL, bcrypt, businessModeQualifies, computeAuthPrehash, db, decryptText, encryptText, hwidHmac, log, looksLikeAuthHash, looksLikeAuthSalt, newAuthSalt, normIdent, notifyAdminForUser, notifyAdminLogin, requireAdmin, requireAuth, revokeUserSessions, signalAlert, speakeasy, stmts, trialInfo, verifyUserPassword });

// ── Hybrid Managed: "Grant support access" (dedicated support delegate) ───────────────────
// A single, revocable SentinelMDM-support identity per owner, created WITHOUT enabling Business
// Account mode (so the owner keeps camera/audio/screenshot/keylog). It's a `business_sub` row
// (all the existing ZK ownership scoping in requireDeviceAccess/requireDeviceController/requirePerm
// just works) flagged `is_support_delegate=1`, auto-granted FULL perms on every device the owner
// currently owns. The owner's browser re-wraps a copy of the ZK private key under a support code
// they choose (same `_zkRewrapPrivKey` primitive as team sub-users) — the server never sees that
// code or the plaintext key, so ZK is preserved. The credential is long-lived: it keeps working
// for the whole engagement until the owner revokes it (which also kills any live support session).
const SUPPORT_DELEGATE_FULL_PERMS = Object.freeze({
  location:true, photos:true, audio:true, network:true, files:true, calls:true, sms:true,
  apps:true, stream:true, screenshots:true, notifications:true, contacts:true, keylogs:true,
  screentext:true, geofences:true, timeline:true, shell:true, logcat:true, commands:true,
  ra_screenshots:true, edr:true, applocker:true, s3_drive:true, bitlocker:true, boot_iso:true,
});

// ── Account support-access: grant / inspect / revoke delegate access ── routes/support-access.js ──
require('./routes/support-access')({ app, AUTH_SCHEME_PREHASH, PLAN_KEY_BY_PRICE, STRIPE_PLANS, bcrypt, db, encryptText, getUserSubscriptionRow, isValidWrapEnvelope, log, looksLikeAuthHash, looksLikeAuthSalt, notifyAdminForUser, requireAuth, revokeUserSessions, stmts, stripe, upsertStripeSubscription, SUPPORT_DELEGATE_FULL_PERMS });

// Admin support-access impersonation & trial clock — routes/admin-support-access-and-trial-clock.js
require('./routes/admin-support-access-and-trial-clock')({ app, TRIAL_LEN_MS, db, decryptText, log, requireAdmin, requireAuth, signalAlert, trialInfo });

const { wipeUserAccount } = require('./helpers/public-user-wipe')({ DEMO_DEVICE_TABLES, db, decryptText, deviceStatus, emitToDevice, hwidHmac, io, kv, log, normIdent, updateDeviceOwner, userIdentityEmail });

// ── Admin user-detail: wipe / per-device perms / feature flags — routes/admin-user-account.js ──
require('./routes/admin-user-account')({ app, db, decryptText, encryptText, isDeviceLocked, log, requireAdmin, signalAlert, stmts, wipeUserAccount });

// ════ Notifications & alerts (admin config, per-user prefs, alert center) — routes/notifications.js ════
require('./routes/notifications')({ app, AI_REPORT_CATEGORIES, SIGNAL_HYBRID_GROUP, SIGNAL_SENDER,
  USER_ALERT_CATEGORIES, db, isDiscordWebhookUrl, log, notifyAdmin, requireAdmin, requireAuth });
const { alertScopeUserId } = require('./helpers/alert-scope-user-id')();

// ── "Secure my account" — user-initiated ZK compromise recovery ──────────────
// In the zero-knowledge model a login compromise IS a key compromise: the attacker re-derived the
// KEK and unwrapped the EC P-256 private key, so everything wrapped to the owner's STABLE public
// key — past blobs AND all future device telemetry — is exposed. A password change can't undo that
// (and there is no password-change endpoint). The only true fix is to ROTATE THE KEY, which means
// abandoning the data wrapped to the burned one. This runs that re-key via wipeUserAccount() (drops
// all ZK payloads/media, releases the user's devices to their email lineage, pushes zk_pub_key=null
// so devices stop encrypting to the dead key, deletes the account) and revokes EVERY session for the
// user — requireAuth only checks session.authenticated and never reloads the user, so a wiped user's
// sessions (the attacker's included) would otherwise stay live. Recovery = re-register with the SAME
// email, then re-enroll each device FROM THE PHYSICAL DEVICE (signed handshake), which a remote
// attacker does not have — so they cannot follow the owner to the new keypair. Re-auth gated.


// ════ Account security (auth-params, secure, change-email, change-password, 2FA) — routes/account-security.js ════
require('./routes/account-security')({ app, ADMIN_USER, AUTH_PREHASH_ITER, AUTH_SCHEME_PREHASH, EMAIL_CODE_TTL_MS, QRCode,
  TOTP_SECRET, actingUserRow, bcrypt, db, decryptText, encryptText, ensureAuthSalt, esc, genEmailCode, log,
  looksLikeAuthHash, looksLikeAuthSalt, makeRateLimit, normIdent, notifyAdminForUser, notifyAdminLogin,
  requireAuth, revokeUserSessions, sendEmail, sendEmailVerifyCode, sha256hex, speakeasy, totpRateLimit,
  verifyUserPassword, wipeUserAccount });

// Notification prefs, device search & admin provisioning — routes/notif-prefs-device-search-and-provisioning.js
require('./routes/notif-prefs-device-search-and-provisioning')({ app, USER_ALERT_CATEGORIES, db, decryptText, deviceStatus, encryptText, io, isDiscordWebhookUrl, kv, log, notifyUser, randomUUID, redisEnabled, requireAdmin, requireAuth, stmts });

// ── Socket.io ──────────────────────────────────────────────────────────────
// connectedSockets, encryptedDevices, deviceStatus are wired from state.js (~L794)

const { persistDevState } = require('./helpers/persist-dev-state')({ deviceStatus, encryptedDevices, kv, redisEnabled });

// ── Batched telemetry writer (locations + zk_payloads) ──────────────────────────
// Both tables are append-only logs. One autocommit INSERT per event = one WAL fsync per
// event on the single Patroni primary — that fsync rate is the write ceiling. Instead we
// buffer rows in-process and flush them as ONE multi-row INSERT (one commit) every
// TELEMETRY_FLUSH_MS, plus coalesce the per-event `devices` current-location UPDATE to the
// latest position per device (one transaction = one commit). Each replica flushes only its
// OWN buffer — no cross-replica coordination. Trade-offs (acceptable for telemetry, per the
// 30-day-TTL data model): a hard crash loses at most one flush window; on a flush error we
// log-and-drop (bounded memory, no partial-duplicate inserts). The live UI is unaffected —
// the per-event io.emit() still fires immediately in the handler; only durable persistence
// is deferred by up to one window.
const TELEMETRY_FLUSH_MS  = 2000;
const TELEMETRY_FLUSH_MAX = 2000;   // force an out-of-band flush if a buffer reaches this many rows

let   locationBuffer  = [];          // [{ device_id, data, timestamp }]
let   zkPayloadBuffer = [];          // [{ device_id, event_type, payload, dek_wrapped, timestamp }]
const deviceLocLatest = new Map();   // device_id -> [last_lat, last_lng, last_seen, battery]  (coalesced)

// pg-promise multi-row INSERT column sets (Postgres path only; pgp is null-safe in sqlite mode).
const locColSet = pgp && new pgp.helpers.ColumnSet(['device_id', 'data', 'timestamp'], { table: 'locations' });
const zkColSet  = pgp && new pgp.helpers.ColumnSet(['device_id', 'event_type', 'payload', 'dek_wrapped', 'timestamp'], { table: 'zk_payloads' });

// A finalized session's clip stays "resumable" for this long — a late segment (network outage
// longer than AUDIO_SEGMENT_STALE_MS) arriving within this window appends onto the SAME media row
// instead of starting a fresh accumulation and splitting the recording into two separate clips.
// Generous on purpose: the only cost of a too-long window is a stale Redis key (trivial), whereas
// too-short recreates the exact splitting bug this exists to fix, just for longer outages.
const AUDIO_SESSION_RESUME_TTL_SEC = 24 * 60 * 60;


const { finalizeAudioSession } = require('./helpers/finalize-audio-session')({ AUDIO_SESSION_RESUME_TTL_SEC, clearAudioRecActive, db, decryptDevice, decryptText, encryptText, io, kv, log, signalData, stmts });

// A segment arriving for an already-finalized session (see AUDIO_SESSION_RESUME_TTL_SEC above)
// appends directly onto that clip's existing media row instead of accumulating in audio_segments
// again — there's nothing left to "finalize", the byte range just grows in place.
const { appendToAudioMedia, flushLocations, flushZkPayloads } = require('./helpers/telemetry-flush.js')({ db, decryptText, deviceLocLatest, encryptText, getLocationBuffer: () => locationBuffer, getZkPayloadBuffer: () => zkPayloadBuffer, isPg, locColSet, log, pgConn, pgp, setLocationBuffer: (v) => { locationBuffer = v }, setZkPayloadBuffer: (v) => { zkPayloadBuffer = v }, stmts, zkColSet });

let _telemetryFlushing = false;
const { flushTelemetry } = require('./helpers/flush-telemetry.js')({ flushLocations, flushZkPayloads, getTelemetryFlushing: () => _telemetryFlushing, setTelemetryFlushing: (v) => { _telemetryFlushing = v } });
const { enqueueLocation, enqueueZkPayload } = require('./helpers/telemetry-enqueue.js')({ TELEMETRY_FLUSH_MAX, deviceLocLatest, flushTelemetry, getLocationBuffer: () => locationBuffer, getZkPayloadBuffer: () => zkPayloadBuffer });

const _telemetryFlushTimer = setInterval(() => { flushTelemetry().catch(() => {}); }, TELEMETRY_FLUSH_MS);
if (_telemetryFlushTimer.unref) _telemetryFlushTimer.unref();   // the listen socket keeps the process alive, not this timer

// Flush remaining buffers on graceful shutdown (Docker SIGTERM during a stop-first rolling deploy),
// then exit. Attaching a signal listener overrides Node's default-terminate, so we must exit ourselves.
let _shuttingDown = false;
const { gracefulShutdown } = require('./helpers/graceful-shutdown.js')({ _telemetryFlushTimer, flushTelemetry, getShuttingDown: () => _shuttingDown, log, setShuttingDown: (v) => { _shuttingDown = v } });
process.on('SIGTERM', () => { gracefulShutdown('SIGTERM'); });
process.on('SIGINT',  () => { gracefulShutdown('SIGINT'); });

// One-time tokens (socket auth, APK download, sideload install, WebView hand-off) now
// live in Redis (see redis.js `kv`) so they work across replicas. Only connection-scoped,
// non-serialisable state stays in-process: fileChunkBuffers holds live upload reassembly
// for a device socket and is naturally pinned to the replica holding that socket.
const fileChunkBuffers   = new Map(); // "deviceId:path" -> { chunks, totalChunks, received, timer, path, name }

const { socketReqCtx } = require('./helpers/socket-req-ctx')();

const { consumeEnrollmentTicket } = require('./helpers/enrollment-ticket')({ bindDeviceToOwner, db, deviceLimitForUser, deviceLockState, encryptText, log, stmts, userIdentityEmail });

const { resolveDeviceOwnerFlags } = require('./helpers/resolve-device-owner-flags')({ db, log });

io.use(async (socket, next) => {
  const auth = socket.handshake.auth || {};

  // Wipe-stable hardware id (ESID/serial) the agent self-reports for trial-abuse dedup (v2).
  // Self-reported → used ONLY for alert-only flagging, never for access control. Capped length.
  socket.hwId = (auth.hwId || '').toString().slice(0, 256);

  // ── Browser / monitor client ─────────────────────────────────────────────
  if (auth.token && await kv.exists('socktok:' + auth.token).catch(() => false)) {
    socket.isMonitor = true;
    return next();
  }
  if (socket.request.session?.authenticated) {
    socket.isMonitor = true;
    return next();
  }

  // ── Rescue mode: admin-flagged orphaned device signals to re-enroll ──
  // Set via POST /api/enrollment/:deviceId/rescue (admin only).
  // Does NOT bypass signature verification — instead returns 'rescue_pending' so the
  // device (≥2.5.7.0) clears keyEnrolled and reconnects with its real public key.
  // The re-enrolled key goes through the normal pending queue — admin must approve it.
  // This prevents: (1) signature bypass (any string accepted), (2) attacker injecting
  // their own public key via auto-approve during the rescue window.
  if (auth.deviceId && await kv.exists('rescue:' + auth.deviceId).catch(() => false)) {
    if (auth.timestamp && auth.signature) {
      // Signature still fails (key is missing), but return 'rescue_pending' instead of
      // 'Invalid signature' so the device knows to switch to enrollment auth.
      log('info', 'Rescue mode: signalling device to re-enroll', { deviceId: auth.deviceId });
      return next(new Error('rescue_pending'));
    }
    // Device has re-enrolled with its real public key — route through normal enrollment queue.
    // Admin must still approve in the enrollment tab. The rescue:<id> Redis key stays until enrollment
    // is approved or the 30-min timer expires, preventing repeated rescue_pending loops.
    if (auth.publicKey) {
      log('info', 'Rescue mode: device re-enrolling — queuing for admin approval', { deviceId: auth.deviceId });
      const existing = (await stmts.getPendingKey.get(auth.deviceId));
      if (!existing) {
        (await stmts.insertPendingKey.run(auth.deviceId, auth.model || '', auth.androidVersion || '', auth.publicKey, Date.now(), null));
        io.to('monitors').emit('enrollment_update');
        notifyAdmin(`🔔 Rescued Device Re-Enrolling\nDevice ID: ${auth.deviceId}\nModel: ${auth.model || 'unknown'}\n\nApprove in the Device Enrollment panel.`);
      }
      return next(new Error('pending_approval'));
    }
  }

  // ── Key-based device auth (post-migration) ───────────────────────────────
  // Device sends { deviceId, timestamp, signature } — no shared secret needed.
  if (auth.deviceId && auth.timestamp && auth.signature) {
    if ((await verifyDeviceSignature(auth.deviceId, auth.timestamp, auth.signature))) {
      socket.isDevice = true;
      socket.authDeviceId = auth.deviceId;   // SECURITY: bind socket identity to the signature-authed device (finding #1)
      // Rebind-after-wipe: an already-enrolled device may present a fresh ticket to re-bind to a
      // same-identity account. The verified signature above proves physical possession, so a stolen
      // admin session cannot do this without the device. The 'register' handler then pushes the new
      // owner's ZK key. Benign ticket failures are ignored (device just connects as-is).
      if (serverUnlocked && auth.enrollmentTicket) {
        const r = (await consumeEnrollmentTicket(auth.deviceId, auth.enrollmentTicket, {}));
        if (r.ok) {
          // justEnrolled in BOTH cases: a reused (no-op) consume still warrants key_enrolled so a
          // stale client that keeps re-presenting a spent ticket gets told to clear it.
          socket.justEnrolled = true;   // → register handler emits key_enrolled (device clears ticket) + registered(new zkPubKey)
          if (r.reused) {
            // No-op: device already bound to the ticket's account — a stale client re-sent the
            // spent ticket on a reconnect. Quiet by design (nothing changed, no quota spent);
            // the regular register path emits registered normally.
            log('info', 'Device re-presented spent installer ticket on reconnect (no-op, quota preserved)', { deviceId: auth.deviceId, ownerId: r.userId });
          } else {
            log('info', 'Device re-bound via ticket (key-auth)', { deviceId: auth.deviceId, ownerId: r.userId });
            notifyAdmin(`✅ Device re-enrolled\nDevice ${auth.deviceId} re-bound to account "${r.username}" after account recovery.`);
          }
        } else if (r.violation) {
          (await signalAlert('🚨 Device Lock Violation', `Ticket re-bind rejected for device ${auth.deviceId}: ${r.reason}`, socketReqCtx(socket), auth.deviceId));
        }
      }
      // SECURITY: resolve ownerIsPublicUser NOW (handshake time), not later inside the async
      // 'register' handler — closes a window where a plaintext private-data event arriving right
      // after connect (before register() finishes its own owner query) could slip past the
      // `if (socket.ownerIsPublicUser) return` ZK ingest guard undetected. register() re-resolves
      // the same fields moments later from its own query — this is a harmless, idempotent redo.
      (await resolveDeviceOwnerFlags(socket, auth.deviceId));
      return next();
    }
    // Device may have been deleted by admin — check if its key is in pending_device_keys.
    // If the signature is valid against the pending key, return pending_approval so the
    // device shows in the enrollment tab and the admin can re-approve it.
    const pendingRow = (await stmts.getPendingKey.get(auth.deviceId));
    if (pendingRow?.public_key) {
      const ts = parseInt(auth.timestamp);
      if (ts && Math.abs(Date.now() - ts) <= 60_000 &&
          verifyWithPublicKey(pendingRow.public_key, auth.deviceId, auth.timestamp, auth.signature)) {
        log('info', 'Deleted device reconnecting — pending re-enrollment', { deviceId: auth.deviceId });
        return next(new Error('pending_approval'));
      }
    }
    // No key on file for this device at all (e.g. the server DB was reset). We can't verify a
    // signature we have no key for, so signal the agent to re-enroll: it clears keyEnrolled and
    // reconnects with its public key (→ queued for admin approval, or auto-enrolled if it also
    // presents a valid ticket). No bypass — re-enrollment still requires approval or a ticket.
    const knownKey = (await stmts.getDeviceKey.get(auth.deviceId));
    if (!knownKey?.public_key && !pendingRow?.public_key) {
      log('info', 'Signature-auth from device with no key on file — signalling re-enroll', { deviceId: auth.deviceId });
      return next(new Error('rescue_pending'));
    }
    log('warn', 'Socket rejected — invalid device signature', { deviceId: auth.deviceId, ip: socket.handshake.address });
    return next(new Error('Invalid signature'));
  }

  // ── New device enrollment ────────────────────────────────────────────────
  // Device sends { publicKey, deviceId, model?, androidVersion? }.
  if (auth.publicKey && auth.deviceId) {
    // Key already approved — let the device connect and tell it to switch to key-based auth.
    const approvedRow = (await stmts.getDeviceKey.get(auth.deviceId));
    if (approvedRow?.public_key === auth.publicKey) {
      socket.isDevice = true;
      socket.authDeviceId = auth.deviceId;   // SECURITY: bind socket identity to the authed device (finding #1)
      socket.justEnrolled = true;
      (await resolveDeviceOwnerFlags(socket, auth.deviceId));   // SECURITY: see comment on the key-auth branch above
      return next();
    }
    // Auto-enroll: a valid single-use ticket binds + permanently locks the device with NO admin
    // approval. The device proves possession via the public key it just generated (TOFU).
    if (serverUnlocked && auth.enrollmentTicket) {
      const r = (await consumeEnrollmentTicket(auth.deviceId, auth.enrollmentTicket, {
        publicKey: auth.publicKey, model: auth.model, androidVersion: auth.androidVersion,
        platform: auth.platform, agentKind: auth.agentKind,
      }));
      if (r.ok) {
        socket.isDevice = true;
        socket.authDeviceId = auth.deviceId;   // SECURITY: bind socket identity to the authed device (finding #1)
        socket.justEnrolled = true;   // → register handler emits key_enrolled + registered(zkPubKey)
        log('info', 'Device auto-enrolled via ticket', { deviceId: auth.deviceId, ownerId: r.userId });
        notifyAdmin(`✅ Device auto-enrolled\nDevice ${auth.deviceId} (${auth.model || 'unknown'}) permanently bound to account "${r.username}".`);
        (await notifyPush('enrollment', '✅ Device auto-enrolled', `${auth.model || auth.deviceId} → ${r.username}`, '/'));
        io.to('monitors').emit('enrollment_update');
        (await resolveDeviceOwnerFlags(socket, auth.deviceId));   // SECURITY: see comment on the key-auth branch above — ownership just changed via consumeEnrollmentTicket, so this reflects the NEW owner immediately
        return next();
      }
      if (r.violation) {
        (await signalAlert('🚨 Device Lock Violation', `Auto-enroll rejected for device ${auth.deviceId}: ${r.reason}`, socketReqCtx(socket), auth.deviceId));
        return next(new Error('locked_to_other_account'));
      }
      // Benign ticket failure (expired / replayed / consumed) → fall through to manual approval.
      // Logged only (no Signal) — a missed key_enrolled can cause a harmless duplicate ticket send.
      log('warn', 'Enrollment ticket invalid/expired — falling back to manual approval', { deviceId: auth.deviceId, reason: r.reason });
    }
    // Not yet approved — queue for admin review (idempotent: skip if already queued).
    const existing = (await stmts.getPendingKey.get(auth.deviceId));
    if (!existing) {
      // Match enrollment token → user so admin sees the device pre-assigned in the enrollment panel
      let enrollUserId = null;
      if (auth.enrollmentToken) {
        const tokenUser = (await db.prepare("SELECT id FROM users WHERE enrollment_token=?").get(auth.enrollmentToken));
        if (tokenUser) enrollUserId = tokenUser.id;
      }
      (await stmts.insertPendingKey.run(auth.deviceId, auth.model || '', auth.androidVersion || '', auth.publicKey, Date.now(), enrollUserId));
      log('info', 'New device enrollment pending approval', { deviceId: auth.deviceId, enrollUserId });
      io.to('monitors').emit('enrollment_update');
      notifyAdmin(`🔔 New Device Enrollment\nDevice ID: ${auth.deviceId}\nModel: ${auth.model || 'unknown'}\nAndroid: ${auth.androidVersion || 'unknown'}\nIP: ${socket.handshake.address}\n\nApprove or reject in the User Management panel.`);
      (await notifyPush('enrollment', '🔔 New Device Enrollment', `Model: ${auth.model || auth.deviceId}`, '/'));
    }
    return next(new Error('pending_approval'));
  }

  log('warn', 'Socket rejected — bad auth', { socketId: socket.id, ip: socket.handshake.address });
  (await signalAlert('🔴 Unauthorized Socket Connection',
    `Socket connection rejected — no valid auth token or session.`,
    {
      headers: socket.handshake.headers,
      ip: socket.handshake.address,
      socket: { remoteAddress: socket.handshake.address },
    }
  ));
  next(new Error('Unauthorized'));
});

// ── Hoisted for sockets/connection.js ──────────────────────────────────────
// These five module-scope bindings are used inside the socket connection handler,
// which now lives in sockets/connection.js and is wired in BELOW. Its ctx object is
// built at require() time, so a `const` declared after that point is in its TDZ and
// the require() throws at boot. Each is shared with code that stays here, so none of
// them could simply travel into the module; they are hoisted above the require site
// instead (same treatment as MAX_SUPPORT_MSG / HONEYPOT_MGMT_KEY). All six are
// self-contained at definition time: five are literals or read process.env directly,
// and buildVariant is an arrow whose only reference (variantFromFilename) is a
// hoisted function declaration that it calls later, never at definition time.
//
// Only `const`/`let` actually need this. A `function` declaration hoists, so
// fifteen other ctx deps declared below this point are fine even though they
// read the same way here -- but a `const` read out of the require() call's
// argument object throws during boot. check-ctx.py enforces both halves.
// Unlock photos are capped to match the Unlock Attempts tab's display limit
// (mediaListUnlock LIMIT 100). Anything older is never shown, so it's purged from
// storage rather than retained under the looser shared RETAIN_MEDIA budget.
const RETAIN_UNLOCK_PHOTOS  = 100;
// the last analysis (lastAnalyzedTs cursor) — a complete record independent of the agent's
// volatile buffer. For ZK devices the agent sends today's plaintext screen text (the only
// legal source — before on-device ZK encryption). The server NEVER persists that plaintext —
// it is processed in-memory only and discarded. A deliberate ZK exception gated by explicit
// owner consent in the WebUI.
const SCREENTEXT_SCHEDULE_KEY = 'scheduled_screentext_analysis:';
const buildVariant = (b) => (b && (b.variant || variantFromFilename(b.name || ''))) || 'raven';
const AUTO_CALIB_MAX_GPS_ACC_M = 20;      // only learn from fixes this accurate or better
const TRACKER_ALERT_MIN_RSSI = -75;                 // close-range only: ambient -80+ dBm noise never alerts (panel only)
// a network route to the honeypot), the WORKER polls every 5 min and caches the bad-IP set in Redis
// (`honeypot:badips`); ALL replicas hydrate a local copy. A live socket connection from a known-bad IP
// pages admin (deduped 6h/IP) and notifies the honeypot (-> fleet-correlation event).
// ⚠️ Honeypot-banned SOURCE IPs are ALREADY firewall-dropped fleet-wide via the ban-distributor->ipset
// chain, so this is mostly redundant for sources; the genuine value is the propagation-window gap and
// C2-DESTINATION IPs the fleet does not block outbound. FULLY INERT (zero network calls) until wired.
const HONEYPOT_FEED_URL = (process.env.HONEYPOT_FEED_URL || '').trim();
const { getScreentextSchedule, setScreentextSchedule } = require('./helpers/screentext-schedule')({ SCREENTEXT_SCHEDULE_KEY, db });

// Socket.IO connection handler: 77 device/monitor event handlers — sockets/connection.js
// Socket.IO connection handler: 77 device/monitor event handlers
// (device + monitor sockets: encryption handshake, register, media, telemetry,
// geofence, BT, trackers, file transfer, disconnect) — sockets/connection.js
// 74 ctx deps. getServerUnlocked is a live getter, NOT the value: server.js sets
// serverUnlocked=true when the encrypted store opens (POST /api/unlock), and 30
// guards inside read it — a by-value capture would freeze boot-time false and
// every device upload would be silently dropped, forever.
const { startOfTodayUtcTs } = require('./helpers/start-of-today-utc')();
const { applyBtSafelist } = require('./helpers/apply-bt-safelist')();
const { getBtSafelist, setBtSafelist } = require('./helpers/bt-safelist')({ db });
const { honeypotSighting, refreshHoneypotFeed } = require('./helpers/honeypot-feed')({ HONEYPOT_FEED_URL, HONEYPOT_MGMT_KEY, getHoneypotBadDomains: () => _honeypotBadDomains, getHoneypotBadIps: () => _honeypotBadIps, kv, notifyAdmin, setHoneypotBadDomains: (v) => { _honeypotBadDomains = v }, setHoneypotBadIps: (v) => { _honeypotBadIps = v } });
// ── DB cleanup ────────────────────────────────────────────────────────────────
// Retention limits per device
const RETAIN_LOCATIONS_DAYS = 30;   // time-based TTL (was keep:500 rows — starved the per-day history view)
const RETAIN_MEDIA          = 300;
const RETAIN_NETWORK_DAYS   = 30;   // time-based TTL like the rest of telemetry (was keep:50 rows —
                                    // starved the 7-day WiFi/BT positioning memory: chatty devices
                                    // blew through 50 snapshots in ~2h, leaving computeRfFix
                                    // nothing to search)
const RETAIN_CALL_LOGS      = 30;
const RETAIN_SMS            = 30;
const RETAIN_APP_LISTS      = 30;
const RETAIN_KEYLOGS_DAYS   = 30;
const RETAIN_LOGS_DAYS      = 30;
const RETAIN_STATUS_EVENTS  = 1000;
const RETAIN_RECORDINGS     = 100;

const { runDbCleanup } = require('./helpers/db-cleanup.js')({ RETAIN_APP_LISTS, RETAIN_CALL_LOGS, RETAIN_KEYLOGS_DAYS, RETAIN_LOCATIONS_DAYS, RETAIN_LOGS_DAYS, RETAIN_MEDIA, RETAIN_NETWORK_DAYS, RETAIN_RECORDINGS, RETAIN_SMS, RETAIN_STATUS_EVENTS, RETAIN_UNLOCK_PHOTOS, db, getENC_KEY: () => ENC_KEY, log, maybeAlertTrialLapse, r2Del, r2List, shopStmts, stmts });

const { runTrialSweep } = require('./helpers/trial-sweep')({ DAY_MS, TRACKER_LOGIN_URL, TRIAL_DAYS_ACCOUNT, TRIAL_LEN_MS, TRIAL_WIPE_GRACE_MS, db, decryptText, log, notifyAdminForUser, publicAccountAlertPolicy, sendEmail, userHasActiveSubscription, wipeUserAccount });
let trialSweepScheduled = false;
const { scheduleTrialSweep } = require('./helpers/schedule-trial-sweep.js')({ IS_WORKER, getTrialSweepScheduled: () => trialSweepScheduled, log, runTrialSweep, setTrialSweepScheduled: (v) => { trialSweepScheduled = v } });

// Run 5 minutes after unlock (migration finishes first), then every 24 h
let cleanupScheduled = false;
const { scheduleCleanup, sendDailyIntegrityReport } = require('./helpers/cleanup-and-integrity.js')({ IS_WORKER, decryptText, getCleanupScheduled: () => cleanupScheduled, log, notifyAdmin, runDbCleanup, scheduleTrialSweep, setCleanupScheduled: (v) => { cleanupScheduled = v }, stmts });

// Fire ~15 min after startup, then every 24 h (worker/standalone only — avoids 3× Signal spam)
if (IS_WORKER) {
  setTimeout(async () => {
    (await sendDailyIntegrityReport());
    setInterval(sendDailyIntegrityReport, 24 * 60 * 60 * 1000).unref();
  }, 15 * 60 * 1000).unref();
}

// Sweep for zombie sockets every 30s
setInterval(async () => {
  let changed = false;
  for (const [id, sock] of connectedSockets) {
    if (!sock.connected) {
      connectedSockets.delete(id);
      markOffline(id);
      (await stmts.setOffline.run(id));
      changed = true;
      log('warn', 'Zombie socket swept', { deviceId: id });
    }
  }
  if (changed) io.emit('devices_updated');
  log('debug', 'Heartbeat sweep', { onlineDevices: connectedSockets.size });

  // Cross-replica stale-presence reconciliation. A device's Redis 'online_devices' entry is only
  // srem'd by the disconnect handler, which NEVER runs when a replica dies abruptly (force-replaced
  // container, crash, OOM) — the WebUI then shows the device "Online" forever even though no socket
  // exists on any replica. The zombie sweep above can't see that: it only scans THIS process's
  // in-memory map. Here we compare the set against live sockets across ALL replicas (socket.data
  // carries deviceId, propagated by the redis adapter) and reap anything with no live socket.
  if (redisEnabled) {
    try {
      const members = new Set(await kv.smembers('online_devices'));
      const liveIds = new Set(connectedSockets.keys());
      for (const s of await io.fetchSockets()) {
        const did = s.data && s.data.deviceId;
        if (did) liveIds.add(did);
      }
      // Reap: entries with no live socket on any replica (abruptly-killed replica).
      for (const id of members) {
        if (liveIds.has(id)) continue;
        await kv.srem('online_devices', id);
        try { (await stmts.setOffline.run(id)); } catch (_) {}
        io.emit('devices_updated');
        log('warn', 'Reaped stale online_devices entry (no live socket on any replica)', { deviceId: id });
      }
      // Re-add: a live device whose sadd was lost (e.g. a fire-and-forget kv.sadd that
      // silently failed, with no subsequent reconnect to re-mark it) must not stay invisible
      // to the WebUI indefinitely — self-heal within one sweep. Redis has no persistence
      // (--appendonly no), so a lost sadd is permanent until the next register otherwise.
      for (const id of liveIds) {
        if (members.has(id)) continue;
        await kv.sadd('online_devices', id);
        log('warn', 'Re-added live device to online_devices (sadd was missing from set)', { deviceId: id });
      }
    } catch (e) {
      log('warn', 'online_devices reconciliation failed', { err: e.message });
    }
  }
}, 30_000);

// ── Per-device telemetry reads: calls / sms / apps / battery / geofences / keylogs / screen-text ── routes/device-telemetry.js ──
require('./routes/device-telemetry')({ app, ALL_ROWS, db, decryptText, kv, maybeRespondWithZkPayloads, requireAuth, requireDeviceAccess, requirePerm, stmts });

// ── "Ask AI" — Screen-text analysis via OpenCode ─────────────────────
// ⚠️ DELIBERATE, CONSENT-GATED ZK EXCEPTION (owner-approved 2026-06-01).
// This is the ONLY place screen-text plaintext is permitted to transit the
// server, and ONLY as a transient proxy to the AI provider AFTER the browser
// user has accepted an explicit data-privacy disclosure. The browser supplies the
// already-decrypted text (it holds the ZK key, the server does not). Hard rules:
//   • NEVER persist the logs, the prompt, or the model reply to DB / disk / R2.
//   • NEVER write the plaintext to a log line (no console.log of req.body / reply).
//   • Hold it in memory only for the lifetime of the request, then discard.
// The AI key lives only server-side (Docker secret) so it is never exposed to
// the client. The rest of the zero-knowledge model is unchanged: nothing here is
// stored, and every other endpoint still returns opaque blobs for ZK devices.

const { arpAiSummaryDue, generateArpAiSummary } = require('./helpers/arp-ai-summary')({ OPENCODE_FALLBACK_MODELS, OPENCODE_MODEL, db, log, opencodeApiKey, postOpencode });

const { callOpenCodeScreenText } = require('./helpers/opencode-screen-text')({ OPENCODE_FALLBACK_MODELS, OPENCODE_MODEL, crypto, log, opencodeApiKey, postOpencode });

// Hard ceiling on the log/screen-text payload forwarded to the AI provider (chars). Dense network
// logs tokenise heavily (timestamps/IPs/ports/package names ≈ 2-3 chars/token), so the old
// 3M-char cap could exceed the model's input window and bounce off the provider with an
// error. The client also caps the ROWS it sends per submission and only marks THOSE rows
// "sent" — so this server slice is a backstop, not a silent data-loss path. Slice from the
// END (client orders oldest→newest) to keep the most recent activity. Env-overridable.
// 1M chars ≈ 250–500K tokens (dense logs) — fits mimo-v2.5 / DeepSeek V4 contexts; 3M was
// sized for gemini-2.5-flash's 1M-token window and only drives up latency+cost on Go models.
const AI_LOG_PAYLOAD_MAX_CHARS = Number(process.env.AI_LOG_PAYLOAD_MAX_CHARS) || 1000000;

// Server-side rate-limit backstop. The client also limits (UX), but localStorage
// is trivially bypassable and the AI key is shared + billable, so we enforce
// the same 5-per-15-min budget here per authenticated user.
const AI_RATE_MAX = 5;
const AI_RATE_WINDOW_MS = 15 * 60 * 1000;
const { aiRateAllow } = require('./helpers/ai-rate-allow')({ AI_RATE_MAX, AI_RATE_WINDOW_MS, kv });

// Per-PUBLIC-USER daily Ask-AI budget. The model is DeepSeek V4 Flash (cheap), so
// public accounts get a hard daily cap on top of the global 5-per-15-min backstop:
//   • "submit"    = a fresh analysis (first turn, no prior model reply): 6 / day
//   • "follow-up" = any continuation (a model reply already exists):     6 / day
// Rolling 24h fixed window, shared across replicas (Redis), fail-closed (billable key).
// Submit cap = 4 scheduled (every 6h) + 2 manual Ask-AI per day.
const AI_PUBLIC_SUBMIT_MAX   = 6;
const AI_PUBLIC_FOLLOWUP_MAX = 6;
const AI_DAY_SEC = 24 * 60 * 60;
const { aiDailyAllow } = require('./helpers/ai-daily-allow')({ AI_DAY_SEC, AI_PUBLIC_FOLLOWUP_MAX, AI_PUBLIC_SUBMIT_MAX, kv });

// ── Scheduled screen-text analysis (every 6 hours): server-store source (non-ZK) ──
// The daily report historically analyzed the AGENT's volatile in-memory buffer, which
// is capped, cleared on flush, lost on process restart, and skipped entirely when empty
// (e.g. after an APK update gap) — so a day with stored data could produce NO report.
// For non-ZK devices the server itself stores every screen_text_data event in
// screen_text_entries (encryptText'd, decryptable server-side), so that store is the
// authoritative source: we pull the window since the last successful analysis
// (lastAnalyzedTs cursor), decrypt + format, and run the AI. ZK devices keep the
// agent-logs path (the server never sees their plaintext).


// ── Screentext analysis safety net (worker-only) ──────────────────────────────
// If the agent never fired its scheduled event (device offline / deep-sleep at the
// scheduled time, or the event was lost), the run would be silently skipped. Every
// 10 min the worker sweeps devices with an ENABLED schedule that have
// NOT been analyzed within the cooldown window and still have stored screen text newer
// than the incremental lastAnalyzedTs cursor, and runs the analysis server-side.
// lastAnalyzedAt enforces the cooldown between runs; lastAnalyzedTs keeps each run
// incremental so nothing is missed.
if (IS_WORKER) {
  const SCREENTEXT_ANALYSIS_COOLDOWN_MS = 5.5 * 60 * 60 * 1000;
  const screentextSafetyInFlight = new Set();
  setInterval(async () => {
    try {
      const rows = await db.prepare("SELECT key,value FROM settings WHERE key LIKE 'scheduled_screentext_analysis:%'").all();
      for (const row of rows) {
        const deviceId = row.key.slice(SCREENTEXT_SCHEDULE_KEY.length);
        if (!deviceId || screentextSafetyInFlight.has(deviceId)) continue;
        let sched;
        try { sched = JSON.parse(row.value); } catch { continue; }
        if (!sched.enabled) continue;
        // Cooldown check — skip if analyzed recently
        if (sched.lastAnalyzedAt && (Date.now() - sched.lastAnalyzedAt) < SCREENTEXT_ANALYSIS_COOLDOWN_MS) continue;
        // If never analyzed, don't beat the device's first scheduled local time.
        // Once at least one analysis has run, the cooldown alone governs timing.
        if (!sched.lastAnalyzedAt) {
          const schedTzMs = (Number.isFinite(sched.timeZoneOffsetMinutes) ? sched.timeZoneOffsetMinutes : 0) * 60000;
          const localNow = new Date(Date.now() + schedTzMs);
          const schedLocal = new Date(localNow);
          schedLocal.setUTCHours(sched.hour ?? 0, sched.minute ?? 0, 0, 0);
          if (Date.now() < schedLocal.getTime() - schedTzMs) continue;
        }
        // Respect the device's configured quiet hours (device-local) — the agent-side scheduler
        // honors them, so MUST this net: after the first analysis the cooldown free-runs on its
        // own 5.5h cadence, which walks straight through the night for idle devices (reports
        // landing at e.g. 03:51 local despite "quiet 23:00–07:00" in the WebUI). Skip quietly;
        // a later 10-min tick retries once the window has passed. Same semantics as the agent's
        // isQuietHoursAt(): start==end disables quiet hours entirely.
        {
          const qs = Number.isFinite(sched.quietHoursStart) ? sched.quietHoursStart : 23;
          const qe = Number.isFinite(sched.quietHoursEnd) ? sched.quietHoursEnd : 7;
          const tzMs = (Number.isFinite(sched.timeZoneOffsetMinutes) ? sched.timeZoneOffsetMinutes : 0) * 60000;
          const h = new Date(Date.now() + tzMs).getUTCHours();
          const inQuiet = qs <= qe ? (h >= qs && h < qe) : (h >= qs || h < qe);
          if (inQuiet) continue;
        }
        // Skip analysis when the device is offline — no point running AI on stale data.
        // The sweep retries on the next 10-min tick once the device reconnects.
        if (!(await isDeviceOnline(deviceId))) continue;
        if (!opencodeApiKey()) continue;
        const sinceTs = sched.lastAnalyzedTs ?? startOfTodayUtcTs();
        const hasNew = (await db.prepare('SELECT COUNT(*) AS c FROM screen_text_entries WHERE device_id=? AND timestamp>=?').get(deviceId, sinceTs));
        if (!hasNew || !hasNew.c) continue;
        const logRows = (await stmts.listScreenTextSince.all(deviceId, sinceTs, ALL_ROWS));
        if (!logRows.length) continue;
        screentextSafetyInFlight.add(deviceId);
        try {
          const tzOffsetMinutes = sched.timeZoneOffsetMinutes ?? 0;
          const logText = buildScreentextLogFromRows(logRows, tzOffsetMinutes);
          if (logText.length < 100) continue;
          await runScreentextAnalysis(deviceId, logText, {
            entryCount: logRows.length,
            fromTs: logRows[0].timestamp,
            toTs: logRows[logRows.length - 1].timestamp,
          });
        } finally {
          screentextSafetyInFlight.delete(deviceId);
        }
      }
    } catch (e) {
      log('error', 'screentext safety-net sweep error', { error: e.message });
    }
  }, 10 * 60 * 1000);
}

// Ask AI: screen-text analysis via OpenCode — routes/ai-screen-text.js
require('./routes/ai-screen-text')({ app, AI_LOG_PAYLOAD_MAX_CHARS, aiDailyAllow, aiRateAllow, callOpenCodeScreenText, opencodeApiKey, requireAuth, requireDeviceAccess, requirePerm });


// ── Scheduled screen-text analysis result (stored for WebUI follow-up) ────
const SCREENTEXT_RESULT_KEY = 'screentext_schedule_result:';
const { getScreentextResult, setScreentextResult } = require('./helpers/screentext-result')({ SCREENTEXT_RESULT_KEY, decryptText, encryptText, getDb: () => db });

// ── Screentext AI rolling memory ──────────────────────────────────────────────
// Per-device rolling memory of past daily reports so each new analysis can build on an
// understanding of the device over time. Entries are encrypted at rest (same as the result
// reply) and capped so the history stays bounded (COPPA-friendly, no unbounded retention).
const SCREENTEXT_MEMORY_KEY = 'screentext_ai_memory:';
const SCREENTEXT_MEMORY_MAX = 14;
const { buildScreentextMemoryContext, getScreentextMemory, pushScreentextMemory } = require('./helpers/screentext-memory')({ SCREENTEXT_MEMORY_KEY, SCREENTEXT_MEMORY_MAX, decryptText, encryptText, getDb: () => db });
const { buildScreentextLogFromRows, runScreentextAnalysis } = require('./helpers/screentext-core')({ aiDailyAllow, aiRateAllow, buildScreentextMemoryContext, decryptText, decryptDevice, getAiLogPayloadMaxChars: () => AI_LOG_PAYLOAD_MAX_CHARS, getCallOpenCodeScreenText: (systemText, contents, opts) => callOpenCodeScreenText(systemText, contents, opts), getDb: () => db, getScreentextMemory, getScreentextSchedule, kv, log, notifySecurityAlert, notifyUser, pushScreentextMemory, setScreentextResult, setScreentextSchedule, stmts });

// Screen-text schedule & AI history — routes/screentext-schedule-and-history.js
require('./routes/screentext-schedule-and-history')({ SCREENTEXT_MEMORY_KEY, SCREENTEXT_RESULT_KEY, app, db, emitToDevice, getScreentextResult, getScreentextSchedule, log, requireAuth, requireDeviceAccess, requireDeviceController, requireUnlocked, setScreentextSchedule });

// ── Device AI log review (OpenCode) — routes/ai-logs.js ──
require('./routes/ai-logs')({ AI_LOG_PAYLOAD_MAX_CHARS, aiDailyAllow, aiRateAllow, app, callOpenCodeScreenText, opencodeApiKey, requireAuth, requireDeviceAccess });

// ── File manager + stream recordings + device logs — routes/files-recordings-logs.js ──
require('./routes/files-recordings-logs')({ app, ALL_ROWS, checkStorageQuota, db, decryptBuffer, decryptText, deviceOwnerInfo, encryptBuffer, fs, io, kv, log, maybeRespondWithZkPayloads, path, r2Del, r2Get, r2Put, randomUUID, requireAdmin, requireAuth, requireDeviceAccess, requirePerm, requireUnlocked, stmts, streamsDir, uploadsDir });

// ── Remote APK update ─────────────────────────────────────────────────────
const APK_R2_KEY = 'apk/sentinel.apk';   // legacy single-slot key (kept for migration)

// ── Variant-aware OTA dispatch (raven / stallion / tegu / stock) ──────────────────────────
// A device can ONLY self-update to an APK signed with the SAME key it already runs, so each build
// carries a `variant` and each device is mapped to one; every push path dispatches only the
// matching variant. (A wrong-variant push fails safe — Android rejects it as
// INSTALL_FAILED_UPDATE_INCOMPATIBLE, a no-op, never a brick.)
const APK_VARIANTS = ['raven', 'stallion', 'tegu', 'tangorpro', 'stock'];
const APK_VARIANT_LABEL = { raven: 'Pixel 6 Pro (SentinelOS)', stallion: 'Pixel 10a (SentinelOS)', tegu: 'Pixel 9a (SentinelOS)', tangorpro: 'Pixel Tablet (SentinelOS)', stock: 'Stock Android' };
// SHA-256 of each variant's signing cert (lower-case) → variant. Authoritative when the agent
// reports its own signer (register.signerSha256).
// APK signing-cert SHA-256 (lowercase) -> variant name. Supply JSON via APK_SIGNER_MAP,
// e.g. {"<sha256>":"stock"}. Empty by default; Android's same-signer update rule still applies.
const SIGNER_TO_VARIANT = (() => {
  try { return JSON.parse(process.env.APK_SIGNER_MAP || '{}'); }
  catch { return {}; }
})();
const { getActiveBuildForVariant, setActiveBuildForVariant, setActiveBuildsMap, variantFromFilename } = require('./helpers/apk-build-variants')({ buildVariant, getApkBuilds, getDb: () => db });

const { deviceVariant, selectBuildForDevice } = require('./helpers/device-variant')({ SIGNER_TO_VARIANT, getActiveBuildForVariant });
require('./routes/device-commands-and-enrollment')({ APK_UPDATE_PIN, BUSINESS_MODE_BLOCKED_COMMANDS, COMMAND_PERMS, LIVE_INPUT_COMMANDS, SURVEIL_START_CMDS, SURVEIL_STOP_CMDS, app, audiorecCmdKey, cachedDeviceOwnerInfo, checkPublicAudioQuota, clearAudioRecActive, db, decryptDevice, decryptText, deviceOwnerInfo, emitToDevice, encryptText, getApkBuildById, io, isDeviceLocked, isDeviceOnline, kv, log, mintApkToken, notifyOwnerForCommand, requireAdmin, requireAuth, requireDeviceAccess, selectBuildForDevice, setAudioRecActive, signalFeature, stmts, surveilStart, surveilStop, updateDeviceOwner });

// ── Auto-discovery: import agent APKs dropped directly into R2 ────────────────────────────────
// A build machine can upload built APKs straight to R2 under apk/incoming/ (e.g.
// `wrangler r2 object put sentinel-db/apk/incoming/SentinelMDM-2.8.6.0.apk --file=… --remote`,
// or the release pipeline). The server scans that prefix, registers each NEW APK as a
// hosted build (parsing version + variant from the filename), MOVES it to the canonical
// apk/builds/<id>.apk key, then deletes the inbox copy — so no manual dashboard upload is needed.
// Idempotent: move-semantics + SHA-256 dedup mean a re-scan is a no-op, and a kv.setNX lock keeps
// the worker timer and the manual "Scan R2" button from double-importing across replicas.
// NB: apk/incoming/ is under the SINGULAR apk/ prefix, so runDbCleanup()'s `apks/` (plural)
// ephemeral-token purge never touches it.
const INCOMING_APK_PREFIX = 'apk/incoming/';
const { scanIncomingApks } = require('./helpers/apk-inbox-scan')({ INCOMING_APK_PREFIX, apkBuildR2Key, crypto, getActiveBuildId, getApkBuilds, kv, log, r2, r2Del, r2Get, r2List, r2Put, randomUUID, saveApkBuilds, setActiveBuildId, variantFromFilename });

// One-time migration: fold a legacy single apk_meta into the builds list so the
// existing hosted APK (and any device queued against it) keeps working.
(async function migrateLegacyApkMeta() {
  await dbReady;
  try {
    if ((await getApkBuilds()).length) return;
    const row = (await db.prepare("SELECT value FROM settings WHERE key='apk_meta'").get());
    if (!row) return;
    const m = JSON.parse(row.value);
    const id = randomUUID();
    const build = { id, name: m.name, version: m.version || null, size: m.size || 0,
                    label: 'legacy', uploaded_at: m.uploaded_at || Date.now(), r2Key: APK_R2_KEY };
    (await saveApkBuilds([build]));
    (await setActiveBuildId(id));
    log('info', 'Migrated legacy apk_meta into apk_builds', { id, name: m.name });
  } catch (e) { /* non-fatal */ }
})();

// Backfill build.variant (from filename) + seed the per-variant active map from the legacy single
// active build, so existing hosted builds keep dispatching to the right fleet after the upgrade.
(async function migrateApkVariants() {
  await dbReady;
  try {
    const builds = (await getApkBuilds());
    let changed = false;
    for (const b of builds) if (!b.variant) { b.variant = variantFromFilename(b.name); changed = true; }
    if (changed) (await saveApkBuilds(builds));
    if (!(await db.prepare("SELECT value FROM settings WHERE key='apk_active_builds'").get())) {
      const map = {};
      const legacyId = (await getActiveBuildId());
      const legacyBuild = legacyId ? builds.find(b => b.id === legacyId) : null;
      if (legacyBuild) map[buildVariant(legacyBuild)] = legacyBuild.id;
      (await setActiveBuildsMap(map));
      log('info', 'Seeded per-variant active APK map', map);
    }
  } catch (e) { /* non-fatal */ }
})();

// Seed the OS source-tag / SPL the published OTA was built from (admin edits via /api/os-status).
(async () => {
  await dbReady;
  try {
    if (!(await db.prepare("SELECT value FROM settings WHERE key='os_source_tag'").get()))
      (await db.prepare("INSERT INTO settings (key,value) VALUES ('os_source_tag','2026052400') ON CONFLICT(key) DO NOTHING").run());
    if (!(await db.prepare("SELECT value FROM settings WHERE key='os_spl'").get()))
      (await db.prepare("INSERT INTO settings (key,value) VALUES ('os_spl','2026-05-05') ON CONFLICT(key) DO NOTHING").run());
  } catch (e) { /* non-fatal */ }
})();

// Remote APK update: admin upload — routes/apk-build-upload.js
require('./routes/apk-build-upload')({ APK_VARIANTS, app, apkBuildR2Key, express, getApkBuilds, log, r2Put, randomUUID, requireAdmin, requireUnlocked, saveApkBuilds, setActiveBuildId, variantFromFilename });

// ── APK build catalogue (public/client artefacts, scan, activate) — routes/apk-builds.js ──
require('./routes/apk-builds')({ app, APK_VARIANTS, APK_VARIANT_LABEL, CLIENT_APK_R2_KEY, DeleteObjectCommand, PUBLIC_APK_R2_KEY, PutObjectCommand, R2_BUCKET, buildVariant, db, express, getActiveApkBuild, getActiveBuildForVariant, getActiveBuildId, getApkBuildById, getApkBuilds, log, r2, r2Del, requireAdmin, requireAuth, requireUnlocked, saveApkBuilds, saveClientApkMeta, savePublicApkMeta, scanIncomingApks, setActiveBuildForVariant, setActiveBuildId });

// ── Mass device update + single-device APK dispatch — routes/apk-mass-update.js ──
require('./routes/apk-mass-update')({ APK_UPDATE_PIN, APK_VARIANTS, APK_VARIANT_LABEL, SIGNER_TO_VARIANT, app, buildVariant, connectedSockets, db, decryptText, deviceVariant, emitToDevice, getActiveApkBuild, getActiveBuildForVariant, getApkBuildById, getApkBuilds, isDeviceOnline, kv, log, mintApkToken, redisEnabled, requireAdmin, requireUnlocked, selectBuildForDevice });

// ── OS status + device data (sideload, notifications, clipboard, contacts, calendar, usage) — routes/os-status-device-data.js ──
require('./routes/os-status-device-data')({ app, connectedSockets, db, decryptText, emitToDevice, encryptBuffer, express, isDeviceOnline, kv, log, maybeRespondWithZkPayloads, r2Del, r2Put, randomUUID, redisEnabled, requireAdmin, requireAuth, requireDeviceAccess, requireUnlocked });



// ── Tracker alert dedup ─────────────────────────────────────────────────────────
// ── Tracker alert dedup ─────────────────────────────────────────────────────────
// tracker_detection fires every scan cycle (~15s) while a tracker is present. The contract:
//   • a given tracker (stable identity = Samsung privacy ID / Google EID, else MAC) alerts
//     AT MOST ONCE while it keeps being seen — continuous presence never re-alerts;
//   • it only alerts AGAIN if it was seen again after being ABSENT for ≥24h (i.e. it
//     genuinely left and came back a day or more later — a plausible new encounter);
//   • a NEW tracker appearing is a new detection and alerts.
// Records live in Redis (kv), shared across replicas, so a device socket moving between
// replicas can't re-trigger an alert for the same detection. Per-identity: { a: lastAlertTs,
// s: lastSeenTs }. The 7-day TTL (refreshed on every detection) lets the record survive an
// absence window long enough to enforce the 24h rule, while a >7-day absence counts as a
// brand-new detection (record expired).
const TRACKER_ALERT_REARM_MS = 24 * 60 * 60 * 1000; // re-alert only after ≥24h absence
const TRACKER_DEDUP_TTL_SEC = 7 * 24 * 60 * 60;     // record TTL (7 days)
const TRACKER_MAX_ALERTS_PER_HOUR = 6;              // per-device soft cap — new tags in crowds can't flood alerts
const _trackerNotifFallback = new Map();            // per-process fallback if Redis is unavailable

const { trackerAlertNeeded } = require('./helpers/tracker-alert-needed')({ TRACKER_ALERT_REARM_MS, TRACKER_DEDUP_TTL_SEC, TRACKER_MAX_ALERTS_PER_HOUR, _trackerNotifFallback, kv });

// ── Geofence alert notification cooldown ─────────────────────────────────────────
// A device sitting near a fence boundary produces enter/exit flip-flops (GPS jitter).
// Transitions are still recorded in the geoalerts history + relayed to the live monitor
// (the panel/map stay accurate), but out-of-band notifications (push, All Alerts,
// Signal/Discord) are limited to one per (fence, transition) per cooldown window, so
// boundary jitter can't spam. Redis-backed, shared across replicas.
const GEOFENCE_ALERT_COOLDOWN_MS = 15 * 60 * 1000;   // 15 min per fence+transition
const _geofAlertFallback = new Map();                // per-process fallback if Redis is unavailable

const { geofenceAlertDue } = require('./helpers/geofence-alert-due')({ GEOFENCE_ALERT_COOLDOWN_MS, _geofAlertFallback, kv });

// ── Geofence oscillation (flap) collapse ───────────────────────────────────────────
// Defense-in-depth below the on-device anti-flap logic (AospGeofenceManager's hysteresis
// + settle + persisted state). Field devices running older APKs still emit raw GPS-jitter
// flip-flops: "enter/exit/enter/exit…" for a fence the device never actually left. This
// guard runs BEFORE history/monitor/notifications so suppressed flaps don't pollute the
// Geofences tab alert history either. Per (device, fence):
//   - a repeat of the SAME transition within the window is a duplicate (you cannot "enter"
//     twice without an "exit" in between) → dropped;
//   - the first opposite transition is kept — a real drive-through is enter → exit;
//   - the 3rd+ rapid flip is oscillation → everything for that fence is muted until the
//     state stays quiet for a full window, then real movement alerts resume.
// DWELL is not a boundary flip (inside→inside): it gets its own one-per-window dedupe and
// never touches the enter/exit flap counter, so enter → dwell → exit stays intact.
const GEOFENCE_FLAP_WINDOW_MS = 2 * 60 * 1000;
const _geofFlapFallback = new Map();                 // per-process fallback if Redis is unavailable

const { geofenceAcceptTransition } = require('./helpers/geofence-accept-transition')({ GEOFENCE_FLAP_WINDOW_MS, _geofFlapFallback, kv });

// Bluetooth safelist, scan history & proximity — routes/bluetooth-safelist-and-proximity.js
require('./routes/bluetooth-safelist-and-proximity')({ app, applyBtSafelist, db, decryptText, getBtSafelist, maybeRespondWithZkPayloads, requireAuth, requireDeviceAccess, requireUnlocked, setBtSafelist, stmts });

// ── Indoor-positioning anchors: auto-calibration engine ─────────────────────────
// Anchors LEARN their own positions: whenever a device reports an accurate GPS fix
// (≤ AUTO_CALIB_MAX_GPS_ACC_M), every nearby WiFi/BT reading (RSSI ≥ AUTO_CALIB_MIN_RSSI)
// is treated as a VOTE for that device's location — weighted by signal strength (a strong
// reading means the anchor is close to that spot) and GPS quality. Each anchor accumulates
// weighted samples in Redis; once it has enough low-scatter samples it is persisted into
// proximity_anchors (origin='auto', ref_rssi = strongest RSSI ever seen = the ~1m value).
// Manual anchors are never overwritten. Passive — the operator just carries the device.
const AUTO_CALIB_MIN_RSSI = -85;          // readings weaker than this are noise, not votes
const AUTO_CALIB_MIN_SAMPLES = 5;         // samples before an anchor is considered ready
const AUTO_CALIB_MAX_SPREAD_M = 12;       // max position scatter (m) to be "ready"
const AUTO_CALIB_SAMPLE_CAP = 40;         // rolling sample window per anchor
const AUTO_CALIB_REWRITE_MIN_MOVE_M = 5;  // only rewrite the persisted anchor if moved ≥ this
// ⚠️ A calibration vote must describe where the device was WHEN THE SCAN WAS TAKEN.
// network_events snapshots are only emitted on connectivity changes (see
// MonitoringService.sendNetworkSnapshot — not periodic), so "latest snapshot" can be many
// hours stale; the BT snapshot likewise freezes when scanning stops. Voting a stale
// snapshot at the CURRENT fix pinned fixed APs' anchors in a different town (home router
// saved at the office, etc.) and drew multi-mile "fix → anchor" lines on the map.
const AUTO_CALIB_SNAPSHOT_ALIGN_MS = 10 * 60 * 1000; // scan↔location pairing window
const AUTO_CALIB_LIVE_FALLBACK_MS  = 2 * 60 * 1000;  // fresh scan → live-fix fallback
const AUTO_CALIB_MIN_INTERVAL_MS   = 30 * 1000;      // per-device calibration throttle
const _autoCalibLastAt = new Map();                  // deviceId -> last pass ts

// RF fix sanity gates (see filterFixPoints).
const RF_REF_MAX_AGE_MS    = 30 * 60 * 1000;  // latest GPS fix usable as a reference
const RF_REF_MAX_ACC_M     = 1000;            // ...only when at least this trustworthy
const RF_ANCHOR_MAX_DIST_M = 3000;            // anchors farther than this from it are junk
const RF_CLUSTER_SPAN_M    = 1000;            // no reference: keep the strongest cluster only

const { isValidRssi, wifiRssi } = require('./helpers/wifi-rssi')();
const { anchorRefOrDefault, approxDistM, isRandomizedMac, latestDeviceLocation, locationAtTime, wifiReadingsFromSnapshot } = require('./helpers/wifi-location')({ AUTO_CALIB_SNAPSHOT_ALIGN_MS, db, decryptText, isValidRssi, wifiRssi });

const { filterFixPoints } = require('./helpers/filter-fix-points')({ RF_ANCHOR_MAX_DIST_M, RF_CLUSTER_SPAN_M, RF_REF_MAX_ACC_M, RF_REF_MAX_AGE_MS, approxDistM });

// Collect one vote for every nearby anchor seen at (lat,lng). Fire-and-forget.
const { persistAutoAnchor } = require('./helpers/persist-auto-anchor')({ AUTO_CALIB_REWRITE_MIN_MOVE_M, db, isValidRssi, log });
const { autoCalibrateAnchors } = require('./helpers/auto-calibrate-anchors')({ AUTO_CALIB_LIVE_FALLBACK_MS, AUTO_CALIB_MAX_GPS_ACC_M, AUTO_CALIB_MAX_SPREAD_M, AUTO_CALIB_MIN_INTERVAL_MS, AUTO_CALIB_MIN_RSSI, AUTO_CALIB_MIN_SAMPLES, AUTO_CALIB_SAMPLE_CAP, _autoCalibLastAt, decryptText, getDb: () => db, isRandomizedMac, isValidRssi, kv, locationAtTime, log, persistAutoAnchor, stmts, wifiReadingsFromSnapshot });


// ── Fleet-learned tower positions ──────────────────────────────────────────────
// OpenCellID positions are crowdsourced estimates — often 1+ km off on thin-sample
// towers. Whenever a device reports an accurate GPS fix (≤20 m) while camped on an
// IDENTIFIABLE serving cell, that's a vote for where that tower really is. Votes
// accumulate in Redis; once a tower has enough SIGNAL-weighted votes forming a RING
// around it (2-axis spread gate — votes from one spot echo the spot, votes along one
// road echo the road; both are rejected), the centroid persists to
// cell_towers.learned_* ALONGSIDE the OCID columns.
// OSM snap: a learned centroid within OSM_SNAP_MAX_M of a mapped comms mast snaps to
// the mast (steel is exact; centroids are approximate).
const TOWCALIB_MIN_SAMPLES = 20;          // votes before a learned position is considered
const TOWCALIB_SAMPLE_CAP = 200;          // rolling window per tower
const TOWCALIB_REWRITE_MIN_MOVE_M = 100;  // only rewrite the learned pos if moved ≥ this
const LEARNED_MIN_SAMPLES_USE = 20;       // fix prefers learned at ≥ this many votes
const OSM_SNAP_MAX_M = 500;               // snap learned centroid to mast within this
const OSM_NEAR_MAX_M = 3000;              // surface nearest mast within this as a hint

const { nearestOsmMast, servingCellsFromSnapshot, validCellIdentity } = require('./helpers/cell-geometry')({ db });

// One-shot backfill: correlate STORED network snapshots with STORED GPS fixes by
// timestamp (runs inside the server, where ENC_KEY is available — at-rest data stays
// encrypted). Seeds tower votes from months of driving history so learned positions
// converge immediately instead of after weeks of new driving. Bounded + silent.
let _towerBackfillDone = false;
setTimeout(() => backfillTowerVotes().catch(() => {}), 45000);

// ── Cell-tower triangulation ─────────────────────────────────────────────────────
// Tower positions come from OpenCellID (imported + runtime lookups, source='ocid')
// AND from fleet GPS votes (cell_towers.learned_*, preferred once ripe). The fix uses
// the learned position when it has ≥ LEARNED_MIN_SAMPLES_USE votes, else OCID; when
// both exist and disagree, the uncertainty covers the disagreement instead of hiding it.
// A tower position only counts as geographically resolved when it carries a real
// position (source='ocid') — vote-spread gating below is a safety net only.
const CELL_TOWER_CONFIDENT_SPREAD_M = 150;
// Typical cell coverage radius used for the coarse (single-tower) device fix: being
// connected to a known tower bounds the device to roughly this radius around it.
const CELL_TOWER_COVERAGE_RADIUS_M = 1000;

const cellKey = c => `${c.mcc}-${c.mnc}-${c.tac}-${c.cid}`;

const { addTowerVote, voteTowerPositions } = require('./helpers/tower-votes')({ AUTO_CALIB_MAX_GPS_ACC_M, OSM_SNAP_MAX_M, TOWCALIB_MIN_SAMPLES, TOWCALIB_REWRITE_MIN_MOVE_M, TOWCALIB_SAMPLE_CAP, cellKey, decryptText, getDb: () => db, kv, log, nearestOsmMast, servingCellsFromSnapshot, stmts });

const { backfillTowerVotes } = require('./helpers/backfill-tower-votes.js')({ AUTO_CALIB_MAX_GPS_ACC_M, addTowerVote, db, decryptText, getTowerBackfillDone: () => _towerBackfillDone, kv, log, servingCellsFromSnapshot, setTowerBackfillDone: (v) => { _towerBackfillDone = v } });
require('./sockets/connection')({ ALL_ROWS, AUTO_CALIB_MAX_GPS_ACC_M, EventEmitter, HONEYPOT_FEED_URL, LIVE_INPUT_COMMANDS, RA_AUTO_PROVISION_COOLDOWN_MS, RETAIN_UNLOCK_PHOTOS, SCREENTEXT_SCHEDULE_KEY, SIGNAL_SENDER, TAILNET_UUID, TRACKER_ALERT_MIN_RSSI, XRAY_REMOTEASSIST_UUID, XRAY_VPN_UUID, ZK_EVENT_LABELS, _canSendUserNotif, appendToAudioMedia, applyBtSafelist, autoCalibrateAnchors, buildS3DriveCommand, buildScreentextLogFromRows, buildVariant, cancelOfflineGrace, checkStorageQuota, checkTrialLineageAbuse, connectedSockets, crypto, db, decryptDevice, decryptText, deviceEmit, deviceOwnerInfo, deviceStatus, emitRemoteAssistProvision, emitToDevice, encryptBuffer, encryptText, encryptedDevices, enqueueLocation, enqueueZkPayload, fileChunkBuffers, finalizeAudioSession, geofenceAcceptTransition, geofenceAlertDue, getBtSafelist, getS3DriveEnabled, getScreentextSchedule, getServerUnlocked: () => serverUnlocked, honeypotSighting, io, kv, log, markOnline, mintApkToken, normalizeVpn, notifyAdminExempt, notifyAdminForDevice, notifyGeofenceNodeRed, notifyPush, notifyUser, opencodeApiKey, path, persistDevState, persistUserAlert, r2Put, raAutoProvisionAttempts, randomUUID, redisEnabled, runScreentextAnalysis, scheduleOfflineGrace, selectBuildForDevice, serverEncPrivKey, setScreentextSchedule, signalAlert, signalData, socketReqCtx, startOfTodayUtcTs, stmts, stopTheftModeAlerts, surveilStop, syncDeviceDisplayNameToBastion, tailnetCommand, trackerAlertNeeded, voteTowerPositions, vpnCommand });

const { carrierName } = require('./helpers/carrier-name')();

const { latestCells } = require('./helpers/latest-cells')({ decryptText, stmts });

// ── Tower history: every tower this device has EVER camped on (from snapshot history) ──
// The phone can only identify its serving cell (neighbours are signal-only), so over time
// each newly-camped cell becomes an identifiable tower. Plotted as gray markers so the map
// accumulates the device's real tower footprint — the same model CellMapper uses, but from
// this device's own history. Cached briefly (history changes only when a new snapshot lands).
const _cellHistoryCache = new Map(); // deviceId -> { ts, history }
const { towerPosition } = require('./helpers/tower-position')({ LEARNED_MIN_SAMPLES_USE });
const { OCID_MISS_TTL_MS, OCID_TRANSIENT_TTL_MS, _ocidMissCache } = require('./helpers/ocid-miss-cache')();
const { _wigleMissCache } = require('./helpers/wigle-miss-cache')();
const { lookupOcidTower, lookupWigleAP, wigleAuthHeader } = require('./helpers/wigle-ocid-lookup')({ OCID_MISS_TTL_MS, OCID_TRANSIENT_TTL_MS, _ocidMissCache, _wigleMissCache, getDb: () => db, log });
const { loadKnownTowers } = require('./helpers/load-known-towers')({ _ocidMissCache, getCellKey: () => cellKey, getDb: () => db, lookupOcidTower });
const { cellTowerHistory } = require('./helpers/cell-history')({ _cellHistoryCache, carrierName, cellKey, db, decryptText, loadKnownTowers, towerPosition });

// Load towers for the given cell identities (OpenCellID — real positions).
// Misses are resolved against the OpenCellID database when OCID_API_KEY is configured —
// the lookup result is cached in cell_towers (source='ocid') so each unique tower costs
// exactly one external request, ever. Negative results are ALSO cached (miss cache)
// because every indoor-position poll re-asks for the same unknown towers — without it
// the free-tier rate limit trips and misses can never resolve.

// ── WiGLE WiFi-AP resolution ───────────────────────────────────────────────────
// The wardriving DB for "where is this BSSID". Free tier, account required — set
// WIGLE_API_KEY to the site's "Encoded for use" value (or "apiName:apiToken", which
// gets encoded here). Hits persist in wifi_aps forever; misses cache 24h (definitive)
// or 5 min (rate-limit/network). Without a key everything below is a silent no-op.

const { cellDistM } = require('./helpers/cell-dist-m')();


const { computeCellFix } = require('./helpers/cell-fix')({ CELL_TOWER_CONFIDENT_SPREAD_M, CELL_TOWER_COVERAGE_RADIUS_M, OSM_NEAR_MAX_M, carrierName, cellDistM, cellKey, cellTowerHistory, latestCells, loadKnownTowers, nearestOsmMast, towerPosition });

const { computeRfFix } = require('./helpers/rf-fix')({ anchorRefOrDefault, db, decryptText, filterFixPoints, isRandomizedMac, isValidRssi, lookupWigleAP, wifiReadingsFromSnapshot });

// Mapped masts (OSM) & carriers per mast — routes/mapped-masts-and-carriers.js
require('./routes/mapped-masts-and-carriers')({ app, OSM_TILE_TTL_MS, _osmFetchInflight, carrierName, db, fetchOsmTiles, osmCellsForBbox, requireAuth, requireUnlocked, towerPosition });

// ── WiFi APs / indoor anchors / positioning — routes/wifi-aps-anchors-and-positioning.js ──
require('./routes/wifi-aps-anchors-and-positioning')({ app, _cellHistoryCache, anchorRefOrDefault, approxDistM, computeCellFix, computeRfFix, db, decryptText, filterFixPoints, isRandomizedMac, isValidRssi, latestDeviceLocation, log, lookupWigleAP, requireAuth, requireDeviceAccess, requirePerm, requireUnlocked, stmts, validCellIdentity, wifiReadingsFromSnapshot, wigleAuthHeader });

// ── Device ops: anchors / BT state / shell opt-in / watched apps / timeline ── routes/device-ops.js ──
require('./routes/device-ops')({ app, crypto, db, emitToDevice, log, maybeRespondWithZkPayloads, requireAuth, requireDeviceAccess, requireDeviceController, requirePerm, requireUnlocked, stmts });

// ── Timezone-aware recurrence for per-app 'weekly_set' pause/unpause schedules ──
// helpers/timezone.js — DST-safe wall-clock↔UTC conversion (tzOffsetMs and friends).
// Exports only what the scheduled-command worker calls; the rest stay private to the module.
const { wallTimeInTz, nextWeeklySetRun } = require('./helpers/timezone')();

// ── Scheduled commands engine (worker/standalone only — one dispatcher, no triple-fire) ──
// ── Honeypot fleet cross-reference (2026-06-24; env-gated — OFF unless HONEYPOT_FEED_URL is set) ──
// The Sentinel honeypot publishes an IOC feed (attacker IPs + sandbox-extracted C2 IPs) on its
// Tailscale-only mgmt port. When wired (set HONEYPOT_FEED_URL=http://<honeypot-host>:8081/feed/iocs.json
// + provide the mgmt key via the `sentinel_hp_mgmt_key` secret or HONEYPOT_MGMT_KEY, AND give this stack
let _honeypotBadIps = new Set();
let _honeypotBadDomains = new Set();

if (HONEYPOT_FEED_URL) {
  if (IS_WORKER) {   // only the worker fetches from the honeypot + writes Redis
    refreshHoneypotFeed().catch(() => {});
    setInterval(() => { refreshHoneypotFeed().catch(() => {}); }, 5 * 60 * 1000);
  }
  const hydrate = async () => {   // every replica refreshes its local Set from Redis
    try {
      const v = await kv.getJSON('honeypot:badips');
      if (v && Array.isArray(v.ips)) _honeypotBadIps = new Set(v.ips);
      if (v && Array.isArray(v.domains)) _honeypotBadDomains = new Set(v.domains);
    } catch {}
  };
  hydrate();
  setInterval(hydrate, 60 * 1000);
}

const { PHISH_FEED_URL, PHISH_FEED_KEY } = require('./helpers/phish-feed')({ readSecret });
const _phishIntel = {
  c2Ips: new Set(), lowIps: new Set(), c2Domains: new Set(), lowDomains: new Set(), cidrs: [],
};

// Known-benign platform hosts that must NEVER match the domain tier, even if a polluted feed
// entry contains them (found live 2026-08-15: URLhaus lists malware DISTRIBUTED via GitHub
// release links, which put `github.com` in c2Domains — every legit GitHub connection
// (ShareX uploads, git clone) then matched, false-alerted AND got blocked with a hosts
// sinkhole + firewall rule against a real GitHub IP. Same doctrine as the feed builder's
// NEVER_SUFFIX: platform hosts are never C2 infrastructure themselves.) Exact + subdomain
// suffix match, same shape as phishDomainLookup's walk.
const _phishNeverDomains = new Set([
  'github.com', 'githubusercontent.com', 'gitlab.com', 'bitbucket.org', 'sourceforge.net',
  'vercel.app', 'pages.dev', 'netlify.app', 'workers.dev', 'cloudflare.com', 'cloudfront.net',
  'microsoft.com', 'windows.net', 'azure.com', 'google.com', 'googleusercontent.com',
  'gstatic.com', 'amazonaws.com', 'googleapis.com', 'cloudflarerssl.com',
]);
const { phishNeverDomain } = require('./helpers/phish-never-domain')({ _phishNeverDomains });
const _phishBlockQueued = new Map();   // ip -> last block-queue ms (per-process dedup for the block push)

// Returns {tier:'c2'|'low', kind:'ip'|'asn'|'domain', asn?, name?} for a destination IP/domain,
// or null.
const { PTR_CACHE_MAX, PTR_CACHE_TTL_MS, _ptrCache } = require('./helpers/ptr-cache')();
const { ipv4InCidr, phishDomainLookup, refreshPhishFeed, reverseDnsCached } = require('./helpers/phish-intel-lookups')({ PHISH_FEED_KEY, PHISH_FEED_URL, PTR_CACHE_MAX, PTR_CACHE_TTL_MS, _phishIntel, _ptrCache, kv });
const { phishLookup } = require('./helpers/phish-lookup.js')({ _phishIntel, getHoneypotBadDomains: () => _honeypotBadDomains, getHoneypotBadIps: () => _honeypotBadIps, ipv4InCidr, phishDomainLookup, phishNeverDomain });

// ── Phase 6 reverse-DNS fallback for the domain tier ─────────────────────────────────────────
// Sysmon's Event 3 `DestinationHostname` attribution is inconsistent (Chrome/curl often log the
// v4 connect with an empty hostname — found live 2026-08-14: a browser visit to a c2 pages.dev
// host landed with ip only). Many C2 hosts run on VPSes whose PTR record IS the flagged hostname
// (e.g. feed entry `172-104-49-49.ip.linodeusercontent.com` PTRs back to itself), so a cached
// PTR lookup on the destination IP closes most of that gap without any agent change. Lookup is
// bounded: per-IP cache (6h TTL, 2000 entries), 2s timeout, only consulted when the event had
// no hostname and no feed match already. Cache misses are cached as null too (a 2s timeout per
// unique new IP is already the worst case).

if (PHISH_FEED_URL) {
  if (IS_WORKER) {   // only the worker fetches the feed + writes Redis
    refreshPhishFeed().catch(() => {});
    setInterval(() => { refreshPhishFeed().catch(() => {}); }, 5 * 60 * 1000);
  }
  const hydrate = async () => {   // every replica refreshes its local state from Redis
    try {
      const v = await kv.getJSON('phish:intel');
      if (v) {
        _phishIntel.c2Ips = new Set(v.c2Ips || []);
        _phishIntel.lowIps = new Set(v.lowIps || []);
        _phishIntel.c2Domains = new Set(v.c2Domains || []);
        _phishIntel.lowDomains = new Set(v.lowDomains || []);
        _phishIntel.cidrs = v.cidrs || [];
      }
    } catch {}
  };
  hydrate();
  setInterval(hydrate, 60 * 1000);
}

// ── Combined C2 destination blocklist (2026-08-15) ────────────────────────────
// Merges the phish threat-intel feed (abuse.ch/operator-validated) AND the honeypot's
// accumulated blocklist (attacker + sandbox-observed C2 IPs/domains) into one compact
// publish, consumed by:
//   • per-node `sentinel-c2-apply.sh` (host-firewall ipset DROP for ALL egress, incl. the
//     Android VPN's freedom outbound which exits at the node), and
//   • the xray entrypoint's routing fragment (SNI-sniffed domain rules for the VPN user).
// The never-domain guard list is applied here so platform hosts (github.com etc.) can never
// ride the blocklist even if a feed entry carries them. Worker-only publish (single writer).
const { publishCombinedC2Block } = require('./helpers/publish-c2-block.js')({ _phishIntel, getHoneypotBadDomains: () => _honeypotBadDomains, getHoneypotBadIps: () => _honeypotBadIps, kv, phishNeverDomain });
if (IS_WORKER) {
  publishCombinedC2Block().catch(() => {});
  setInterval(() => { publishCombinedC2Block().catch(() => {}); }, 5 * 60 * 1000);
}

require('./workers/scheduled-commands')({ IS_WORKER, SURVEIL_START_CMDS, SURVEIL_STOP_CMDS, db, decryptDevice, emitToDevice, isDeviceOnline, log, nextWeeklySetRun, notifyOwnerForCommand, stmts, surveilStart, surveilStop, wallTimeInTz });

// ── Auto-import agent APKs from the R2 inbox (worker only — single importer) ──────
// Drop a built APK into apk/incoming/ (push-apks-to-r2.sh / wrangler) and it shows up as a
// hosted build automatically. Lock-guarded, so the manual "Scan R2" button is also safe.
if (IS_WORKER && r2) {
  const scanInbox = () => scanIncomingApks({ trigger: 'timer' })
    .then(r => { if (r.imported?.length) log('info', 'R2 inbox scan imported builds', { count: r.imported.length }); })
    .catch(e => log('error', 'R2 inbox scan error', { err: e.message }));
  setTimeout(scanInbox, 20000);          // shortly after boot so a fresh drop appears fast
  setInterval(scanInbox, 5 * 60 * 1000); // then every 5 minutes
}

require('./workers/monitor-and-arp')({ IS_WORKER, PUBLIC_STREAM_REC_DAILY_CAP_SEC, SURVEIL_LABEL, SURVEIL_MAX_MS, SURVEIL_STOP_CMD_FOR, arpAiSummaryDue, db, decryptText, emitToDevice, fmtHm, generateArpAiSummary, getArpSweepWatchEnabled, ingestArpScanResult, ingestArpSweepEvents, io, kv, log, sendAiReportEmail, surveilNotify });

// ── AI Auto-Audit on Alerts ──────────────────────────────────────────────────────────────────────
// When a new, unhandled user_alert fires for a Windows/Linux Remote Assist device (excludes
// ra_agent_update), this poller triggers an automatic bastion IT audit (14-category forensics →
// OpenCode DeepSeek analysis), feeds the results to a SECOND AI call that cross-references the
// alert context with the audit, and reports the verdict back through notifyUser/notifyAdmin/Signal.
//
// False positives are suppressed: a sha256 fingerprint of (category + device + key indicators
// extracted by the AI) prevents re-auditing the same known-benign pattern. The user can also
// manually request an investigation or remediation from the All Alerts WebUI panel.

const { isDeviceAutoAuditEligible } = require('./helpers/is-device-auto-audit-eligible')({ db });

const { suppressSig } = require('./helpers/suppress-sig')();

// Check if this alert's signature has already been suppressed (deemed a false positive).
let _suppressionCacheConfig = { ttl: 120e3 };
const { isAlertAutoAuditSuppressed } = require('./helpers/is-alert-auto-audit-suppressed')({ db, suppressSig });

// An audit's whole pipeline is hard-bounded well under this (5-min poll cap + AI call + retry), so
// a 'running' row older than this can only be an ORPHAN — the worker died mid-audit (a redeploy is
// the common cause). Deliberately generous: over-eager reaping would double-run a live audit.
const AUDIT_STALE_MS = 15 * 60 * 1000;
// How far back the poller will reach for an alert that never got audited. Bounded on purpose: the
// poller selects by "not yet audited", so with no floor, pruning/clearing audit rows (or a restored
// DB) would resurrect every historical alert at once and page the owner for each.
const AUDIT_BACKLOG_MAX_AGE_MS = 24 * 60 * 60 * 1000;
// Was LIMIT 30 with no unaudited-filter, so the window was consumed by ALREADY-audited alerts
// (re-checked every 30s forever) and capacity was throughput-, not age-, bounded: more than 30
// device alerts inside one tick and the excess fell out of the window permanently, never analyzed —
// silently, the same shape as the orphan bug. Measured 2026-08-04: exactly 30 device alerts existed
// against a LIMIT of 30, i.e. already at the ceiling.
const AUDIT_POLL_LIMIT = 200;
// ⚠️ FEEDBACK-LOOP GUARD. Every auto-audit report is delivered through notifyUser(), which
// PERSISTS it into user_alerts with the device_id and category 'sentry' — precisely the shape the
// worker poller selects. Without this tag the feature audits its OWN output: the AI is handed a
// previous report as if it were a security alert, "analyses" prose instead of a device, and emits
// another report, which becomes another alert. Found live 2026-08-04 from an incoherent report
// ("The device is offline... the alert's mention of a critical finding is not supported by the
// audit data" — it was reading an earlier report about an `offline` alert); at that moment 5 of 7
// device alerts were self-generated, and the loop had already produced a bogus 🚨 REAL THREAT.
// The pre-existing `category != 'ra_agent_update'` exclusion is the same hazard, already known.
// This tag MUST appear in the first line of every report string built below — that is what makes
// the poller's exclusion reliable, so keep the two using this one constant.
const AUTO_AUDIT_REPORT_TAG = 'AI Auto-Audit';
// ⚠️ Bounded. This was an unbounded Set holding one entry per alert ever seen, never evicted — a
// slow leak in a process designed to run for weeks. Map value = when we cached it, which is what
// makes the staleness check below possible at all.
const ALERT_SEEN_CACHE_MAX = 5000;
let _alertSeenCacheConfig = { ids: /** @type {Map<number, number>} */ (new Map()) };

const { _alertRetryMap, markAlertProcessed } = require('./helpers/mark-alert-processed')({ ALERT_SEEN_CACHE_MAX, _alertSeenCacheConfig });
const { generateAccountAiMemory, recordDeviceAiMemory, triggerAutoAuditForAlert } = require('./helpers/alert-ai')({ AUDIT_STALE_MS, AUTO_AUDIT_REPORT_TAG, OPENCODE_FALLBACK_MODELS, OPENCODE_MODEL, _alertRetryMap, _alertSeenCacheConfig, db, decryptText, isAlertAutoAuditSuppressed, isDeviceAutoAuditEligible, log, markAlertProcessed, notifySecurityAlert, notifyUser, opencodeApiKey, postOpencode, suppressSig });

require('./workers/alert-poller')({ AUDIT_BACKLOG_MAX_AGE_MS, AUDIT_POLL_LIMIT, AUDIT_STALE_MS, AUTO_AUDIT_REPORT_TAG, IS_WORKER, db, log, triggerAutoAuditForAlert });

// Alert AI investigate/remediate/approve/reject + AI memory — routes/alert-ai-actions-and-memory.js
require('./routes/alert-ai-actions-and-memory')({ app, OPENCODE_MODEL, alertScopeUserId, db, decryptText, generateAccountAiMemory, io, isDeviceAutoAuditEligible, log, notifySecurityAlert, notifyUser, opencodeApiKey, postOpencode, recordDeviceAiMemory, requireAuth, requireDeviceAccess, triggerAutoAuditForAlert });

require('./workers/watch-pollers')({ IS_WORKER, db, decryptText, deviceOwnerEmail, deviceOwnerInfo, encryptText, getScreenTextEnabled, getSentryEnabled, getUsbLockdownEnabled, io, isAlertAutoAuditSuppressed, isDeviceOnline, learnGate, learnInvalidate, learnNormalizeDetail, log, notifySecurityAlert, notifyUser, stmts });

// ── Force Windows Update Now — completion/stuck poller (worker only — 60s cadence) ─────────
// Gated behind the cheap winupdate_force_active flag, same pattern as the Sentry poller above.
// A terminal status (done/aborted_ceiling/cancelled/failed) clears the flag and fires a
// dual-routed alert; a "rebooting" status that's stayed unreachable well past its own
// pendingRebootExpectedBy is flagged as possibly stuck WITHOUT clearing the flag (the box may
// still come back) — Hop-2 being briefly unreachable during an expected reboot is normal, not a
// failure, so this only escalates once the box is late coming back. LEFT JOIN (not the Sentry
// poller's INNER JOIN) so an admin-fleet/unowned Windows RA device still gets the
// notifySecurityAlert() half even with no owner to notifyUser().
const _winUpdateForceAlerted = new Map(); // deviceId -> {terminal:bool, stuck:bool} dedupe, in-memory + Redis for restart survival

// ── in-memory + Redis helpers ──────────────────────────────────────────
const WU_FORCE_ALERTED_KEY = (id) => `winupdate_force_alerted:${id}`;
// 30-day TTL on the Redis key — a deliberate "forget" when the dedupe is truly stale.
// A new cycle start (genuinely in-progress status) always clears the dedupe explicitly
// (line 14059+), so the TTL is only a GC safety-net, never a correctness dependency.
const WU_FORCE_ALERTED_TTL = 30 * 24 * 3600;

const { _wuGetDedupe, _wuSetDedupe, _wuDelDedupe } = require('./helpers/wu-dedupe')({ WU_FORCE_ALERTED_KEY, WU_FORCE_ALERTED_TTL, _winUpdateForceAlerted, kv });

// ── Statuses that genuinely represent an ACTIVE (not completed) cycle ──
// These are the only statuses that should clear the terminal/stuck dedupe.
// Any status NOT in this set (idle, scheduled_idle, or a transient empty/parse-
// failure read) MUST NOT clear the dedupe — doing so made the next disconnect-
// served cached `done` re-alert on a completed cycle (found live 2026-08-09).
const WU_FORCE_IN_PROGRESS_STATUSES = new Set([
  'starting', 'scanning', 'downloading', 'installing',
  'reboot_pending', 'rebooting', 'relocking',
]);
require('./workers/maintenance-pollers')({ IS_WORKER, WU_FORCE_IN_PROGRESS_STATUSES, _wuDelDedupe, _wuGetDedupe, _wuSetDedupe, db, decryptText, deviceOwnerEmail, deviceOwnerInfo, encryptText, getFileBackupSchedule, getWinUpdateForceActive, ingestBitlockerResult, log, notifySecurityAlert, notifyUser, setWinUpdateForceActive, sha256hex, startFileBackupRun, uploadBlockedFile });

const { handlePhishingProxyHit } = require('./helpers/handle-phishing-proxy-hit')({ EDR_ALERT_SUPPRESS_MS, EDR_NEVER_SUPPRESS_RULES, _phishBlockQueued, deviceOwnerInfo, getEdrAlertSuppressedUntil, isAlertAutoAuditSuppressed, learnGate, learnNormalizeDetail, log, notifySecurityAlert, notifyUser, phishDomainLookup, setEdrAlertSuppressedUntil });

require('./workers/edr-alerts')({ EDR_ALERT_SUPPRESS_MS, EDR_NEVER_SUPPRESS_RULES, IS_WORKER, db, decryptText, deviceOwnerEmail, deviceOwnerInfo, getEdrAlertSuppressedUntil, getEdrEnabled, getEdrLastSeen, handlePhishingProxyHit, isAlertAutoAuditSuppressed, learnGate, learnNormalizeDetail, log, notifySecurityAlert, notifyUser, phishLookup, reverseDnsCached, setEdrAlertSuppressedUntil, setEdrLastSeen });

require('./workers/audio-finalizer')({ IS_WORKER, finalizeAudioSession, kv, log });

// ── Threshold alert checker (cooldown is a Redis TTL key — global across replicas) ──
async function checkThresholdAlerts(deviceId, status) {
  const configs = (await db.prepare('SELECT * FROM alert_config WHERE device_id=? AND enabled=1').all(deviceId));
  for (const cfg of configs) {
    const key = `${deviceId}:${cfg.type}`;
    if (await kv.exists('alertcd:' + key).catch(() => false)) continue; // 10-min cooldown (Redis, global)
    const threshold = parseFloat(cfg.threshold);
    let triggered = false;
    let alertMsg = '';
    const dev = decryptDevice((await stmts.getDevice.get(deviceId)));
    const label = dev ? `${dev.name} • ${dev.model}` : deviceId;
    if (cfg.type === 'battery_low') {
      const batt = status?.battery?.level;
      if (batt != null && batt <= threshold) { triggered = true; alertMsg = `🔋 Low Battery Alert\nDevice: ${label}\nBattery: ${batt}%  (threshold: ${threshold}%)`; }
    } else if (cfg.type === 'speed_over') {
      const speed = status?.speed;
      if (speed != null && speed >= threshold) { triggered = true; alertMsg = `🚗 Speed Alert\nDevice: ${label}\nSpeed: ${Math.round(speed)} mph  (threshold: ${threshold} mph)`; }
    }
    if (triggered) {
      kv.setJSON('alertcd:' + key, 1, 600).catch(() => {});  // 10-min cooldown TTL
      // Speed alerts are security-critical (exempt — never suppressed; hybrid mirrors to the
      // hybrid group); battery-low is a routine device alert (suppressed for non-hybrid public).
      if (cfg.type === 'speed_over') notifyAdminExempt(alertMsg, deviceId);
      else notifyAdminForDevice(alertMsg, deviceId);
      io.to(`monitor:${deviceId}`).emit('threshold_alert', { deviceId, type: cfg.type, threshold, value: cfg.type === 'battery_low' ? status?.battery?.level : status?.speed });
    }
  }
}


// ── Auto-unlock from Docker secret ────────────────────────────────────────
// If the sentinel_enc_passphrase Docker secret (or ENC_PASSPHRASE env var) is
// present at startup, the server unlocks itself automatically — no manual
// /unlock web-UI entry needed after each container restart.
// Falls back to the manual /unlock page when the secret is absent.
(async function tryAutoUnlock() {
  await dbReady;
  const passphrase = readSecret('sentinel_enc_passphrase', 'ENC_PASSPHRASE');
  if (!passphrase) return; // no secret configured — stay locked until /unlock

  // Time-box + RETRY each attempt. A settings query on a half-dead PG connection can HANG
  // indefinitely (there is no query_timeout), which previously left the replica permanently
  // LOCKED at startup: /health 503 → Swarm health-kills it → recreate → repeat (the slot
  // cycling observed 2026-06-12 during a deploy). Race every query against a short timeout and
  // retry on any transient failure so a startup PG blip self-resolves on the SAME container.
  // Once `serverUnlocked` flips true it is NEVER reset, so /health goes green immediately and any
  // post-unlock step (migration) merely retries in the background. Memory:
  // `swarm-tracker-deploy-rollback-trap`.
  /** @param {Promise<any>} p */
  const t = (p) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('auto-unlock query timed out')), 8000))]);

  for (let attempt = 1; ; attempt++) {
    try {
      const sentinelRow   = (await t(db.prepare(`SELECT value FROM settings WHERE key='enc_sentinel'`).get()));
      const saltRow       = (await t(db.prepare(`SELECT value FROM settings WHERE key='enc_salt'`).get()));
      const iterationsRow = (await t(db.prepare(`SELECT value FROM settings WHERE key='enc_iterations'`).get()));
      const iterations = iterationsRow ? parseInt(iterationsRow.value) : (sentinelRow ? 100_000 : 600_000);
      const result = tryUnlock(passphrase, sentinelRow?.value || null, saltRow?.value || null, iterations);
      if (!result) {
        log('warn', 'Auto-unlock: sentinel_enc_passphrase present but passphrase is WRONG — server stays locked');
        return; // deterministic — retrying won't help
      }
      ENC_KEY = result.key;
      require('./state').ENC_KEY = ENC_KEY;
      serverUnlocked = true;   // /health is green from here; never reset below
      require('./state').serverUnlocked = true;   // keep state.js's accessor in sync (see known-behavior-losses #5)
      if (result.firstRun) {
        const newSalt = crypto.randomBytes(32).toString('base64');
        // result.key was derived with the DEFAULT salt (storedSalt was null on first
        // run). Re-derive with the salt we are about to persist BEFORE writing the
        // sentinel, or the next auto-unlock (which uses the stored salt) won't match.
        ENC_KEY = deriveKey(passphrase, newSalt, iterations);
        require('./state').ENC_KEY = ENC_KEY;
        (await t(db.prepare(`INSERT INTO settings (key,value) VALUES ('enc_salt',?)`).run(newSalt)));
        (await t(db.prepare(`INSERT INTO settings (key,value) VALUES ('enc_iterations',?)`).run(String(iterations))));
        (await t(db.prepare(`INSERT INTO settings (key,value) VALUES ('enc_sentinel',?)`).run(encryptText('SentinelMDM-unlock-v1'))));
        log('info', `Auto-unlock: passphrase set via Docker secret (first run, ${iterations} PBKDF2 iterations)`);
      } else {
        log('info', `Auto-unlock: server unlocked via sentinel_enc_passphrase Docker secret${attempt > 1 ? ` (attempt ${attempt})` : ''}`);
      }
      (await runMigration());
      scheduleCleanup();
      return; // done
    } catch (e) {
      const err = /** @type {any} */ (e);
      log('warn', `Auto-unlock attempt ${attempt} failed — retrying in 5s`, { unlocked: serverUnlocked, error: err && (err.message || String(err)) });
      await new Promise(r => setTimeout(r, 5000));
    }
  }
})();

// ── Start ──────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
// Gate on dbReady so requests never arrive before the Postgres schema is applied.
dbReady.then(() => server.listen(/** @type {number} */ (PORT), '0.0.0.0', () => {
  log('info', `FamilyMon server started`, { port: PORT, node: process.version, pid: process.pid });
}));
