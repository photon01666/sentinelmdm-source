// config.js — Static configuration, environment variables, secrets, R2 client, directories.
// All values are read once at startup. Mutable state (ENC_KEY etc.) lives in state.js.

const path = require('path');

// Comma-separated environment list helper.
const csvEnv = (key) => (process.env[key] || '').split(',').map((v) => v.trim()).filter(Boolean);
const fs   = require('fs');
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, ListObjectsV2Command } = require('@aws-sdk/client-s3');

// ── Docker Secrets helper ─────────────────────────────────────────────────────
function readSecret(secretName, envKey, defaultVal = '') {
  try { return fs.readFileSync(`/run/secrets/${secretName}`, 'utf8').trim(); } catch {}
  return process.env[envKey] || defaultVal;
}

// ── Directories ───────────────────────────────────────────────────────────────
const __dir = __dirname;
const uploadsDir   = path.join(__dir, 'uploads');
const apkDir       = path.join(__dir, 'apk');
fs.mkdirSync(uploadsDir, { recursive: true });
fs.mkdirSync(apkDir,     { recursive: true });

// ── Role split ────────────────────────────────────────────────────────────────
const ROLE = process.env.ROLE || 'standalone';
const IS_WORKER = ROLE !== 'web';

// ── Cloudflare R2 object storage ──────────────────────────────────────────────
const R2_KEY    = readSecret('sentinel_litestream_key_id',     'LITESTREAM_ACCESS_KEY_ID');
const R2_SECRET = readSecret('sentinel_litestream_secret_key', 'LITESTREAM_SECRET_ACCESS_KEY');
const R2_BUCKET = process.env.R2_BUCKET || 'sentinel-db';
const R2_ENDPOINT = process.env.R2_ENDPOINT || '';
const r2 = (R2_KEY && R2_SECRET) ? new S3Client({
  region: 'auto',
  endpoint: R2_ENDPOINT,
  credentials: { accessKeyId: R2_KEY, secretAccessKey: R2_SECRET },
}) : null;

async function r2Put(key, buf) {
  if (!r2) { fs.writeFileSync(path.join(__dir, key.replace('/', path.sep)), buf); return; }
  await r2.send(new PutObjectCommand({ Bucket: R2_BUCKET, Key: key, Body: buf }));
}

async function r2Get(key) {
  if (!r2) {
    const p = path.join(__dir, key.replace('/', path.sep));
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
  if (!r2) { try { fs.unlinkSync(path.join(__dir, key.replace('/', path.sep))); } catch {} return; }
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

// ── Admin credentials ─────────────────────────────────────────────────────────
const ADMIN_USER     = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS     = readSecret('sentinel_admin_pass', 'ADMIN_PASS');
const APK_UPDATE_PIN = readSecret('sentinel_apk_pin', 'APK_UPDATE_PIN');
if (!ADMIN_PASS) {
  console.error('FATAL: admin password not set — define Docker secret sentinel_admin_pass or env ADMIN_PASS');
  process.exit(1);
}
if (!APK_UPDATE_PIN) {
  console.warn('APK_UPDATE_PIN not set — update_app command will be disabled until configured');
}

// ── TOTP ──────────────────────────────────────────────────────────────────────
const speakeasy = require('speakeasy');
let TOTP_SECRET = readSecret('sentinel_totp_secret', 'TOTP_SECRET');
if (!TOTP_SECRET) {
  TOTP_SECRET = speakeasy.generateSecret({ length: 20 }).base32;
  console.log('TOTP_SECRET not set — generated ephemeral secret: [REDACTED]');
  console.log('   Create a Docker secret named sentinel_totp_secret to persist it.');
  console.log('   Scan the QR code at /setup-2fa after first login step.');
}

// ── Signal configuration ──────────────────────────────────────────────────────
const SIGNAL_API_URL = process.env.SIGNAL_API_URL || 'http://signal-api_swarm:8080';
const SIGNAL_SENDER  = readSecret('sentinel_signal_sender', 'SIGNAL_SENDER');
const SIGNAL_GROUP   = readSecret('sentinel_signal_group',  'SIGNAL_GROUP', 'group.Uno2dnN4dWt3c0h6TDhYVGNQdC90RXpTbC91bk9sdldaOGRCMTB0N2pvMD0=');
const SIGNAL_SECURITY_GROUP = readSecret('sentinel_signal_security_group', 'SIGNAL_SECURITY_GROUP',
  'group.QVFiYUkxVVp1SEZTMklMVzJNTUxpdUdxUWx0VUc2ZytkeFFvN1FDaEo4ND0=');
const SIGNAL_HYBRID_GROUP = readSecret('sentinel_signal_hybrid_group', 'SIGNAL_HYBRID_GROUP',
  'group.MmxIRnVjRGp6N1d5UmZrRFA1WEUzaWVIZVBxN3JrZnBwUXlyb0VjNGFnTT0=');

// ── App-layer encryption key ──────────────────────────────────────────────────
const SERVER_ENC_KEY_PEM = readSecret('sentinel_enc_private_key', 'SERVER_ENC_KEY_PEM');

// ── Node-RED alert ────────────────────────────────────────────────────────────
const NODERED_ALERT_URL = (process.env.NODERED_ALERT_URL || 'http://node-red-signal-api_nodered-swarm:1880/admin-login-alert').trim();
const NODERED_ALERT_KEY = (readSecret('sentinel_nodered_alert_key', 'NODERED_ALERT_KEY') || '').trim();

// ── Session secret ────────────────────────────────────────────────────────────
const _sessSecret = readSecret('sentinel_session_secret', 'SESSION_SECRET');

// ── Server origin ─────────────────────────────────────────────────────────────
const SERVER_ORIGIN = process.env.SERVER_ORIGIN || 'http://localhost:3000';

// ── DB path ───────────────────────────────────────────────────────────────────
const DB_PATH = process.env.DB_PATH || path.join(__dir, 'tracker.db');
const DATA_DIR = path.dirname(DB_PATH);
const streamsDir = path.join(DATA_DIR, 'streams');
fs.mkdirSync(DATA_DIR,   { recursive: true });
fs.mkdirSync(streamsDir, { recursive: true });

// ── NOWPayments crypto billing ────────────────────────────────────────────────
const NOWPAYMENTS_API_KEY    = readSecret('nowpayments_api_key',    'NOWPAYMENTS_API_KEY');
const NOWPAYMENTS_IPN_SECRET = readSecret('nowpayments_ipn_secret', 'NOWPAYMENTS_IPN_SECRET');
const CRYPTO_PLAN_PRICES = {
  '1device_monthly':   { usd: 14.99,  label: 'SentinelMDM FamilySafe 5 Devices — 1 Month'   },
  '1device_annual':    { usd: 149.90, label: 'SentinelMDM FamilySafe 5 Devices — 1 Year'    },
  'unlimited_monthly': { usd: 3,      label: 'SentinelMDM Per Device — 1 Month'             },
  'unlimited_annual':  { usd: 30,     label: 'SentinelMDM Per Device — 1 Year'              },
  'hybrid_monthly':    { usd: 15,     label: 'SentinelMDM Hybrid Managed — Per Device, 1 Month' },
  'hybrid_annual':     { usd: 150,    label: 'SentinelMDM Hybrid Managed — Per Device, 1 Year'  },
};
const CRYPTO_SKU_COMP = {
  '1device_monthly':   { plan: '1device',   months: 1  },
  '1device_annual':    { plan: '1device',   months: 12 },
  'unlimited_monthly': { plan: 'unlimited', months: 1  },
  'unlimited_annual':  { plan: 'unlimited', months: 12 },
  'hybrid_monthly':    { plan: 'hybrid', months: 1  },
  'hybrid_annual':     { plan: 'hybrid', months: 12 },
};

// ── Stripe billing ────────────────────────────────────────────────────────────
const STRIPE_SECRET_KEY     = readSecret('stripe_secret_key',     'STRIPE_SECRET_KEY');
const STRIPE_WEBHOOK_SECRET = readSecret('stripe_webhook_secret', 'STRIPE_WEBHOOK_SECRET');
const STRIPE_TRIAL_DAYS     = parseInt(process.env.STRIPE_TRIAL_DAYS || '30', 10);
const TRIAL_DAYS_ACCOUNT    = parseInt(process.env.TRIAL_DAYS || '30', 10);
const TRIAL_WIPE_GRACE_MS   = 48 * 60 * 60 * 1000;
const TRIAL_DEVICE_LIMIT    = parseInt(process.env.TRIAL_DEVICE_LIMIT || '10', 10);

// Per-device model (2026-08-24). Base price covers the first device; each additional device
// is an add-on line at the matching *_EXTRA_DEVICE price. Old flat prices stay resolvable
// (legacy sets below) for grandfathered subscribers.
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
// Legacy price IDs are only needed when migrating grandfathered subscribers.
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
if (HYBRID_LEGACY_PRICE)
  PLAN_META[HYBRID_LEGACY_PRICE] = { label: 'Hybrid Managed (legacy)', amount: 9999, interval: 'month' };
if (UNLIMITED_LEGACY_MONTHLY_PRICE)
  PLAN_META[UNLIMITED_LEGACY_MONTHLY_PRICE] = { label: 'Unlimited (legacy)', amount: 2499, interval: 'month' };
if (UNLIMITED_LEGACY_ANNUAL_PRICE)
  PLAN_META[UNLIMITED_LEGACY_ANNUAL_PRICE]  = { label: 'Unlimited (legacy)', amount: 24990, interval: 'year' };

const PLAN_KEY_BY_PRICE = Object.fromEntries(Object.entries(STRIPE_PLANS).filter(([, v]) => v).map(([k, v]) => [v, k]));
for (const pid of HYBRID_FLAT_LEGACY_PRICES) PLAN_KEY_BY_PRICE[pid] = 'hybrid_monthly';
for (const pid of UNLIMITED_FLAT_LEGACY_PRICES) PLAN_KEY_BY_PRICE[pid] = 'unlimited_monthly';

const COMP_PLANS = new Set(['unlimited', '1device', 'hybrid']);
const COMP_PLAN_LABEL = {
  unlimited: 'Per Device (complimentary)', '1device': '5 Devices (complimentary)',
  hybrid: 'Hybrid Managed (complimentary)',
};

const PUBLIC_USER_DEFAULT_FEATURES = {
  location: true, photos: true, audio: true, screenshots: true,
  stream: true, network: true, files: true, calls: true, sms: true,
  apps: true, contacts: true, notifications: true,
  keylogs: true, screentext: true, geofences: true,
  schedules: true, timeline: true, commands: true,
  connect: true, security: true,
  edr: true, applocker: true,
  file_backup: true, s3_drive: true, bitlocker: true, boot_iso: true,
};

// ── Boot ISO catalog ─────────────────────────────────────────────────────────
// Curated ISOs the WebUI "Boot ISO" RA panel can boot a Windows box into. Each entry
// is { id, name, url (public R2 URL), size (bytes), md5, sha256, isoFile (filename on
// the box + GRUB findiso path), kernel, initrd (paths INSIDE the ISO's /live/ dir) }.
// The download/verify/bcdedit flow lives in the support service (_BOOT_ISO_STAGE_PS1); the
// box downloads the ISO directly from the configured public OTA URL (never through
// the tunnel), verifies SHA-256, then points the Boot Manager at a standalone GRUB on
// the ESP.
//
// ⚠️ The catalog is DB-backed (settings['boot_iso_catalog']) and intentionally STARTS
// EMPTY — an entry only appears in the list once its ISO object actually exists in the
// sentinelmdm-ota R2 bucket. Add ISOs via the WebUI upload (admin, Boot ISO tab → chunks
// to R2 multipart + registers the entry) or publish-boot-iso.sh (CLI, RCLONE_CONFIG_OTA_*)
// then seed the entry into the settings row. NEVER hardcode a default here that isn't
// actually uploaded — the box-side download would 404 and the WebUI would list a phantom
// ISO (found + fixed 2026-08-16: the 13.6.0 default was removed for exactly this reason).
const BOOT_ISO_CATALOG_DEFAULTS = [];
// Boot ISOs are published to the SAME public bucket/domain as OS OTAs (memory
// r2-ota-publish-token — scoped WRITE token; NOT the account-wide one). Uploads from
// the WebUI go through this dedicated client; the litestream sentinel-db client above
// is NOT used for ISO uploads (runDbCleanup() purges that bucket on the 30-day TTL).
// OTA_R2_ENDPOINT is env-overridable so the upload flow can be exercised against a
// local S3 mock in dev/testing without touching the real bucket.
const OTA_R2_ENDPOINT = process.env.OTA_R2_ENDPOINT || '';
const OTA_R2_BUCKET = process.env.OTA_R2_BUCKET || 'sentinelmdm-ota';
const BOOT_ISO_R2_PREFIX = 'boot-iso/';
const otaR2 = (readSecret('sentinel_ota_key_id', 'OTA_ACCESS_KEY_ID') && readSecret('sentinel_ota_secret_key', 'OTA_SECRET_ACCESS_KEY')) ? new S3Client({
  region: 'auto',
  endpoint: OTA_R2_ENDPOINT,
  credentials: {
    accessKeyId: readSecret('sentinel_ota_key_id', 'OTA_ACCESS_KEY_ID'),
    secretAccessKey: readSecret('sentinel_ota_secret_key', 'OTA_SECRET_ACCESS_KEY'),
  },
}) : null;

const DAY_MS = 24 * 60 * 60 * 1000;
const TRIAL_DAYS = { digital_mdm_7: 30, hardware_software_30: 30, os_flash_7: 30 };

// ── Honeypot cross-reference ──────────────────────────────────────────────────
const HONEYPOT_FEED_URL    = (process.env.HONEYPOT_FEED_URL || '').trim();
const HONEYPOT_MGMT_KEY    = (readSecret('sentinel_honeypot_mgmt_key', 'HONEYPOT_MGMT_KEY') || '').trim();

module.exports = {
  readSecret,
  __dir,
  uploadsDir,
  apkDir,
  ROLE,
  IS_WORKER,
  r2Put, r2Get, r2Del, r2List,
  ADMIN_USER, ADMIN_PASS, APK_UPDATE_PIN, TOTP_SECRET,
  SIGNAL_API_URL, SIGNAL_SENDER, SIGNAL_GROUP, SIGNAL_SECURITY_GROUP, SIGNAL_HYBRID_GROUP,
  SERVER_ENC_KEY_PEM,
  NODERED_ALERT_URL, NODERED_ALERT_KEY,
  _sessSecret,
  SERVER_ORIGIN,
  DB_PATH, DATA_DIR, streamsDir,
  NOWPAYMENTS_API_KEY, NOWPAYMENTS_IPN_SECRET, CRYPTO_PLAN_PRICES, CRYPTO_SKU_COMP,
  STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_TRIAL_DAYS,
  TRIAL_DAYS_ACCOUNT, TRIAL_WIPE_GRACE_MS, TRIAL_DEVICE_LIMIT,
  STRIPE_PLANS, PLAN_META, PLAN_KEY_BY_PRICE,
  HYBRID_INCLUDED_DEVICES, HYBRID_EXTRA_DEVICE_AMOUNT, HYBRID_EXTRA_DEVICE_PRICE,
  HYBRID_EXTRA_DEVICE_ANNUAL_PRICE, HYBRID_LEGACY_EXTRA_DEVICE_PRICE, HYBRID_LEGACY9_EXTRA_DEVICE_PRICE,
  THREE_DEVICE_EXTRA_AMOUNT, THREE_DEVICE_EXTRA_PRICE,
  UNLIMITED_INCLUDED_DEVICES, UNLIMITED_EXTRA_DEVICE_AMOUNT, UNLIMITED_EXTRA_DEVICE_PRICE,
  UNLIMITED_EXTRA_DEVICE_ANNUAL_PRICE,
  HYBRID_LEGACY_PRICE, HYBRID_FLAT_LEGACY_PRICES,
  UNLIMITED_LEGACY_MONTHLY_PRICE, UNLIMITED_LEGACY_ANNUAL_PRICE,
  UNLIMITED_FLAT_LEGACY_PRICES, ONEDEVICE_LEGACY_PRICES,
  COMP_PLANS, COMP_PLAN_LABEL,
  PUBLIC_USER_DEFAULT_FEATURES,
  BOOT_ISO_CATALOG_DEFAULTS,
  OTA_R2_BUCKET, BOOT_ISO_R2_PREFIX, otaR2,
  DAY_MS, TRIAL_DAYS,
  HONEYPOT_FEED_URL, HONEYPOT_MGMT_KEY,
};
