// schema/migrations.js — SQLite DDL + schema migrations.
// Called at startup to create tables and add missing columns.
// On Postgres, bootstrapDb() in server.js handles this via schema.sql instead.

const fs   = require('fs');
const path = require('path');

module.exports = function runSchemaMigrations(db, { isPg, encryptText, log, decryptText, PUBLIC_USER_DEFAULT_FEATURES }) {
  if (isPg) return; // Postgres uses schema.sql via bootstrapDb()

  // ── SQLite-only inline DDL + bootstrap ─────────────────────────────────────
  try { db.exec(`CREATE TABLE IF NOT EXISTS devices (
    id TEXT PRIMARY KEY, name TEXT, model TEXT, android_version TEXT,
    os_build TEXT, security_patch TEXT, battery TEXT, last_seen INTEGER,
    online INTEGER DEFAULT 0, platform TEXT, app_version TEXT,
    last_lat TEXT, last_lng TEXT, public_key TEXT,
    owner_user_id INTEGER REFERENCES users(id),
    locked_identity_email TEXT, locked_pubkey_sha TEXT
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, role TEXT DEFAULT 'user',
    permissions TEXT DEFAULT '{}', created_at INTEGER,
    status TEXT DEFAULT 'active', account_type TEXT DEFAULT 'admin',
    email TEXT, notif_prefs TEXT, enrollment_token TEXT,
    enabled_features TEXT DEFAULT '{}', trial_enabled INTEGER DEFAULT 0,
    trial_started_at INTEGER, totp_secret TEXT, totp_verified INTEGER DEFAULT 0,
    zk_public_key TEXT, zk_encrypted_priv_key TEXT, zk_salt TEXT,
    zk_private_key_wrap TEXT, support_key_wrap TEXT
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY, value TEXT
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS locations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT,
    data TEXT, timestamp INTEGER, lat REAL, lng REAL, accuracy REAL
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS media (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT,
    type TEXT, data TEXT, timestamp INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS network_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT,
    data TEXT, timestamp INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS bt_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT,
    data TEXT, timestamp INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT,
    remote_path TEXT, filename TEXT, size INTEGER, captured_at INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS call_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT,
    data TEXT, timestamp INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS sms_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT,
    data TEXT, timestamp INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS app_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT,
    data TEXT, timestamp INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS keylog_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT,
    data TEXT, timestamp INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS screen_text_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT,
    pkg TEXT, data TEXT, timestamp INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS device_status_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT,
    type TEXT, data TEXT, timestamp INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS pending_device_keys (
    device_id TEXT PRIMARY KEY, model TEXT, android_version TEXT,
    public_key TEXT, submitted_at INTEGER, enrollment_user_id INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS device_telemetry (
    device_id TEXT PRIMARY KEY, online INTEGER DEFAULT 0,
    battery_level INTEGER, battery_charging INTEGER,
    battery_temperature REAL, battery_voltage REAL,
    network_type TEXT, network_ssid TEXT, network_ip TEXT,
    storage_total INTEGER, storage_free INTEGER,
    storage_used INTEGER, uptime INTEGER,
    status_zk TEXT, status_dek TEXT, status_ts BIGINT,
    updated_at INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS enrollment_tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ticket TEXT UNIQUE,
    user_id INTEGER, device_id TEXT, kind TEXT DEFAULT 'login',
    uses_remaining INTEGER DEFAULT 1,
    expires_at INTEGER, consumed_at INTEGER, created_at INTEGER,
    platform TEXT DEFAULT 'windows'
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS zk_payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT,
    event_type TEXT, payload TEXT, dek_wrapped TEXT,
    timestamp INTEGER
  )`); } catch {}
  try { db.exec('CREATE INDEX IF NOT EXISTS idx_zk_event ON zk_payloads(device_id, event_type, timestamp DESC)'); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT, order_ref TEXT UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id), email TEXT,
    order_type TEXT NOT NULL, product_sku TEXT,
    amount_cents INTEGER NOT NULL, currency TEXT DEFAULT 'USD',
    status TEXT DEFAULT 'pending', carrier TEXT, tracking_number TEXT,
    shipped_at INTEGER, delivered_at INTEGER,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS entitlements (
    id INTEGER PRIMARY KEY AUTOINCREMENT, license_key TEXT UNIQUE NOT NULL,
    user_id INTEGER REFERENCES users(id), order_id INTEGER REFERENCES orders(id),
    trial_type TEXT NOT NULL, device_id TEXT, hardware_id TEXT,
    hardware_id_hmac TEXT, status TEXT DEFAULT 'pending',
    trial_start_date INTEGER, software_trial_deadline INTEGER,
    first_ping_at INTEGER, last_ping_at INTEGER,
    lapsed_alerted_at INTEGER, created_at INTEGER NOT NULL
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS tos_acceptances (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    order_id INTEGER, email TEXT, policy_key TEXT NOT NULL,
    policy_version TEXT NOT NULL, policy_sha256 TEXT,
    accepted_at INTEGER NOT NULL, ip_address TEXT, user_agent TEXT
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT,
    user_id INTEGER, stripe_customer_id TEXT,
    stripe_subscription_id TEXT UNIQUE, status TEXT,
    price_id TEXT, trial_end INTEGER, current_period_end INTEGER,
    cancel_at_period_end INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS support_threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    subject TEXT, status TEXT DEFAULT 'open',
    created_at INTEGER, last_msg_at INTEGER,
    conversation_id TEXT, archived INTEGER DEFAULT 0,
    unread_admin INTEGER DEFAULT 0, unread_user INTEGER DEFAULT 0
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS support_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, thread_id INTEGER NOT NULL,
    sender TEXT NOT NULL, body TEXT, created_at INTEGER,
    enc INTEGER DEFAULT 0, payload TEXT,
    dek_user TEXT, dek_support TEXT
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS guest_threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT, guest_id TEXT NOT NULL,
    conversation_id TEXT, name TEXT, email TEXT,
    status TEXT DEFAULT 'open', created_at INTEGER,
    last_msg_at INTEGER, archived INTEGER DEFAULT 0,
    unread_admin INTEGER DEFAULT 0, unread_guest INTEGER DEFAULT 0
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS guest_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT, thread_id INTEGER NOT NULL,
    sender TEXT NOT NULL, body TEXT, created_at INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS web_analytics (
    id INTEGER PRIMARY KEY AUTOINCREMENT, session_hash TEXT,
    page TEXT, referrer TEXT, duration_ms INTEGER,
    timestamp INTEGER, ip_hash TEXT,
    browser TEXT, os TEXT, device TEXT, country TEXT, city TEXT,
    utm_source TEXT, utm_medium TEXT, utm_campaign TEXT
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS push_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    endpoint TEXT, p256dh TEXT, auth TEXT
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS fcm_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
    token TEXT UNIQUE
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS remote_assist_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
    bastion_label TEXT, port INTEGER, ssh_public_key TEXT,
    status TEXT DEFAULT 'pending', created_at INTEGER,
    connected_at INTEGER, agent_version TEXT
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS arp_neighbors (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
    ip_address TEXT NOT NULL, mac_address TEXT NOT NULL,
    hostname TEXT, subnet TEXT, first_seen INTEGER,
    last_seen INTEGER, trusted INTEGER DEFAULT 0,
    UNIQUE(device_id, mac_address)
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS arp_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
    event_type TEXT NOT NULL, ip_address TEXT, mac_address TEXT,
    prior_mac TEXT, timestamp INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS arp_canary_ips (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
    subnet TEXT NOT NULL, ip_address TEXT NOT NULL,
    confirmed_at INTEGER, last_seen INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS user_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    device_id TEXT, category TEXT, message TEXT,
    created_at INTEGER NOT NULL, archived INTEGER DEFAULT 0
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS alert_auto_audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT, alert_id INTEGER NOT NULL,
    device_id TEXT, status TEXT DEFAULT 'pending',
    report TEXT, created_at INTEGER NOT NULL,
    UNIQUE(alert_id)
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS device_groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    name TEXT NOT NULL, sort_order INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS learn_mode (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
    started_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
    UNIQUE(device_id)
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS learn_observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
    signature TEXT NOT NULL, detail TEXT, category TEXT,
    first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
    decision TEXT, decided_at INTEGER
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS usblock_approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
    instance_id TEXT, friendly_name TEXT, vid_pid TEXT,
    approved_at INTEGER NOT NULL, approved_by TEXT
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS bitlocker_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT, device_id TEXT NOT NULL,
    key_protector_id TEXT, recovery_key TEXT,
    created_at INTEGER NOT NULL,
    UNIQUE(device_id, key_protector_id)
  )`); } catch {}

  try { db.exec(`CREATE TABLE IF NOT EXISTS account_ai_memory (
    id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
    device_id TEXT, kind TEXT NOT NULL, body TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`); } catch {}
  try { db.exec("CREATE INDEX IF NOT EXISTS idx_account_ai_memory_user ON account_ai_memory(user_id, created_at DESC)"); } catch {}

  // Schema migrations — add missing columns to existing tables
  const migrations = [
    'ALTER TABLE devices ADD COLUMN apk_signer TEXT',
    'ALTER TABLE device_telemetry ADD COLUMN status_zk TEXT',
    'ALTER TABLE device_telemetry ADD COLUMN status_dek TEXT',
    'ALTER TABLE device_telemetry ADD COLUMN status_ts BIGINT',
    'ALTER TABLE scheduled_commands ADD COLUMN days TEXT',
    'ALTER TABLE scheduled_commands ADD COLUMN tz TEXT',
    'ALTER TABLE usblock_approvals ADD COLUMN vid_pid TEXT',
    'ALTER TABLE devices ADD COLUMN tailnet_group_id TEXT',
    'ALTER TABLE devices ADD COLUMN ui_group_id TEXT',
    'ALTER TABLE devices ADD COLUMN archived INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE users ADD COLUMN trial_1d_alerted_at BIGINT',
    'ALTER TABLE users ADD COLUMN email_verify_hash TEXT',
    'ALTER TABLE users ADD COLUMN email_verify_expires BIGINT',
    'ALTER TABLE devices ADD COLUMN rehome_code_hash TEXT',
    'ALTER TABLE devices ADD COLUMN rehome_code_expires BIGINT',
    "ALTER TABLE users ADD COLUMN pw_scheme TEXT NOT NULL DEFAULT 'plain'",
    'ALTER TABLE users ADD COLUMN auth_salt TEXT',
    'ALTER TABLE users ADD COLUMN comp_plan TEXT',
    'ALTER TABLE users ADD COLUMN comp_expires_at BIGINT',
    'ALTER TABLE users ADD COLUMN comp_granted_by TEXT',
    'ALTER TABLE users ADD COLUMN comp_granted_at BIGINT',
    'ALTER TABLE users ADD COLUMN business_mode INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE users ADD COLUMN business_mode_set_at BIGINT',
    'ALTER TABLE users ADD COLUMN business_mode_reverted_at BIGINT',
    'ALTER TABLE users ADD COLUMN business_mode_reverted_by TEXT',
    'ALTER TABLE users ADD COLUMN parent_owner_id INTEGER',
    'ALTER TABLE users ADD COLUMN is_support_delegate INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE users ADD COLUMN support_code_payload TEXT',
    'ALTER TABLE users ADD COLUMN support_code_dek_support TEXT',
    "ALTER TABLE devices ADD COLUMN lineage_kind TEXT DEFAULT 'public'",
    'ALTER TABLE devices ADD COLUMN agent_kind TEXT DEFAULT NULL',
    'ALTER TABLE devices ADD COLUMN is_demo INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE support_messages ADD COLUMN enc INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE support_messages ADD COLUMN payload TEXT',
    'ALTER TABLE support_messages ADD COLUMN dek_user TEXT',
    'ALTER TABLE support_messages ADD COLUMN dek_support TEXT',
    'ALTER TABLE users ADD COLUMN support_key_wrap TEXT',
    'ALTER TABLE web_analytics ADD COLUMN country TEXT',
    'ALTER TABLE web_analytics ADD COLUMN city TEXT',
    'ALTER TABLE web_analytics ADD COLUMN utm_source TEXT',
    'ALTER TABLE web_analytics ADD COLUMN utm_medium TEXT',
    'ALTER TABLE web_analytics ADD COLUMN utm_campaign TEXT',
    'ALTER TABLE file_backup_runs ADD COLUMN backup_kind TEXT',
    "ALTER TABLE enrollment_tickets ADD COLUMN platform TEXT NOT NULL DEFAULT 'windows'",
    'ALTER TABLE device_telemetry ADD COLUMN bt_devices TEXT',
    'ALTER TABLE device_telemetry ADD COLUMN bt_scan_ts BIGINT',
    'ALTER TABLE device_telemetry ADD COLUMN bt_scan_state BOOLEAN DEFAULT 0',
    'ALTER TABLE device_telemetry ADD COLUMN bt_safelist TEXT',
  ];

  for (const sql of migrations) {
    try { db.exec(sql); } catch (_) {}
  }

  // Bootstrap admin user
  const bcrypt = require('bcryptjs');
  const ADMIN_USER = process.env.ADMIN_USER || 'admin';
  const ADMIN_PASS = (() => {
    try { return require('fs').readFileSync('/run/secrets/sentinel_admin_pass', 'utf8').trim(); } catch {}
    return process.env.ADMIN_PASS || '';
  })();

  if (ADMIN_PASS) {
    const AUTH_SCHEME_PREHASH = 'prehash-v1';
    const AUTH_PREHASH_ITER = 600000;
    const AUTH_PREHASH_DOMAIN = 'sentinel-auth-v1|';
    const crypto = require('crypto');
    const newAuthSalt = () => crypto.randomBytes(16).toString('base64');
    const _authPrehashSalt = (s) => Buffer.concat([Buffer.from(AUTH_PREHASH_DOMAIN, 'utf8'), Buffer.from(String(s), 'base64')]);
    const computeAuthPrehashSync = (pw, salt) => crypto.pbkdf2Sync(Buffer.from(String(pw), 'utf8'), _authPrehashSalt(salt), AUTH_PREHASH_ITER, 32, 'sha256').toString('base64');

    const seedCreds = (pass) => { const salt = newAuthSalt(); return { hash: bcrypt.hashSync(computeAuthPrehashSync(pass, salt), 10), salt }; };
    const adminSeed = seedCreds(ADMIN_PASS);
    try {
      const ins = db.prepare(
        'INSERT INTO users (username,password_hash,role,permissions,created_at,pw_scheme,auth_salt) VALUES (?,?,?,?,?,?,?) ON CONFLICT(username) DO NOTHING'
      ).run(ADMIN_USER, adminSeed.hash, 'admin', '{}', Date.now(), AUTH_SCHEME_PREHASH, adminSeed.salt);
      if (ins.changes) log('info', `Bootstrapped admin user: ${ADMIN_USER}`);
    } catch (e) { log('warn', 'Admin bootstrap failed', { error: e.message }); }
  }

  log('info', 'Schema migrations complete');
};
