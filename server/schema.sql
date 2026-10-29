-- server/schema.sql
-- ─────────────────────────────────────────────────────────────────────────────
-- Postgres schema for the SentinelMDM tracker (Phase 2: SQLite → Postgres).
--
-- This is the CONSOLIDATED FINAL-STATE schema: each table already includes every
-- column that the historical `ALTER TABLE ... ADD COLUMN` idempotent migrations in
-- server.js would have added over time. Because Postgres starts EMPTY (old SQLite
-- data is disposable; the test devices are re-enrolled), there is no migration
-- history to replay — we create the end state directly.
--
-- Dialect notes vs the SQLite source:
--   • `INTEGER PRIMARY KEY AUTOINCREMENT`  → `SERIAL PRIMARY KEY`
--   • epoch-millis columns (Date.now())    → `BIGINT`  (SQLite INTEGER is 64-bit;
--     Postgres INTEGER is 4-byte / max 2.1e9 and would OVERFLOW on a ms timestamp)
--   • boolean-ish 0/1 flags, battery, cents, FK ids → kept `INTEGER` (app uses 0/1)
--   • `DEFAULT (strftime('%s','now'))`      → `DEFAULT extract(epoch from now())::bigint`
--   • `INSERT OR REPLACE/IGNORE`, `lastInsertRowid`, `PRAGMA` are APP-SIDE concerns
--     (handled by the codemod / hand-fixes), not here.
--   • Tables are ordered so every FK target is created first.
--
-- Idempotent: every statement uses IF NOT EXISTS, so re-applying at every boot is safe.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── users (FK target for devices, orders, entitlements, support, …) ──────────
CREATE TABLE IF NOT EXISTS users (
  id                    SERIAL PRIMARY KEY,
  username              TEXT UNIQUE NOT NULL,
  password_hash         TEXT NOT NULL,
  role                  TEXT NOT NULL DEFAULT 'user',
  permissions           TEXT NOT NULL DEFAULT '{}',
  created_at            BIGINT NOT NULL,
  status                TEXT NOT NULL DEFAULT 'active',
  account_type          TEXT NOT NULL DEFAULT 'admin_created',
  email                 TEXT,
  totp_secret           TEXT,
  totp_verified         INTEGER DEFAULT 0,
  enabled_features      TEXT DEFAULT '{}',
  zk_public_key         TEXT,
  zk_encrypted_priv_key TEXT,
  zk_salt               TEXT,
  support_key_wrap      TEXT,
  notif_prefs           TEXT DEFAULT '{}',
  enrollment_token      TEXT,
  trial_enabled         INTEGER DEFAULT 0,
  trial_started_at      BIGINT,
  trial_1d_alerted_at   BIGINT,
  email_verify_hash     TEXT,
  email_verify_expires  BIGINT,
  -- Admin-granted complimentary ("comp") subscription — a free override that makes a public
  -- account behave as if it holds a live paid plan (no trial lock / 48h auto-wipe; device cap
  -- follows the comp plan). Lives here (NOT in `subscriptions`) so Stripe webhooks can't clobber it.
  comp_plan             TEXT,            -- 'unlimited' | '1device'  (NULL = no comp)
  comp_expires_at       BIGINT,          -- epoch-ms expiry          (NULL = never expires)
  comp_granted_by       TEXT,            -- admin username (audit)
  comp_granted_at       BIGINT,          -- epoch-ms granted (audit)
  -- Business Account compliance mode (public accounts only) — one-way toggle set by the user,
  -- reversible only by an admin. Permanently blocks audio/video/screen-recording/keylog/manual-
  -- photo commands for every device this account owns. See BUSINESS_MODE_BLOCKED_COMMANDS.
  business_mode             INTEGER NOT NULL DEFAULT 0,
  business_mode_set_at      BIGINT,
  business_mode_reverted_at BIGINT,
  business_mode_reverted_by TEXT,
  -- Business sub-user linkage: set on account_type='business_sub' rows to the business owner's
  -- user id. Scopes GET /api/devices + all device-access middleware to just that owner's fleet.
  parent_owner_id           INTEGER REFERENCES users(id),
  -- Hybrid Managed "Grant support access": a business_sub row with this = 1 is the SentinelMDM
  -- support delegate (created without enabling business_mode, auto-scoped to all owner devices).
  is_support_delegate       INTEGER NOT NULL DEFAULT 0,
  -- The support code, GENUINE E2E-encrypted to the shared Support pubkey (same wire format as the
  -- E2E "Conversations" support chat's dek_support) — server stores/relays ciphertext only.
  support_code_payload      TEXT,
  support_code_dek_support  TEXT
);

CREATE TABLE IF NOT EXISTS support_code_reveals (
  id                  SERIAL PRIMARY KEY,
  delegate_user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  revealed_by         TEXT NOT NULL,
  revealed_at         BIGINT NOT NULL
);

-- ── passkeys / WebAuthn credentials (usernameless login → replaces password+OTP) ──
CREATE TABLE IF NOT EXISTS webauthn_credentials (
  id                TEXT PRIMARY KEY,                  -- credential ID (base64url)
  user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  public_key        TEXT NOT NULL,                     -- COSE public key (base64url)
  counter           BIGINT NOT NULL DEFAULT 0,         -- signature counter (anti-clone)
  transports        TEXT,                              -- JSON array, e.g. ["internal","hybrid"]
  device_type       TEXT,                              -- 'singleDevice' | 'multiDevice'
  backed_up         INTEGER NOT NULL DEFAULT 0,        -- synced/backed-up passkey?
  aaguid            TEXT,                              -- authenticator model (optional)
  name              TEXT,                              -- user-friendly label
  zk_wrapped_priv   TEXT,                              -- ZK priv key wrapped under this cred's PRF KEK (public users)
  created_at        BIGINT NOT NULL,
  last_used_at      BIGINT
);
CREATE INDEX IF NOT EXISTS idx_webauthn_cred_user ON webauthn_credentials(user_id);

-- ── devices (FK target for stream_recordings, zk_stream_sessions) ────────────
CREATE TABLE IF NOT EXISTS devices (
  id                    TEXT PRIMARY KEY,
  name                  TEXT,
  model                 TEXT,
  android_version       TEXT,
  battery               INTEGER,
  last_seen             BIGINT DEFAULT 0,
  last_lat              TEXT,
  last_lng              TEXT,
  online                INTEGER DEFAULT 0,
  platform              TEXT DEFAULT 'android',
  integrity             TEXT DEFAULT NULL,
  deep_sleep            INTEGER NOT NULL DEFAULT 0,
  emergency_mode        INTEGER NOT NULL DEFAULT 0,
  theft_mode            INTEGER NOT NULL DEFAULT 0,
  keylog_active         INTEGER NOT NULL DEFAULT 0,
  screen_text_active    INTEGER NOT NULL DEFAULT 0,
  pending_update        INTEGER NOT NULL DEFAULT 0,
  pending_ota           INTEGER NOT NULL DEFAULT 0,
  app_version           TEXT,
  os_build              TEXT,
  security_patch        TEXT,
  apk_signer            TEXT,
  public_key            TEXT,
  locked_identity_email TEXT,
  locked_pubkey_sha     TEXT,
  rehome_code_hash      TEXT,
  rehome_code_expires   BIGINT,
  lineage_kind          TEXT DEFAULT 'public',
  owner_user_id         INTEGER REFERENCES users(id),
  archived              INTEGER NOT NULL DEFAULT 0,
  -- Remote shell (sentinel-adb CLI) opt-in, per device, default OFF. Toggled under the
  -- Shell tab with an explainer modal; gates operator-token shell_exec/shell_stop only
  -- (the dashboard terminal is unaffected).
  remote_shell_enabled  INTEGER NOT NULL DEFAULT 0,
  -- NULL/'native' = existing/reserved-future Windows agent path; 'remote_assist' = a
  -- SentinelRemoteAssist-registered device. New Windows-agent UI/endpoints gate on this, never
  -- on bare platform='windows'.
  agent_kind            TEXT DEFAULT NULL,
  -- Synthetic placeholder device auto-seeded for a public user so their dashboard isn't empty
  -- before a real device is added (see createDemoDeviceForUser() in server.js). Never real
  -- hardware: excluded from ZK/admin-visibility/plan-device-count logic and deleted the moment
  -- the owner's first real device is bound.
  is_demo               INTEGER NOT NULL DEFAULT 0
);

-- ── Per-device telemetry tables (device_id is plain TEXT, no FK constraint) ──
CREATE TABLE IF NOT EXISTS locations (
  id        SERIAL PRIMARY KEY,
  device_id TEXT,
  data      TEXT,
  timestamp BIGINT
);

CREATE TABLE IF NOT EXISTS media (
  id             SERIAL PRIMARY KEY,
  device_id      TEXT,
  type           TEXT,
  data           TEXT,
  timestamp      BIGINT,
  zk_encrypted   INTEGER DEFAULT 0,
  zk_dek_wrapped TEXT
);

CREATE TABLE IF NOT EXISTS audio_segments (
  id         SERIAL PRIMARY KEY,
  session_id TEXT,
  device_id  TEXT,
  seq        INTEGER,
  data       TEXT,
  timestamp  BIGINT
);

CREATE INDEX IF NOT EXISTS idx_audio_segments_session ON audio_segments(session_id, seq);

CREATE TABLE IF NOT EXISTS network_events (
  id        SERIAL PRIMARY KEY,
  device_id TEXT,
  data      TEXT,
  timestamp BIGINT
);

CREATE TABLE IF NOT EXISTS bt_events (
  id        SERIAL PRIMARY KEY,
  device_id TEXT,
  data      TEXT,
  timestamp BIGINT
);
CREATE INDEX IF NOT EXISTS idx_bt_events_device_ts ON bt_events (device_id, timestamp);

CREATE TABLE IF NOT EXISTS files (
  id          SERIAL PRIMARY KEY,
  device_id   TEXT,
  remote_path TEXT,
  filename    TEXT,
  size        BIGINT DEFAULT 0,
  captured_at BIGINT
);

CREATE TABLE IF NOT EXISTS call_logs (
  id        SERIAL PRIMARY KEY,
  device_id TEXT,
  data      TEXT,
  timestamp BIGINT
);

CREATE TABLE IF NOT EXISTS sms_messages (
  id        SERIAL PRIMARY KEY,
  device_id TEXT,
  data      TEXT,
  timestamp BIGINT
);

CREATE TABLE IF NOT EXISTS app_lists (
  id        SERIAL PRIMARY KEY,
  device_id TEXT,
  data      TEXT,
  timestamp BIGINT
);

CREATE TABLE IF NOT EXISTS stream_recordings (
  id           TEXT PRIMARY KEY,
  device_id    TEXT NOT NULL,
  type         TEXT NOT NULL,
  filename     TEXT NOT NULL,
  size         BIGINT  DEFAULT 0,
  duration     BIGINT  DEFAULT 0,
  captured_at  BIGINT  NOT NULL,
  zk_encrypted INTEGER NOT NULL DEFAULT 0,
  dek_wrapped  TEXT,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS settings (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS zk_stream_sessions (
  id          TEXT PRIMARY KEY,
  device_id   TEXT NOT NULL,
  event_type  TEXT NOT NULL,
  dek_wrapped TEXT NOT NULL,
  started_at  BIGINT NOT NULL,
  FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS device_network_logs (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  type      TEXT NOT NULL,
  data      TEXT NOT NULL,
  timestamp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_security_logs (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  tag       INTEGER NOT NULL,
  name      TEXT NOT NULL DEFAULT '',
  data      TEXT NOT NULL,
  timestamp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_status_events (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  type      TEXT NOT NULL,
  data      TEXT NOT NULL,
  timestamp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS pending_device_keys (
  device_id          TEXT PRIMARY KEY,
  model              TEXT,
  android_version    TEXT,
  public_key         TEXT NOT NULL,
  submitted_at       BIGINT NOT NULL,
  enrollment_user_id INTEGER
);

CREATE TABLE IF NOT EXISTS enrollment_tickets (
  ticket         TEXT PRIMARY KEY,
  user_id        INTEGER NOT NULL,
  device_id      TEXT    NOT NULL DEFAULT '',
  kind           TEXT    NOT NULL DEFAULT 'login',
  uses_remaining INTEGER NOT NULL DEFAULT 1,
  expires_at     BIGINT  NOT NULL,
  consumed_at    BIGINT,
  created_at     BIGINT  NOT NULL,
  platform       TEXT    NOT NULL DEFAULT 'windows'
);
-- Idempotent additive columns for EXISTING deployments (bootstrapDb runs this whole file in a
-- txn; CREATE TABLE IF NOT EXISTS won't alter a pre-existing table, and the index below references
-- `kind`, which would otherwise 500 the whole boot with "column kind does not exist" — found live
-- 2026-08-03 on the first deploy of the auto-provisioning installer variant).
ALTER TABLE enrollment_tickets ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'login';
ALTER TABLE enrollment_tickets ADD COLUMN IF NOT EXISTS uses_remaining INTEGER NOT NULL DEFAULT 1;
ALTER TABLE enrollment_tickets ADD COLUMN IF NOT EXISTS platform TEXT NOT NULL DEFAULT 'windows';
CREATE INDEX IF NOT EXISTS idx_enroll_tickets_user ON enrollment_tickets(user_id, kind, created_at DESC);

-- ToS/MSA acceptance records for the auto-provisioning installer variant (agent 2.0.3) — the
-- agent records deviceId + ToS version + timestamp after the user accepts the dialog on the target
-- PC (POST /api/ra/consent). Metadata only; kept indefinitely (audit trail proving consent for
-- remote access — same no-TTL reasoning as bitlocker_keys).
CREATE TABLE IF NOT EXISTS ra_consents (
  id          SERIAL PRIMARY KEY,
  device_id   TEXT   NOT NULL,
  tos_version TEXT   NOT NULL,
  accepted    INTEGER NOT NULL DEFAULT 1,
  created_at  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ra_consents_device ON ra_consents(device_id, created_at DESC);

-- SentinelRemoteAssist (consensual Windows remote-support agent) session records. One row per
-- dashboard-initiated remote-assist session request; ssh_public_key is the BROWSER-generated
-- ephemeral SSH public key for that session (private key never leaves the browser — see
-- requireRemoteAssistAccess()/the ZK access-control design). bastion_label/bastion_port are filled
-- in once the bastion-side session is actually provisioned.
CREATE TABLE IF NOT EXISTS remote_assist_sessions (
  id                 TEXT PRIMARY KEY,
  device_id          TEXT    NOT NULL,
  requested_by_user_id INTEGER NOT NULL,
  ssh_public_key     TEXT,
  bastion_label      TEXT,
  bastion_port       INTEGER,
  status             TEXT    NOT NULL DEFAULT 'pending',
  created_at         BIGINT  NOT NULL,
  ended_at           BIGINT
);

-- Per-device Hop-2 key material persistently cached server-side so an owner can retrieve their
-- SSH private key + connect command after a browser refresh without regenerating the keypair.
-- encrypted_data is encryptText(<JSON>) at rest; the raw JSON shape is:
--   {priv_key, pub_key, connect_cmd, connect_cmd_on_host, bastion_port, bastion_label}
-- Created on first Connect, deleted on explicit "Regen Private Key" or device deletion.
-- Gated behind requireDeviceController() — only the device owner can read this row.
CREATE TABLE IF NOT EXISTS ra_hop2_keys (
  device_id      TEXT PRIMARY KEY,
  encrypted_data TEXT    NOT NULL,
  created_at     BIGINT  NOT NULL
);

CREATE TABLE IF NOT EXISTS keylog_entries (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  data      TEXT NOT NULL,
  timestamp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS screen_text_entries (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  pkg       TEXT NOT NULL DEFAULT '',
  data      TEXT NOT NULL,
  timestamp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  pkg       TEXT NOT NULL,
  title     TEXT NOT NULL DEFAULT '',
  text      TEXT NOT NULL DEFAULT '',
  timestamp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS clipboard_events (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  content   TEXT NOT NULL,
  timestamp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  data      TEXT NOT NULL,
  timestamp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS calendar_events (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  data      TEXT NOT NULL,
  timestamp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS browser_history (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  data      TEXT NOT NULL,
  timestamp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS usage_stats (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  data      TEXT NOT NULL,
  timestamp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS shell_sessions (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  command   TEXT NOT NULL,
  output    TEXT NOT NULL DEFAULT '',
  timestamp BIGINT NOT NULL
);

-- Operator API tokens (sentinel-adb CLI etc.): Bearer tokens minted out-of-band,
-- sha256-hashed at rest, shown once at mint. Scopes are comma-separated route
-- groups (currently 'shell'). Revocation is instant (checked per request).
-- device_id scopes a token to ONE device (per-device connect commands); NULL = fleet-wide.
CREATE TABLE IF NOT EXISTS operator_tokens (
  id           SERIAL PRIMARY KEY,
  name         TEXT NOT NULL,
  token_hash   TEXT NOT NULL UNIQUE,
  scopes       TEXT NOT NULL DEFAULT 'shell',
  device_id    TEXT,
  created_at   BIGINT NOT NULL,
  last_used_at BIGINT,
  revoked      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS scheduled_commands (
  id          SERIAL PRIMARY KEY,
  device_id   TEXT NOT NULL,
  label       TEXT NOT NULL DEFAULT '',
  command     TEXT NOT NULL,
  params      TEXT NOT NULL DEFAULT '{}',
  repeat_type TEXT NOT NULL DEFAULT 'once',
  run_at      BIGINT NOT NULL,
  next_run    BIGINT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1,
  last_ran    BIGINT DEFAULT NULL,
  days        TEXT,
  tz          TEXT
);

CREATE TABLE IF NOT EXISTS alert_config (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  type      TEXT NOT NULL,
  threshold TEXT NOT NULL,
  enabled   INTEGER NOT NULL DEFAULT 1,
  UNIQUE(device_id, type)
);

CREATE TABLE IF NOT EXISTS watched_apps (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  pkg       TEXT NOT NULL,
  UNIQUE(device_id, pkg)
);

CREATE TABLE IF NOT EXISTS sms_outbox (
  id        SERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  number    TEXT NOT NULL,
  message   TEXT NOT NULL,
  status    TEXT NOT NULL DEFAULT 'sent',
  timestamp BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS device_telemetry (
  device_id             TEXT PRIMARY KEY,
  owner_user_id         INTEGER,
  ip_address            TEXT,
  model_plain           TEXT,
  android_version_plain TEXT,
  online                INTEGER DEFAULT 0,
  battery               INTEGER,
  updated_at            BIGINT,
  -- Latest ZK-encrypted device_status blob (battery/motion/network) for public-user devices.
  status_zk             TEXT,
  status_dek            TEXT,
  status_ts             BIGINT,
  -- Latest Bluetooth scan snapshot (JSON of nearby BLE/classic devices + detected trackers).
  bt_devices            TEXT,
  bt_scan_ts            BIGINT,
  bt_scan_state         BOOLEAN DEFAULT false,
  bt_safelist           TEXT
);

-- Zero-knowledge opaque payload store (server cannot decrypt; 30-day TTL purge).
CREATE TABLE IF NOT EXISTS zk_payloads (
  id          SERIAL PRIMARY KEY,
  device_id   TEXT NOT NULL,
  event_type  TEXT NOT NULL,
  payload     TEXT NOT NULL,
  dek_wrapped TEXT NOT NULL,
  timestamp   BIGINT NOT NULL
);

-- ── Commerce / trial / legal (EXCLUDED from the 30-day purge) ────────────────
CREATE TABLE IF NOT EXISTS orders (
  id                    SERIAL PRIMARY KEY,
  order_ref             TEXT UNIQUE NOT NULL,
  user_id               INTEGER REFERENCES users(id),
  email                 TEXT,
  order_type            TEXT NOT NULL DEFAULT 'hardware',
  product_sku           TEXT,
  amount_cents          INTEGER,
  currency              TEXT DEFAULT 'usd',
  stripe_session_id     TEXT,
  stripe_payment_intent TEXT,
  status                TEXT NOT NULL DEFAULT 'pending',
  carrier               TEXT,
  tracking_number       TEXT,
  shipped_at            BIGINT,
  delivered_at          BIGINT,
  created_at            BIGINT NOT NULL,
  updated_at            BIGINT
);

CREATE TABLE IF NOT EXISTS entitlements (
  id                       SERIAL PRIMARY KEY,
  license_key              TEXT UNIQUE NOT NULL,
  user_id                  INTEGER NOT NULL REFERENCES users(id),
  order_id                 INTEGER REFERENCES orders(id),
  device_id                TEXT,
  trial_type               TEXT NOT NULL DEFAULT 'digital_mdm_7',
  hardware_id              TEXT,
  hardware_id_hmac         TEXT,
  trial_start_date         BIGINT,
  software_trial_deadline  BIGINT,
  hardware_return_deadline BIGINT,
  status                   TEXT NOT NULL DEFAULT 'Active',
  first_ping_at            BIGINT,
  last_ping_at             BIGINT,
  created_at               BIGINT NOT NULL,
  lapsed_alerted_at        BIGINT
);

-- Append-only audit of every 30-day account-trial start (trial-abuse detection, alert-only).
-- Keyed on the serial-derived device handle + a keyed HMAC of the email. Purge-excluded.
CREATE TABLE IF NOT EXISTS trial_starts (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER REFERENCES users(id),
  device_id   TEXT,
  email_hmac  TEXT,
  serial_hmac TEXT,
  created_at  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_trial_starts_device ON trial_starts(device_id);
CREATE INDEX IF NOT EXISTS idx_trial_starts_email  ON trial_starts(email_hmac);
CREATE INDEX IF NOT EXISTS idx_trial_starts_serial ON trial_starts(serial_hmac);

-- Account continuity across "Secure my account" / trial auto-wipe: when a public account is wiped,
-- its trial countdown + admin comp plan (which live on the users row) are stashed here keyed by the
-- email-lineage HMAC, so a NEW same-email account restores them at registration (trial resumes at
-- its remaining days; comp carries over). Privacy-safe (keyed hash, no raw email). Purge-excluded.
CREATE TABLE IF NOT EXISTS account_continuity (
  email_hmac        TEXT PRIMARY KEY,
  trial_started_at  BIGINT,
  comp_plan         TEXT,
  comp_expires_at   BIGINT,
  updated_at        BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS tos_acceptances (
  id             SERIAL PRIMARY KEY,
  user_id        INTEGER REFERENCES users(id),
  order_id       INTEGER REFERENCES orders(id),
  email          TEXT,
  policy_key     TEXT NOT NULL,
  policy_version TEXT NOT NULL,
  policy_sha256  TEXT,
  accepted_at    BIGINT NOT NULL,
  ip_address     TEXT,
  user_agent     TEXT
);

CREATE TABLE IF NOT EXISTS products (
  id              SERIAL PRIMARY KEY,
  sku             TEXT UNIQUE NOT NULL,
  title           TEXT NOT NULL,
  model_series    TEXT,
  base_cost_cents INTEGER NOT NULL DEFAULT 0,
  markup_cents    INTEGER NOT NULL DEFAULT 5000,
  price_cents     INTEGER NOT NULL DEFAULT 0,
  currency        TEXT DEFAULT 'usd',
  active          INTEGER NOT NULL DEFAULT 1,
  sort_order      INTEGER DEFAULT 0,
  updated_at      BIGINT
);

CREATE TABLE IF NOT EXISTS rma_requests (
  id                    SERIAL PRIMARY KEY,
  rma_ref               TEXT UNIQUE NOT NULL,
  order_id              INTEGER REFERENCES orders(id),
  user_id               INTEGER REFERENCES users(id),
  reason                TEXT,
  status                TEXT NOT NULL DEFAULT 'Requested',
  return_carrier        TEXT,
  return_tracking       TEXT,
  returned_delivered_at BIGINT,
  serial_verified       INTEGER NOT NULL DEFAULT 0,
  condition_pass        INTEGER,
  inspection_notes      TEXT,
  inspected_by          TEXT,
  refund_released_at    BIGINT,
  refund_released_by    TEXT,
  created_at            BIGINT NOT NULL,
  updated_at            BIGINT
);

CREATE TABLE IF NOT EXISTS rma_photos (
  id           SERIAL PRIMARY KEY,
  rma_id       INTEGER NOT NULL REFERENCES rma_requests(id),
  slot         TEXT NOT NULL,
  r2_key       TEXT NOT NULL,
  content_type TEXT,
  uploaded_at  BIGINT NOT NULL
);

-- ── Support chat (admin ↔ buyer) ─────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS support_threads (
  id              SERIAL PRIMARY KEY,
  user_id         INTEGER NOT NULL REFERENCES users(id),
  subject         TEXT,
  status          TEXT NOT NULL DEFAULT 'open',
  created_at      BIGINT NOT NULL,
  last_msg_at     BIGINT,
  unread_admin    INTEGER NOT NULL DEFAULT 0,
  unread_user     INTEGER NOT NULL DEFAULT 0,
  archived        INTEGER DEFAULT 0,
  conversation_id TEXT
);

CREATE TABLE IF NOT EXISTS support_messages (
  id          SERIAL PRIMARY KEY,
  thread_id   INTEGER NOT NULL REFERENCES support_threads(id),
  sender      TEXT NOT NULL,
  body        TEXT NOT NULL,
  created_at  BIGINT NOT NULL,
  -- E2E (zero-knowledge) Conversations: enc=1 rows store ONLY ciphertext the server
  -- cannot read; body='' for those. payload=b64(iv‖ct‖tag) of the message under a
  -- random DEK; dek_user/dek_support = that DEK ECDH-wrapped to the owner user's and
  -- the shared Support public keys ({eph_pub,iv,ct} JSON). Legacy rows keep enc=0+body.
  enc         INTEGER NOT NULL DEFAULT 0,
  payload     TEXT,
  dek_user    TEXT,
  dek_support TEXT
);

CREATE TABLE IF NOT EXISTS guest_contacts (
  id         SERIAL PRIMARY KEY,
  name       TEXT,
  email      TEXT,
  message    TEXT NOT NULL,
  read       INTEGER NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL,
  archived   INTEGER DEFAULT 0
);

-- guest_threads: FINAL (post-v2-migration) shape — guest_id is NOT unique;
-- uniqueness moved to conversation_id (allows multiple conversations per guest).
CREATE TABLE IF NOT EXISTS guest_threads (
  id              SERIAL PRIMARY KEY,
  guest_id        TEXT NOT NULL,
  conversation_id TEXT NOT NULL,
  name            TEXT,
  email           TEXT,
  status          TEXT NOT NULL DEFAULT 'open',
  created_at      BIGINT NOT NULL,
  last_msg_at     BIGINT,
  unread_admin    INTEGER NOT NULL DEFAULT 0,
  unread_guest    INTEGER NOT NULL DEFAULT 0,
  archived        INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS guest_messages (
  id         SERIAL PRIMARY KEY,
  thread_id  INTEGER NOT NULL REFERENCES guest_threads(id),
  sender     TEXT NOT NULL,
  body       TEXT NOT NULL,
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS bug_reports (
  id          SERIAL PRIMARY KEY,
  user_id     INTEGER,
  username    TEXT,
  title       TEXT NOT NULL,
  description TEXT,
  status      TEXT NOT NULL DEFAULT 'open',
  created_at  BIGINT NOT NULL,
  updated_at  BIGINT NOT NULL
);

-- Optional image attachments for bug reports (base64 in-row; deleted with the report).
CREATE TABLE IF NOT EXISTS bug_report_photos (
  id           SERIAL PRIMARY KEY,
  bug_id       INTEGER NOT NULL REFERENCES bug_reports(id) ON DELETE CASCADE,
  content_type TEXT,
  data         TEXT NOT NULL,
  uploaded_at  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bug_report_photos ON bug_report_photos(bug_id);

-- Two-way conversation thread on a bug report (admin ↔ submitter). Body encrypted at rest.
CREATE TABLE IF NOT EXISTS bug_report_messages (
  id             SERIAL PRIMARY KEY,
  bug_id         INTEGER NOT NULL REFERENCES bug_reports(id) ON DELETE CASCADE,
  sender_role    TEXT NOT NULL,
  sender_user_id INTEGER,
  sender_name    TEXT,
  body           TEXT NOT NULL,
  created_at     BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bug_report_messages ON bug_report_messages(bug_id);

CREATE TABLE IF NOT EXISTS subscriptions (
  id                     SERIAL PRIMARY KEY,
  email                  TEXT,
  user_id                INTEGER,
  stripe_customer_id     TEXT,
  stripe_subscription_id TEXT UNIQUE,
  status                 TEXT,
  price_id               TEXT,
  trial_end              BIGINT,
  current_period_end     BIGINT,
  cancel_at_period_end   INTEGER DEFAULT 0,
  created_at             BIGINT,
  updated_at             BIGINT
);

CREATE TABLE IF NOT EXISTS push_subscriptions (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER NOT NULL,
  endpoint   TEXT    NOT NULL UNIQUE,
  p256dh     TEXT    NOT NULL,
  auth       TEXT    NOT NULL,
  created_at BIGINT DEFAULT extract(epoch from now())::bigint
);

CREATE TABLE IF NOT EXISTS fcm_tokens (
  id         SERIAL PRIMARY KEY,
  user_id    INTEGER NOT NULL,
  token      TEXT    NOT NULL UNIQUE,
  created_at BIGINT DEFAULT extract(epoch from now())::bigint
);

CREATE TABLE IF NOT EXISTS web_analytics (
  id               SERIAL PRIMARY KEY,
  timestamp        BIGINT NOT NULL,
  session_hash     TEXT   NOT NULL,
  path             TEXT   NOT NULL,
  referrer         TEXT,
  duration_seconds INTEGER DEFAULT 0,
  os               TEXT,
  browser          TEXT,
  device_type      TEXT,
  country          TEXT,
  city             TEXT,
  utm_source       TEXT,
  utm_medium       TEXT,
  utm_campaign     TEXT
);

-- Bot traffic — URL-scanner hits on the marketing site, fed by the nginx 404-mirror
-- (market-website/nginx.conf -> POST /api/analytics/bot). Marketing bots never run the
-- JS pageview beacon, so this is the only place they are visible.
CREATE TABLE IF NOT EXISTS bot_traffic (
  id        SERIAL PRIMARY KEY,
  timestamp BIGINT NOT NULL,
  ip        TEXT,
  host      TEXT,
  path      TEXT,
  ua        TEXT,
  method    TEXT
);

-- ── Indexes ──────────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_calls_device        ON call_logs(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_sms_device          ON sms_messages(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_apps_device         ON app_lists(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_locations_device    ON locations(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_media_device        ON media(device_id, type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_network_device      ON network_events(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_files_device        ON files(device_id, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_recordings_device   ON stream_recordings(device_id, type, captured_at DESC);
CREATE INDEX IF NOT EXISTS idx_zk_sessions_device  ON zk_stream_sessions(device_id, event_type, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_netlog_device       ON device_network_logs(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_seclog_device       ON device_security_logs(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_statusevt_device    ON device_status_events(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_enroll_tickets_device ON enrollment_tickets(device_id);
CREATE INDEX IF NOT EXISTS idx_remote_assist_device  ON remote_assist_sessions(device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_keylog_device       ON keylog_entries(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_screen_text_device  ON screen_text_entries(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_notif_device        ON notifications(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_clip_device         ON clipboard_events(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_shell_device        ON shell_sessions(device_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_zk_event            ON zk_payloads(device_id, event_type, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_orders_user         ON orders(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_entitlements_user   ON entitlements(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_entitlements_device ON entitlements(device_id);
CREATE INDEX IF NOT EXISTS idx_tos_user            ON tos_acceptances(user_id, accepted_at DESC);
CREATE INDEX IF NOT EXISTS idx_rma_user            ON rma_requests(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_rma_order           ON rma_requests(order_id);
CREATE INDEX IF NOT EXISTS idx_rma_photos          ON rma_photos(rma_id);
CREATE INDEX IF NOT EXISTS idx_support_thread_user   ON support_threads(user_id);
CREATE INDEX IF NOT EXISTS idx_support_thread_recent ON support_threads(last_msg_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_support_thread_convo ON support_threads(conversation_id);
CREATE INDEX IF NOT EXISTS idx_support_msg         ON support_messages(thread_id, created_at);
CREATE INDEX IF NOT EXISTS idx_guest_thread_recent ON guest_threads(last_msg_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_guest_thread_convo ON guest_threads(conversation_id);
CREATE INDEX IF NOT EXISTS idx_guest_thread_by_guest ON guest_threads(guest_id, last_msg_at DESC);
CREATE INDEX IF NOT EXISTS idx_guest_msg           ON guest_messages(thread_id, created_at);
CREATE INDEX IF NOT EXISTS idx_bug_reports_recent  ON bug_reports(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_subs_email          ON subscriptions(email);
CREATE INDEX IF NOT EXISTS idx_subs_user           ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_wa_ts               ON web_analytics(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_wa_sh               ON web_analytics(session_hash, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_bt_ts               ON bot_traffic(timestamp DESC);

CREATE TABLE IF NOT EXISTS tailnet_groups (
  id         TEXT PRIMARY KEY,
  name       TEXT NOT NULL,
  subnets    TEXT NOT NULL DEFAULT '[]',
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tailnet_groups_created ON tailnet_groups(created_at);

-- Sidebar device groups (WebUI organization only — NOT related to tailnet_groups).
-- owner_key scopes a group to ONE user: admin groups (owner_key from the admin session)
-- are private to the admin and apply to admin-fleet devices; public-user groups are
-- private to that public user and apply to their own devices. A device's ui_group_id
-- always points at a group owned by its controlling party, so the owner-type split is
-- never crossed (admins never group public/ZK devices; public users never see admin devices).
CREATE TABLE IF NOT EXISTS device_groups (
  id         TEXT PRIMARY KEY,
  owner_key  TEXT NOT NULL,
  name       TEXT NOT NULL,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_groups_owner ON device_groups(owner_key, sort_order, created_at);

-- ARP scan / network discovery ("ARPwatch"-style persistent roster) — Windows Remote Assist
-- devices only. Current known-neighbor roster per RA device's LAN, keyed by MAC (a device's
-- identity persists across DHCP-assigned IP changes; ARPwatch-style spoof detection relies on
-- keying by MAC and watching for a KNOWN ip_address later reporting a DIFFERENT mac — see
-- arp_events below). Upserted by ingestArpScanResult() on every scan (manual or scheduled).
CREATE TABLE IF NOT EXISTS arp_neighbors (
  device_id   TEXT    NOT NULL,
  mac_address TEXT    NOT NULL,
  ip_address  TEXT    NOT NULL,
  hostname    TEXT,
  first_seen  BIGINT  NOT NULL,
  last_seen   BIGINT  NOT NULL,
  -- Owner-set "authorized scanner" flag (Nmap/Fing/etc a client runs intentionally) — suppresses
  -- arp_sweep alerts for this MAC in ingestArpSweepEvents(); the arp_events row is still recorded,
  -- only the notifyUser() call is skipped. Never suppresses arp_spoof (mac_changed_for_ip) —
  -- trusting a scanner's own recon behavior says nothing about IP/MAC binding integrity.
  trusted     INTEGER NOT NULL DEFAULT 0,
  -- Aggressive fingerprinting from the last scan that saw this neighbor: open TCP ports (JSON int
  -- array) and hosted web UIs (JSON [{port,url,status,title,server}]). NULL when the scanning
  -- agent/bastion predates the feature or nothing answered.
  open_ports  TEXT,
  web_ui      TEXT,
  PRIMARY KEY (device_id, mac_address)
);
CREATE INDEX IF NOT EXISTS idx_arp_neighbors_device ON arp_neighbors(device_id, last_seen DESC);

-- Append-only event log: new_device / ip_changed / mac_changed_for_ip (spoof-suspect —
-- a previously-seen IP now resolving to a different MAC) / device_reappeared. Feeds both the
-- roster's flag badges and the daily AI summary prompt (recent events, not just the static list).
CREATE TABLE IF NOT EXISTS arp_events (
  id          SERIAL PRIMARY KEY,
  device_id   TEXT    NOT NULL,
  event_type  TEXT    NOT NULL,
  mac_address TEXT    NOT NULL,
  ip_address  TEXT    NOT NULL,
  prior_value TEXT,
  timestamp   BIGINT  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_arp_events_device ON arp_events(device_id, timestamp DESC);

-- A managed device's OWN adapter MACs, reported by its ARP scan (_ARP_SCAN_PS1's `selfMacs`).
-- Sole purpose: let ingestArpSweepEvents() recognise that a "sweep" it just detected was OUR OWN
-- Network Discovery scan — either this very box (pktmon sniffs the local adapter, so a box sees
-- its own outbound ARP storm) or another managed device in the same account. On the wire a
-- managed scan and a hostile scan are byte-identical, so identity is the only sound
-- discriminator; raising the >=15-target threshold would just blind the detector to real sweeps.
--
-- !! This table MUST live here, not only in server.js's `if (!isPg)` block. It was originally
-- added to the SQLite branch alone (2026-08-03), so it never existed in Postgres: every
-- device_self_macs upsert AND the suppression lookup threw, both were swallowed by their
-- try/catch, and the entire sibling/self suppression silently did nothing in production while
-- reading as "fixed". Symptom was an arp_recon alert flood — N managed boxes on one LAN page
-- N*(N-1) sibling alerts plus N self alerts every scan interval, and arp_recon is default-ON.
-- Same class as the BitLocker schema.sql gotcha; verify a new table with
-- `SELECT ... FROM information_schema.tables`, never by reading server.js.
CREATE TABLE IF NOT EXISTS device_self_macs (
  device_id   TEXT   NOT NULL,
  mac_address TEXT   NOT NULL,
  last_seen   BIGINT NOT NULL,
  PRIMARY KEY (device_id, mac_address)
);
CREATE INDEX IF NOT EXISTS idx_device_self_macs_mac ON device_self_macs(mac_address);

-- ── Learn Mode ───────────────────────────────────────────────────────────────────────────────
-- A time-boxed window per device during which the noisy heuristic detectors (arp_recon, EDR,
-- Sentry) still RECORD everything but do not PAGE. Every distinct finding signature seen in the
-- window accumulates here; at expiry the owner reviews the list and accepts each one as normal
-- (permanent suppression) or rejects it (keeps alerting). Generalizes the four ad-hoc versions
-- of this idea already in the codebase: arp_neighbors.trusted, _KNOWN_BENIGN_TASKS,
-- EdrWatcher's IsOwnToolingLineage, and the EDR 30-min suppression window.
--
-- Deliberately NOT indefinite: `expires_at` is mandatory and the worker poller closes the window
-- and pages the owner to review. A detector that is silent forever is worse than no detector.
CREATE TABLE IF NOT EXISTS learn_mode (
  device_id   TEXT   PRIMARY KEY,
  started_at  BIGINT NOT NULL,
  expires_at  BIGINT NOT NULL,
  started_by  TEXT,
  -- NULL = window still open. Set by the expiry poller (or an early manual stop); a closed window
  -- leaves its observations behind for review, so this is not a delete.
  ended_at    BIGINT,
  -- Set once the "learn window closed, N findings to review" alert has gone out, so the 60s
  -- poller pages exactly once per window rather than every tick.
  notified_at BIGINT
);

-- One row per distinct (device, category, signature). `decision` NULL = seen during a window and
-- still pending review; 'accepted' = permanent baseline (suppress this signature from now on,
-- even outside a learn window); 'rejected' = keep alerting. Rows survive window close — the
-- accepted set IS the baseline.
CREATE TABLE IF NOT EXISTS learn_observations (
  device_id  TEXT    NOT NULL,
  category   TEXT    NOT NULL,
  signature  TEXT    NOT NULL,
  detail     TEXT,
  hits       INTEGER NOT NULL DEFAULT 1,
  first_seen BIGINT  NOT NULL,
  last_seen  BIGINT  NOT NULL,
  decision   TEXT,
  decided_at BIGINT,
  PRIMARY KEY (device_id, category, signature)
);
CREATE INDEX IF NOT EXISTS idx_learn_obs_device ON learn_observations(device_id, decision);

-- Per-user alert center — persistent alert history surfaced in the WebUI's "All Alerts" panel
-- (one place to monitor every alert + copy any/all to an AI for analytics). Written by
-- notifyUser() for every alert that passes the user's category gate (see persistUserAlert in
-- server.js). Metadata only: the same category-tagged text delivered via email/push/Discord —
-- never private payloads, never ZK data. Archived rows persist until the user's own
-- "Clear History" action; no TTL sweep (same reasoning as arp_events).
CREATE TABLE IF NOT EXISTS user_alerts (
  id          SERIAL PRIMARY KEY,
  user_id     TEXT   NOT NULL,
  device_id   TEXT,
  category    TEXT,
  message     TEXT   NOT NULL,
  created_at  BIGINT NOT NULL,
  archived_at BIGINT,
  audit_result TEXT,
  proposed_fix TEXT
);
ALTER TABLE user_alerts ADD COLUMN IF NOT EXISTS device_id TEXT;
ALTER TABLE user_alerts ADD COLUMN IF NOT EXISTS audit_result TEXT;
ALTER TABLE user_alerts ADD COLUMN IF NOT EXISTS proposed_fix TEXT;
CREATE INDEX IF NOT EXISTS idx_user_alerts_user ON user_alerts(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_user_alerts_device ON user_alerts(device_id, created_at DESC);

-- Indoor-positioning anchors: calibrated known WiFi APs / Bluetooth devices with a fixed
-- map coordinate + reference RSSI (@1m). The Location tab trilaterates the device position
-- from these when GPS is poor indoors. user_id scopes them to the account that placed them.
CREATE TABLE IF NOT EXISTS proximity_anchors (
  id         SERIAL PRIMARY KEY,
  user_id    TEXT   NOT NULL,
  kind       TEXT   NOT NULL,            -- 'wifi' | 'bt'
  address    TEXT   NOT NULL,            -- BSSID or BT MAC (uppercase)
  name       TEXT,
  lat        DOUBLE PRECISION NOT NULL,
  lng        DOUBLE PRECISION NOT NULL,
  ref_rssi   INTEGER NOT NULL,           -- RSSI measured at ~1m from the anchor
  created_at BIGINT NOT NULL
);
ALTER TABLE proximity_anchors ADD COLUMN IF NOT EXISTS origin TEXT DEFAULT 'manual';  -- 'manual' | 'auto' (self-calibrated)
CREATE INDEX IF NOT EXISTS idx_proximity_anchors_user ON proximity_anchors(user_id);
CREATE INDEX IF NOT EXISTS idx_proximity_anchors_addr ON proximity_anchors(address);
CREATE UNIQUE INDEX IF NOT EXISTS uq_proximity_anchors_user_addr ON proximity_anchors(user_id, address);

-- Learned cell-tower positions: the server estimates each tower's location from accurate
-- GPS fixes (the serving cell is within coverage), then triangulates the device position
-- from serving+neighbour cell signals when GPS/WiFi/BT are unavailable (urban canyons,
-- basements). Keyed by the network identity (MCC/MNC/TAC/CID) reported by the device.
CREATE TABLE IF NOT EXISTS cell_towers (
  id         SERIAL PRIMARY KEY,
  mcc        INTEGER NOT NULL,
  mnc        INTEGER NOT NULL,
  tac        INTEGER NOT NULL,
  cid        BIGINT  NOT NULL,
  lat        DOUBLE PRECISION NOT NULL,
  lng        DOUBLE PRECISION NOT NULL,
  ref_dbm    INTEGER NOT NULL,            -- strongest signal ever seen (~tower proximity)
  samples    INTEGER NOT NULL DEFAULT 0,
  spread_m   DOUBLE PRECISION NOT NULL DEFAULT 0,
  source     TEXT NOT NULL DEFAULT 'learned', -- 'ocid' = real position from the OpenCellID DB, 'learned' = GPS-vote estimate
  updated_at BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cell_towers_key ON cell_towers(mcc, mnc, tac, cid);
-- Fleet-learned position (GPS votes; see voteTowerPositions in server.js). Alongside the
-- OCID columns, never overwriting them. learned_snapped=1 means snapped to an OSM mast.
ALTER TABLE cell_towers ADD COLUMN IF NOT EXISTS learned_lat DOUBLE PRECISION;
ALTER TABLE cell_towers ADD COLUMN IF NOT EXISTS learned_lng DOUBLE PRECISION;
ALTER TABLE cell_towers ADD COLUMN IF NOT EXISTS learned_samples INTEGER NOT NULL DEFAULT 0;
ALTER TABLE cell_towers ADD COLUMN IF NOT EXISTS learned_spread DOUBLE PRECISION NOT NULL DEFAULT 0;
ALTER TABLE cell_towers ADD COLUMN IF NOT EXISTS learned_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE cell_towers ADD COLUMN IF NOT EXISTS learned_snapped INTEGER NOT NULL DEFAULT 0;
-- Operator-placed truth (map correction). Wins over learned and OCID positions.
ALTER TABLE cell_towers ADD COLUMN IF NOT EXISTS manual_lat DOUBLE PRECISION;
ALTER TABLE cell_towers ADD COLUMN IF NOT EXISTS manual_lng DOUBLE PRECISION;
ALTER TABLE cell_towers ADD COLUMN IF NOT EXISTS manual_at BIGINT NOT NULL DEFAULT 0;
-- Physical structures from OpenStreetMap (steel locations, NOT cell-ID mappings).
CREATE TABLE IF NOT EXISTS osm_masts (
  id         SERIAL PRIMARY KEY,
  osmid      TEXT   NOT NULL,            -- 'node/123' | 'way/456'
  kind       TEXT   NOT NULL,            -- mast | tower | antenna
  lat        DOUBLE PRECISION NOT NULL,
  lng        DOUBLE PRECISION NOT NULL,
  tags       TEXT,                        -- JSON tag subset
  updated_at BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_osm_masts_osmid ON osm_masts(osmid);
CREATE INDEX IF NOT EXISTS idx_osm_masts_latlng ON osm_masts(lat, lng);
-- OSM tile coverage: which 0.5° cells have been fetched from Overpass (global on-demand).
CREATE TABLE IF NOT EXISTS osm_tiles (
  cell       TEXT   NOT NULL PRIMARY KEY,  -- 'lat:lng' of the tile's south-west corner
  fetched_at BIGINT NOT NULL
);
-- Known WiFi AP positions (BSSID → lat/lng), cached from WiGLE (source='wigle').
CREATE TABLE IF NOT EXISTS wifi_aps (
  bssid      TEXT   NOT NULL PRIMARY KEY,
  ssid       TEXT,
  lat        DOUBLE PRECISION NOT NULL,
  lng        DOUBLE PRECISION NOT NULL,
  accuracy_m INTEGER NOT NULL DEFAULT 100,
  source     TEXT   NOT NULL DEFAULT 'wigle',
  updated_at BIGINT NOT NULL
);

-- AppLocker blocked-file auto-upload — see server.js's runtime migration comment / the support service's
-- fetch_blocked_file_to_disk() doc comment. r2_key is NULL for a 'skipped_size' row until an admin
-- force-uploads it.
-- path_hash = sha256(lowercased path), for dedup/delete lookups (encrypted `path` can't be
-- WHERE-matched — random-IV AES-GCM, same plaintext encrypts differently every time).
CREATE TABLE IF NOT EXISTS applocker_blocked_files (
  id          TEXT    PRIMARY KEY,
  device_id   TEXT    NOT NULL,
  path        TEXT    NOT NULL,
  path_hash   TEXT    NOT NULL,
  file_name   TEXT    NOT NULL,
  size_bytes  BIGINT  NOT NULL DEFAULT 0,
  r2_key      TEXT,
  status      TEXT    NOT NULL,
  error       TEXT,
  blocked_at  BIGINT  NOT NULL,
  uploaded_at BIGINT
);
CREATE INDEX IF NOT EXISTS idx_applocker_blocked_device ON applocker_blocked_files(device_id, blocked_at DESC);
CREATE INDEX IF NOT EXISTS idx_applocker_blocked_path_hash ON applocker_blocked_files(device_id, path_hash);

-- AppLocker AUDIT-mode (8003) seen-paths — durable dedup independent of user_alerts, so
-- archiving/clearing alert history can't make the same executable re-alert on its next run.
CREATE TABLE IF NOT EXISTS applocker_audit_seen (
  device_id  TEXT    NOT NULL,
  path_hash  TEXT    NOT NULL,
  path       TEXT    NOT NULL,
  first_seen BIGINT  NOT NULL,
  PRIMARY KEY (device_id, path_hash)
);
CREATE INDEX IF NOT EXISTS idx_applocker_audit_seen_device ON applocker_audit_seen(device_id, first_seen DESC);

-- File Backup — run history AND the async-job status row polled by the WebUI (backup/restore is
-- fire-and-forget server-side, see server.js's run/restore routes). S3 config lives in `settings`
-- (file_backup_s3:<userId>, per-account, see server.js's getFileBackupS3Config()).
CREATE TABLE IF NOT EXISTS file_backup_runs (
  id           TEXT   PRIMARY KEY,
  device_id    TEXT   NOT NULL,
  kind         TEXT   NOT NULL DEFAULT 'backup',
  status       TEXT   NOT NULL,
  s3_key       TEXT,
  size_bytes   BIGINT NOT NULL DEFAULT 0,
  profiles     TEXT,
  error        TEXT,
  restored_to  TEXT,
  backup_kind  TEXT,
  started_at   BIGINT NOT NULL,
  completed_at BIGINT
);
CREATE INDEX IF NOT EXISTS idx_file_backup_runs_device ON file_backup_runs(device_id, started_at DESC);

-- BitLocker recovery keys — harvested from Get-BitLockerVolume's RecoveryPassword key protectors
-- (bastionClient.bitlockerEnable/bitlockerStatus in server.js). recovery_key is encryptText()'d at
-- rest, same server-key encryption as file_backup_s3/s3_drive secrets (admin/owner infrastructure,
-- not the Android ZK private-data pipeline). Deliberately no TTL/cleanup sweep — a recovery key
-- must stay available for as long as its disk stays encrypted; only manual delete clears a row.
CREATE TABLE IF NOT EXISTS bitlocker_keys (
  id               TEXT   PRIMARY KEY,
  device_id        TEXT   NOT NULL,
  volume           TEXT   NOT NULL,
  key_protector_id TEXT   NOT NULL,
  recovery_key     TEXT   NOT NULL,
  created_at       BIGINT NOT NULL,
  UNIQUE(device_id, key_protector_id)
);
CREATE INDEX IF NOT EXISTS idx_bitlocker_keys_device ON bitlocker_keys(device_id, created_at DESC);

-- Daily-rate-limited AI-generated network summary (same provider as Ask-AI). One row per
-- generation, not just a single latest — the dashboard and the opt-in email both read the newest
-- row per device, but keeping history lets a report be looked back on later.
CREATE TABLE IF NOT EXISTS arp_ai_summaries (
  id           SERIAL PRIMARY KEY,
  device_id    TEXT    NOT NULL,
  summary      TEXT    NOT NULL,
  generated_at BIGINT  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_arp_ai_summaries_device ON arp_ai_summaries(device_id, generated_at DESC);

-- Last-emailed watermark for the two opt-in AI-report email categories (ARP daily summary, IT
-- Mode Audit summary) — lets the polling loop in server.js tell "already emailed this one" apart
-- from "a genuinely new result showed up", without re-emailing the same unchanged report every
-- poll tick. One row per device; either column may be NULL if that report type was never emailed.
CREATE TABLE IF NOT EXISTS ai_report_email_state (
  device_id            TEXT PRIMARY KEY,
  last_arp_email_at    BIGINT,
  last_audit_email_at  BIGINT
);

-- Canary/dark-space IPs ("ARPwatch"-style trap) — per-subnet decoy addresses that should never
-- legitimately answer. Auto-designated by ingestArpScanResult() from the top of each newly-seen
-- subnet's host range (heuristic, not a guarantee — see pickCanaryCandidateIps()). A candidate
-- must be absent from 3 consecutive scans (consecutive_dark_scans) before confirmed_at is set; a
-- candidate that turns out occupied before confirmation is dropped, never re-picked. Only a
-- CONFIRMED canary answering fires a 'canary_hit' arp_events row + instant alert — see the
-- 'arp_recon' category. One row per (device, ip) — a device can roam across subnets over time
-- (different WiFi networks), so old rows for a subnet no longer reported just stop being checked,
-- never deleted (harmless, keeps history).
CREATE TABLE IF NOT EXISTS arp_canary_ips (
  device_id              TEXT    NOT NULL,
  subnet                 TEXT    NOT NULL,
  ip_address             TEXT    NOT NULL,
  candidate_at           BIGINT  NOT NULL,
  confirmed_at           BIGINT,
  consecutive_dark_scans INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (device_id, ip_address)
);
CREATE INDEX IF NOT EXISTS idx_arp_canary_ips_device ON arp_canary_ips(device_id);

-- Manually-added VLAN subnets for ARP scan/sweep — allows the user to specify additional subnets
-- the device should scan beyond its own local interfaces. VLANs are per-device and stored
-- server-side; the server passes them to the bastion on each scan. Each entry has a user-facing
-- label (e.g. "Camera VLAN"), the CIDR subnet to scan (e.g. "192.168.1.0/24"), and an optional
-- VLAN ID (e.g. 4001). The scan scripts (Windows _ARP_SCAN_PS1 / Linux sentineld) receive these
-- as extra targets and include them in the ping sweep + neighbor readback alongside local subnets.
CREATE TABLE IF NOT EXISTS arp_vlans (
  device_id   TEXT    NOT NULL,
  label       TEXT    NOT NULL,
  subnet      TEXT    NOT NULL,
  vlan_id     INTEGER,
  created_at  BIGINT  NOT NULL,
  PRIMARY KEY (device_id, subnet)
);
CREATE INDEX IF NOT EXISTS idx_arp_vlans_device ON arp_vlans(device_id);

-- USB Lockdown approval history — every successful approve action against a Windows RA device.
-- Written server-side in the /usblock/approve passthrough route; the live "allowed devices"
-- snapshot on the box (usb-lockdown.json) is transient, this is the durable audit trail shown
-- in the USB Lockdown tab ("Approval History"). One row per approval event (keeps history);
-- the UI shows the latest rows per device.
CREATE TABLE IF NOT EXISTS usblock_approvals (
  id            SERIAL PRIMARY KEY,
  device_id     TEXT    NOT NULL,
  instance_id   TEXT    NOT NULL,
  friendly_name TEXT,
  class         TEXT,
  approved_at   BIGINT  NOT NULL,
  vid_pid       TEXT
);
CREATE INDEX IF NOT EXISTS idx_usblock_approvals_device ON usblock_approvals(device_id, approved_at DESC);

-- EDR event "mark safe" — admin dismissals of individual EDR findings (device_id + bastion-side
-- event id, plus a rule/time snapshot so a jsonl reset that reuses event ids can't wrongly match).
-- Safe events are hidden from the default EDR feed in the WebUI (toggle to show), never alerted.
CREATE TABLE IF NOT EXISTS edr_safe_events (
  id         SERIAL PRIMARY KEY,
  device_id  TEXT   NOT NULL,
  event_id   BIGINT NOT NULL,
  rule       TEXT,
  reason     TEXT,
  image      TEXT,
  time       TEXT,
  marked_at  BIGINT NOT NULL,
  UNIQUE (device_id, event_id, rule)
);
CREATE INDEX IF NOT EXISTS idx_edr_safe_events_device ON edr_safe_events(device_id);

-- ── AI Auto-Audit on Alerts ──────────────────────────────────────────────────────────────────
-- When a user_alert fires for a Windows/Linux RA device, the IS_WORKER auto-audit poller triggers
-- a bastion IT audit (14-category forensics → OpenCode DeepSeek analysis) automatically. This
-- table tracks every triggered review: what alert caused it, what the AI found, and whether it
-- was a false positive (suppressed for future occurrences of the same signature).
CREATE TABLE IF NOT EXISTS alert_auto_audits (
  id                    SERIAL PRIMARY KEY,
  alert_id              INTEGER NOT NULL,
  device_id             TEXT    NOT NULL,
  user_id               TEXT    NOT NULL,
  status                TEXT    NOT NULL DEFAULT 'pending', -- pending|running|completed|failed|suppressed
  audit_verdict         TEXT,                               -- bastion IT audit verdict (CLEAN / ATTENTION NEEDED)
  ai_analysis           TEXT,                               -- full OpenCode DeepSeek analysis text
  false_positive        INTEGER NOT NULL DEFAULT 0,
  suppression_signature TEXT,                               -- sha256 of category+device+key_indicators
  alert_handled         INTEGER NOT NULL DEFAULT 0,         -- 1 after the "AI investigated" report was sent
  started_at            BIGINT,
  completed_at          BIGINT,
  created_at            BIGINT  NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_alert_auto_audits_device ON alert_auto_audits(device_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_alert_auto_audits_alert ON alert_auto_audits(alert_id);

-- Per-device AI memory: a rolling history of what the AI has found, investigated, and suppressed
-- for this device. Surfaced in the dashboard under a new "AI Memory" section per device.
CREATE TABLE IF NOT EXISTS device_ai_memory (
  id              SERIAL PRIMARY KEY,
  device_id       TEXT   NOT NULL,
  user_id         TEXT   NOT NULL,
  event_type      TEXT   NOT NULL,  -- 'alert_audit', 'scheduled_audit', 'false_positive', 'remediation'
  summary         TEXT   NOT NULL,  -- concise AI verdict
  ai_verdict      TEXT,             -- REAL_THREAT | FALSE_POSITIVE | INCONCLUSIVE | RESOLVED
  root_cause      TEXT,             -- extracted root cause fingerprint
  action_taken    TEXT,             -- what the AI did (if remediation was instructed)
  raw_analysis    TEXT,             -- full AI response
  created_at      BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_ai_memory_device ON device_ai_memory(device_id, created_at DESC);

-- Per-account AI overview: aggregated across all devices owned by this user. Generated periodically
-- or on-demand to give a bird's-eye view of security trends across the fleet.
CREATE TABLE IF NOT EXISTS account_ai_memory (
  id            SERIAL PRIMARY KEY,
  user_id       TEXT   NOT NULL,
  summary       TEXT   NOT NULL,
  created_at    BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_account_ai_memory_user ON account_ai_memory(user_id, created_at DESC);
