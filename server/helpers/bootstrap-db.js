// helpers/bootstrap-db.js — Postgres schema apply + admin/env user bootstrap.
//
// A HELPER module, not a route module: it registers nothing itself. It is CALLED
// eagerly at load (`bootstrapDb();`, now L1626-ish) — so the wiring line sits
// BELOW all its deps and ABOVE that call.
//
//   bootstrapDb   export   apply schema.sql, seed admin/env users, backfill
//                          enrollment tokens; resolves the dbReady promise
//
// IN-PLACE splice at the block position (X = L612, comment absorbed from L609).
// Deps:
//   * _resolveDbReady — `let` at L606, assigned synchronously by the Promise
//     executor at L607 (i.e. BEFORE this wiring line runs) and never rewritten
//     afterwards. Passed BY VALUE (the brief's sanctioned mechanism); the body
//     calls it bare, which is the only canonically-valid form for a call site.
//   * _loadOrInitServerGeneration (L442), ADMIN_PASS/ADMIN_USER (L92/L91),
//     AUTH_SCHEME_PREHASH (L263), bcrypt (L8), computeAuthPrehashSync /
//     newAuthSalt (L266), fs (L14), isPg / pgConn (L434), log (L250), path (L13),
//     redisEnabled (L21) — all stable and above the wiring line.
//   * db travels as the LIVE getter `getDb: () => db` (reads rewritten to
//     `getDb().…`).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ ADMIN_PASS, ADMIN_USER, AUTH_SCHEME_PREHASH, _loadOrInitServerGeneration, _resolveDbReady, bcrypt, computeAuthPrehashSync, crypto, fs, getDb, isPg, log, newAuthSalt, path, pgConn, redisEnabled }) => {

// On Postgres: apply schema.sql + bootstrap admin/env users + backfill enrollment
// tokens (the async equivalent of the inline SQLite DDL+bootstrap below).
// On SQLite: a no-op — the inline `if (!isPg)` block already did all of it.
async function bootstrapDb() {
  try {
    if (isPg) {
      // Serialize schema creation across replicas (3 web + 1 worker boot together):
      // a txn-scoped advisory lock means the first instance applies the DDL and the
      // rest no-op on IF NOT EXISTS instead of racing concurrent CREATE TABLEs.
      await pgConn.tx(async t => {
        await t.any('SELECT pg_advisory_xact_lock($1)', [726270]);
        await t.none(fs.readFileSync(path.join(__dirname, '..', 'schema.sql'), 'utf8'));
        // Idempotent column adds for EXISTING deployments — schema.sql's CREATE TABLE IF NOT EXISTS
        // won't alter a table that already exists. Postgres supports ADD COLUMN IF NOT EXISTS.
        await t.none('ALTER TABLE devices ADD COLUMN IF NOT EXISTS apk_signer TEXT');
        // ZK device_status metadata blob (battery/motion/network) for public-user devices.
        await t.none('ALTER TABLE device_telemetry ADD COLUMN IF NOT EXISTS status_zk TEXT');
        await t.none('ALTER TABLE device_telemetry ADD COLUMN IF NOT EXISTS status_dek TEXT');
        await t.none('ALTER TABLE device_telemetry ADD COLUMN IF NOT EXISTS status_ts BIGINT');
        // Bluetooth scan snapshot (JSON of nearby devices + detected trackers) for the
        // BT-scanner feature — latest only, overwritten each scan (no history).
        await t.none('ALTER TABLE device_telemetry ADD COLUMN IF NOT EXISTS bt_devices TEXT');
        await t.none('ALTER TABLE device_telemetry ADD COLUMN IF NOT EXISTS bt_scan_ts BIGINT');
        // BT scanner ON/OFF state reported by the device — lets the WebUI reflect the real
        // device-side scanning state even when the in-memory deviceStatus map isn't populated.
        await t.none('ALTER TABLE device_telemetry ADD COLUMN IF NOT EXISTS bt_scan_state BOOLEAN');
        // BT scanner safelist — MAC addresses the owner marked "safe" (suppress false tracker
        // alerts). Stored as JSON array [{address,name,ts}], per-device.
        await t.none('ALTER TABLE device_telemetry ADD COLUMN IF NOT EXISTS bt_safelist TEXT');
        // Per-app pause/unpause schedules ('weekly_set' recurrence): weekday set + IANA tz.
        await t.none('ALTER TABLE scheduled_commands ADD COLUMN IF NOT EXISTS days TEXT');
        await t.none('ALTER TABLE scheduled_commands ADD COLUMN IF NOT EXISTS tz TEXT');
        // USB Lockdown: vid_pid (XXXX:XXXX) — the agent-side approved.txt allowlist key. Stored at
        // approve time (Linux agents return it) so the Remove button can revoke by vid:pid, which
        // is stable across replugs (usbguard renumbers instance ids).
        await t.none('ALTER TABLE usblock_approvals ADD COLUMN IF NOT EXISTS vid_pid TEXT');
        // Tailnet access groups — assigned per device for split-tunnel routing
        await t.none('ALTER TABLE devices ADD COLUMN IF NOT EXISTS tailnet_group_id TEXT REFERENCES tailnet_groups(id) ON DELETE SET NULL');
        // Sidebar device groups (WebUI organization only) — assigned per device.
        await t.none('ALTER TABLE devices ADD COLUMN IF NOT EXISTS ui_group_id TEXT REFERENCES device_groups(id) ON DELETE SET NULL');
        // Owner-archived (soft-hide) flag — a public owner can hide old devices from their own list.
        await t.none('ALTER TABLE devices ADD COLUMN IF NOT EXISTS archived INTEGER NOT NULL DEFAULT 0');
        // Free-trial "1 day left" email dedupe (BIGINT epoch-ms; never an INTEGER — would overflow).
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS trial_1d_alerted_at BIGINT');
        // Email-ownership verification code (sha256 hash) + expiry (BIGINT epoch-ms).
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verify_hash TEXT');
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verify_expires BIGINT');
        // Device re-home: code (sha256) sent to the ORIGINAL email to authorize a different-email move.
        await t.none('ALTER TABLE devices ADD COLUMN IF NOT EXISTS rehome_code_hash TEXT');
        await t.none('ALTER TABLE devices ADD COLUMN IF NOT EXISTS rehome_code_expires BIGINT');
        // Client-side password pre-hashing ("prehash-v1"): password_hash becomes bcrypt(PBKDF2
        // prehash) instead of bcrypt(plaintext); pw_scheme tracks which form the row stores and
        // auth_salt is the per-user PBKDF2 salt served pre-auth by /api/auth/prelogin.
        await t.none("ALTER TABLE users ADD COLUMN IF NOT EXISTS pw_scheme TEXT NOT NULL DEFAULT 'plain'");
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS auth_salt TEXT');
        // Admin-granted complimentary ("comp") subscription — a free override that exempts a public
        // account from the trial lock / 48h auto-wipe and sets its device cap (see compPlanFor()).
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS comp_plan TEXT');
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS comp_expires_at BIGINT');
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS comp_granted_by TEXT');
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS comp_granted_at BIGINT');
        // Business Account compliance mode (one-way, public accounts only; admin can revert) +
        // business sub-user parent linkage (account_type='business_sub' rows point at the owner).
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS business_mode INTEGER NOT NULL DEFAULT 0');
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS business_mode_set_at BIGINT');
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS business_mode_reverted_at BIGINT');
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS business_mode_reverted_by TEXT');
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS parent_owner_id INTEGER REFERENCES users(id)');
        // Hybrid Managed "Grant support access": a business_sub row flagged 1 is the SentinelMDM
        // support delegate — created WITHOUT enabling business_mode (so the owner keeps camera/audio/
        // etc.), auto-scoped to all the owner's devices, and shown/managed in its own panel.
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS is_support_delegate INTEGER NOT NULL DEFAULT 0');
        // The support code, delivered to admin via GENUINE E2E — client-side AES-256-GCM under a
        // random DEK, DEK ECDH-wrapped to the shared Support pubkey (settings['support_zk_public']),
        // same primitive as the existing E2E "Conversations" support chat (_scWrapBytes/dek_support
        // wire format). The server stores/relays ciphertext it structurally cannot decrypt — NOT
        // encrypted with a server-held key. Requires Support E2E encryption to be enabled (admin
        // dashboard toggle); the grant flow checks this via GET /api/support/support-pubkey first.
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS support_code_payload TEXT');
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS support_code_dek_support TEXT');
        // AI Auto-Audit result cached inline on the original alert row (see triggerAutoAuditForAlert).
        // Rendered in the WebUI All Alerts panel as a colored glow + inline verdict/summary.
        await t.none('ALTER TABLE user_alerts ADD COLUMN IF NOT EXISTS audit_result TEXT');
        // Audit trail: which admin fetched (and, client-side, decrypted) a support-delegate code.
        await t.none(`CREATE TABLE IF NOT EXISTS support_code_reveals (
          id SERIAL PRIMARY KEY,
          delegate_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          revealed_by TEXT NOT NULL,
          revealed_at BIGINT NOT NULL
        )`);
        // Bug-report image attachments (base64 in-row; small volume, purged when the report is deleted).
        await t.none(`CREATE TABLE IF NOT EXISTS bug_report_photos (
          id SERIAL PRIMARY KEY,
          bug_id INTEGER NOT NULL REFERENCES bug_reports(id) ON DELETE CASCADE,
          content_type TEXT,
          data TEXT NOT NULL,
          uploaded_at BIGINT NOT NULL )`);
        await t.none('CREATE INDEX IF NOT EXISTS idx_bug_report_photos ON bug_report_photos(bug_id)');
        // Two-way conversation thread on a bug report (admin ↔ submitter). Body encrypted at rest.
        await t.none(`CREATE TABLE IF NOT EXISTS bug_report_messages (
          id SERIAL PRIMARY KEY,
          bug_id INTEGER NOT NULL REFERENCES bug_reports(id) ON DELETE CASCADE,
          sender_role TEXT NOT NULL,
          sender_user_id INTEGER,
          sender_name TEXT,
          body TEXT NOT NULL,
          created_at BIGINT NOT NULL )`);
        await t.none('CREATE INDEX IF NOT EXISTS idx_bug_report_messages ON bug_report_messages(bug_id)');
        // Lock KIND: 'public' (locked ⇒ ZK-private, hidden from admin) vs 'admin' (admin-fleet device:
        // locked for anti-theft but still admin-VISIBLE). Decouples the lineage lock from ZK-privacy.
        await t.none("ALTER TABLE devices ADD COLUMN IF NOT EXISTS lineage_kind TEXT DEFAULT 'public'");
        // Discriminates the SentinelRemoteAssist (consensual Windows remote-support tool) device
        // class from the native/reserved-future Windows agent path — NULL/'native' = existing,
        // 'remote_assist' = a SentinelRemoteAssist-registered device. New Windows-agent UI/endpoints
        // gate on this, never on bare platform='windows', so the two concepts can't collide.
        await t.none("ALTER TABLE devices ADD COLUMN IF NOT EXISTS agent_kind TEXT DEFAULT NULL");
        // Synthetic demo device seeded for public users before they add a real one (see
        // createDemoDeviceForUser()) — excluded from ZK/admin-visibility/plan-device-count logic.
        await t.none('ALTER TABLE devices ADD COLUMN IF NOT EXISTS is_demo INTEGER NOT NULL DEFAULT 0');
        // E2E ("Conversations") support chat: ciphertext-only columns (server cannot read enc=1 rows).
        await t.none('ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS enc INTEGER NOT NULL DEFAULT 0');
        await t.none('ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS payload TEXT');
        await t.none('ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS dek_user TEXT');
        await t.none('ALTER TABLE support_messages ADD COLUMN IF NOT EXISTS dek_support TEXT');
        // Shared Support private key, ECDH-wrapped to THIS staffer's personal pubkey ({eph_pub,iv,ct}).
        await t.none('ALTER TABLE users ADD COLUMN IF NOT EXISTS support_key_wrap TEXT');
        // Web Analytics — geo enrichment (resolved server-side from the visitor's IP at ingest
        // time, then the IP is discarded; only these two resolved strings are ever stored).
        await t.none('ALTER TABLE web_analytics ADD COLUMN IF NOT EXISTS country TEXT');
        await t.none('ALTER TABLE web_analytics ADD COLUMN IF NOT EXISTS city TEXT');
        // Web Analytics — real traffic-source tracking (UTM campaign params; `referrer` itself
        // is an existing column, repurposed to hold document.referrer's hostname instead of the
        // old neutered cross-origin Referer header — see POST /api/analytics/pageview).
        await t.none('ALTER TABLE web_analytics ADD COLUMN IF NOT EXISTS utm_source TEXT');
        await t.none('ALTER TABLE web_analytics ADD COLUMN IF NOT EXISTS utm_medium TEXT');
        await t.none('ALTER TABLE web_analytics ADD COLUMN IF NOT EXISTS utm_campaign TEXT');
        // File Backup incremental support (2026-07-22) — 'full'|'incremental' for kind='backup'
        // rows. Originally added via the unlocked top-level getDb().exec(...).catch() pattern used
        // elsewhere in this file for SQLite/legacy retrofits — found live to silently never apply
        // on Postgres (column still missing after multiple tracker redeploys, no error ever
        // logged; root cause not fully isolated, plausibly the 3-web-replica-plus-worker concurrent
        // unlocked ALTER race this advisory-locked block exists specifically to avoid — see its own
        // doc comment above). Moved here to use the same pg_advisory_xact_lock-serialized,
        // proven-reliable path every other Postgres column addition in this file already uses.
        await t.none('ALTER TABLE file_backup_runs ADD COLUMN IF NOT EXISTS backup_kind TEXT');
      });
      // Multi-replica: do NOT globally zero presence on boot — every replica restart would
      // clobber devices still connected to the OTHER replicas (false-offline). Redis
      // 'online_devices' is the cross-replica source of truth; the column is event-maintained.
      if (!redisEnabled) await getDb().exec('UPDATE devices SET online=0');

      const upsertEnvUser = getDb().prepare(
        'INSERT INTO users (username,password_hash,role,permissions,created_at,pw_scheme,auth_salt) VALUES (?,?,?,?,?,?,?) ON CONFLICT(username) DO NOTHING'
      );
      // Seed env accounts already in the prehash scheme (the plaintext is server-side by definition
      // here — it comes from our own env), so their rows never need the login-time upgrade.
      const seedCreds = (pass) => { const salt = newAuthSalt(); return { hash: bcrypt.hashSync(computeAuthPrehashSync(pass, salt), 10), salt }; };
      const adminSeed = seedCreds(ADMIN_PASS);
      const ins = await upsertEnvUser.run(ADMIN_USER, adminSeed.hash, 'admin', '{}', Date.now(), AUTH_SCHEME_PREHASH, adminSeed.salt);
      if (ins.changes) log('info', `Bootstrapped admin user: ${ADMIN_USER}`);

      const PERM_KEYS = ['location','photos','audio','network','files','stream','commands'];
      for (const entry of (process.env.USERS || '').split('|').map(s => s.trim()).filter(Boolean)) {
        const [uname, upass, urole = 'user', uperms = ''] = entry.split(':');
        if (!uname || !upass) continue;
        const permsObj = {};
        if (urole !== 'admin') {
          const allowed = new Set(uperms.split(',').map(s => s.trim()));
          PERM_KEYS.forEach(k => { permsObj[k] = allowed.has(k); });
        }
        const s = seedCreds(upass);
        const res = await upsertEnvUser.run(uname, s.hash, urole, JSON.stringify(permsObj), Date.now(), AUTH_SCHEME_PREHASH, s.salt);
        if (res.changes) log('info', `Bootstrapped user from USERS env: ${uname} (${urole})`);
      }

      if (!(await getDb().prepare("SELECT 1 FROM settings WHERE key='approval_tpl_reset_v2'").get())) {
        await getDb().prepare("DELETE FROM settings WHERE key='email_tpl_approval'").run();
        await getDb().prepare("INSERT INTO settings (key,value) VALUES ('approval_tpl_reset_v2','1') ON CONFLICT(key) DO UPDATE SET value=excluded.value").run();
      }

      // SECURITY (2026-10-13): 128-bit enrollment token (was 32-bit `randomBytes(4)`); matches
      // routes/register.js. This backfills tokens for users missing one, so it must use the same
      // unguessable entropy — 2^32 is brute-forceable against the pre-auth get-token surface.
      const genTok = () => crypto.randomBytes(16).toString('hex').toUpperCase();
      const missing = await getDb().prepare("SELECT id FROM users WHERE enrollment_token IS NULL OR enrollment_token=''").all();
      const setTok  = getDb().prepare("UPDATE users SET enrollment_token=? WHERE id=?");
      for (const u of missing) {
        let tok; do { tok = genTok(); } while (await getDb().prepare("SELECT id FROM users WHERE enrollment_token=?").get(tok));
        await setTok.run(tok, u.id);
      }
      // ── Backfill orphaned audit_result from alert_auto_audits (silent-catch bug fix, 2026-08-13)
      try {
        const pgOrphans = await getDb().prepare(
          `SELECT ua.id, aa.ai_analysis FROM user_alerts ua
           JOIN alert_auto_audits aa ON aa.alert_id = ua.id
           WHERE aa.status = 'completed' AND ua.audit_result IS NULL`
        ).all();
        if (pgOrphans.length) {
          const pgUpd = getDb().prepare('UPDATE user_alerts SET audit_result=? WHERE id=?');
          for (const r of pgOrphans) { await pgUpd.run(r.ai_analysis, r.id); }
          log('info', `Backfilled audit_result for ${pgOrphans.length} orphaned alert(s) (PG)`);
        }
      } catch (e) { log('warn', 'PG audit_result backfill failed (non-fatal)', { err: e.message }); }

      log('info', 'Postgres schema applied + bootstrap complete');
    }
  } catch (e) {
    log('error', 'bootstrapDb failed', { error: e.message });
    process.exit(1);
  }
  // Persist the session generation before accepting requests so sessions created on
  // this boot carry the same stamp as any earlier boot.
  await _loadOrInitServerGeneration();
  _resolveDbReady();
}

return { bootstrapDb };

};
