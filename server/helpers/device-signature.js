// helpers/device-signature.js — device request authentication + schema migration.
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// sleep-check (L2261), license-trial-ping, preauth-assets route wirings (all
// below), the device-login/register paths, and runMigration callers — all at or
// below the wiring line.
//
//   verifyWithPublicKey        export   Ed25519/EC signature check (+/-60s window)
//   verifyDeviceSignature      export   lookup the device row, then verify
//   authenticateDeviceRequest  export   extract + verify a device request's sig
//   runMigration               export   schema/backfill migration pass
//
// IN-PLACE splice at the block position (X = L1746, comment absorbed from L1744).
// Mechanism: LIVE_CALLS wrappers for the two below-defined CALLED deps —
// `normIdent` (const L2719) and `sha256hex` (const L2525) are bound AFTER the
// block, so the wiring passes `getNormIdent: (s) => normIdent(s)` /
// `getSha256hex: (s) => sha256hex(s)` (lazy — called only inside the member
// bodies) and the call sites are rewritten to the wrapper form. All other deps
// are above the wiring line; the earliest eager consumer (sleep-check wiring
// L2261) sits below it.
//
// db travels as the LIVE getter `getDb: () => db` (reads rewritten to
// `getDb().…`); crypto (L15) is ctx-injected by value (scanner blind spot).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ ENC_MAGIC, PUBLIC_USER_DEFAULT_FEATURES, createDemoDeviceForUser, crypto, decryptText, encryptBuffer, encryptText, fs, getDb, getNormIdent, getSha256hex, log, notifyAdmin, path, stmts, uploadsDir }) => {

// Verify an Ed25519/EC device signature. Payload signed by device: "<deviceId>:<timestamp>"
// Timestamp must be within ±60 s of server time to prevent replay attacks.
function verifyWithPublicKey(pubKeyB64, deviceId, timestamp, signature) {
  try {
    const pubKey = crypto.createPublicKey({ key: Buffer.from(pubKeyB64, 'base64'), format: 'der', type: 'spki' });
    const verify = crypto.createVerify('SHA256');
    verify.update(`${deviceId}:${timestamp}`);
    return verify.verify(pubKey, Buffer.from(signature, 'base64'));
  } catch { return false; }
}

async function verifyDeviceSignature(deviceId, timestamp, signature) {
  const row = (await stmts.getDeviceKey.get(deviceId));
  if (!row?.public_key) return false;
  const ts = parseInt(timestamp);
  if (!ts || Math.abs(Date.now() - ts) > 60_000) return false;
  return verifyWithPublicKey(row.public_key, deviceId, timestamp, signature);
}

// Verify EC signature headers sent by enrolled devices.
// Used by HTTP-polled endpoints that devices call without a socket connection.
async function authenticateDeviceRequest(req) {
  const deviceId = req.headers['x-device-id'];
  const ts       = req.headers['x-device-timestamp'];
  const sig      = req.headers['x-device-signature'];
  if (deviceId && ts && sig) return (await verifyDeviceSignature(deviceId, ts, sig));
  return false;
}

// ── Encrypt any pre-existing plaintext data (called after unlock) ──────────
async function runMigration() {
  // ── Locations: add data column, encrypt existing rows, null out plaintext ──
  try { (await getDb().exec(`ALTER TABLE locations ADD COLUMN data TEXT`)); } catch (_) {}
  {
    // Fresh DBs create `locations` with only (id, device_id, data, timestamp) — no
    // legacy lat/lng/accuracy columns — so this SELECT throws "no such column: lat".
    // There is nothing to migrate on a fresh DB, so fall back to an empty set.
    let locRows = [];
    try { locRows = (await getDb().prepare(`SELECT id,lat,lng,accuracy FROM locations WHERE (data IS NULL OR data='') AND lat IS NOT NULL`).all()); } catch (_) {}
    if (locRows.length) {
      const upd = getDb().prepare(`UPDATE locations SET data=?, lat=NULL, lng=NULL, accuracy=NULL WHERE id=?`);
      (await getDb().transaction(async () => {
        for (const r of locRows)
          (await upd.run(encryptText(JSON.stringify({ lat: r.lat, lng: r.lng, accuracy: r.accuracy ?? 0 })), r.id));
      })());
      log('info', `Encrypted ${locRows.length} location row(s)`);
    }
  }
  // ── Devices: encrypt last_lat / last_lng ──
  {
    const devRows = (await getDb().prepare(`SELECT id,last_lat,last_lng FROM devices WHERE last_lat IS NOT NULL`).all());
    const toEnc = devRows.filter(d => !String(d.last_lat).startsWith('ENC:'));
    if (toEnc.length) {
      const upd = getDb().prepare(`UPDATE devices SET last_lat=?,last_lng=? WHERE id=?`);
      (await getDb().transaction(async () => {
        for (const d of toEnc)
          (await upd.run(encryptText(String(d.last_lat)), encryptText(String(d.last_lng)), d.id));
      })());
      log('info', `Encrypted last_lat/last_lng for ${toEnc.length} device(s)`);
    }
  }

  // ── Permanent-lock backfill: lock any device already owned by a public user, so the new
  // immutability rules cover the pre-existing fleet (not just newly-enrolled devices). Idempotent —
  // only fills NULL locked_identity_email; the lineage email is the current owner's identity. ──
  {
    let lockRows = [];
    try {
      lockRows = (await getDb().prepare(`
        SELECT d.id AS device_id, d.public_key, u.email, u.username
        FROM devices d JOIN users u ON d.owner_user_id = u.id
        WHERE u.account_type='public' AND (d.locked_identity_email IS NULL OR d.locked_identity_email='')
      `).all());
    } catch (_) {}
    if (lockRows.length) {
      (await getDb().transaction(async () => {
        for (const r of lockRows) {
          const ident = getNormIdent(r.email) || getNormIdent(r.username);
          if (!ident) continue;
          (await stmts.setDeviceLock.run(encryptText(ident), r.public_key ? getSha256hex(r.public_key) : null, r.device_id));
        }
      })());
      log('info', `Permanent-lock backfill applied to ${lockRows.length} public-user device(s)`);
    }
  }

  // ── Manual account-approval gate removed: auto-activate anyone still stuck in
  // pending_approval from before the switch, so nobody is left permanently locked out
  // now that the admin "Approve" form is gone. Same default-feature grant the old
  // approve action used to apply. Idempotent — no-ops once there's nothing pending. ──
  {
    let stuckRows = [];
    try {
      stuckRows = (await getDb().prepare(
        `SELECT id, username FROM users WHERE status='pending_approval' AND account_type='public'`
      ).all());
    } catch (_) {}
    if (stuckRows.length) {
      (await getDb().prepare("UPDATE users SET status='active', enabled_features=? WHERE status='pending_approval' AND account_type='public'")
        .run(encryptText(JSON.stringify(PUBLIC_USER_DEFAULT_FEATURES))));
      log('info', `Auto-activated ${stuckRows.length} public user(s) stuck in pending_approval`, { usernames: stuckRows.map(r => r.username) });
      notifyAdmin(`✅ Migration: auto-activated ${stuckRows.length} account(s) previously stuck awaiting manual approval (approval gate removed).`);
    }
  }

  // ── Demo device backfill: seed a sample device for every EXISTING active public user who has
  // never added a device of their own — new signups get one at registration (see
  // finishPublicRegistration()); this covers accounts created before the feature shipped. Only
  // users with ZERO devices qualify (someone who already has a real device doesn't need a demo).
  // Idempotent — createDemoDeviceForUser() no-ops once `demo-<id>` already exists. ──
  {
    let candidates = [];
    try {
      candidates = (await getDb().prepare(`
        SELECT id FROM users
        WHERE account_type='public' AND status='active'
          AND id NOT IN (SELECT owner_user_id FROM devices WHERE owner_user_id IS NOT NULL)
      `).all());
    } catch (_) {}
    if (candidates.length) {
      for (const u of candidates) {
        try { (await createDemoDeviceForUser(u.id)); }
        catch (e) { log('warn', 'Demo device backfill failed for user', { userId: u.id, err: e.message }); }
      }
      log('info', `Demo device backfill seeded ${candidates.length} account(s) with sample data`);
    }
  }

  // ── Backfill orphaned audit_result from alert_auto_audits (silent-catch bug fix, 2026-08-13)
  try {
    const sqlOrphans = getDb().prepare(
      `SELECT ua.id, aa.ai_analysis FROM user_alerts ua
       JOIN alert_auto_audits aa ON aa.alert_id = ua.id
       WHERE aa.status = 'completed' AND ua.audit_result IS NULL`
    ).all();
    if (sqlOrphans.length) {
      const sqlUpd = getDb().prepare('UPDATE user_alerts SET audit_result=? WHERE id=?');
      for (const r of sqlOrphans) { sqlUpd.run(r.ai_analysis, r.id); }
      log('info', `Backfilled audit_result for ${sqlOrphans.length} orphaned alert(s) (SQLite)`);
    }
  } catch (e) { log('warn', 'SQLite audit_result backfill failed (non-fatal)', { err: e.message }); }

  const dbTargets = [
    ['media',          getDb().prepare("SELECT id,data FROM media          WHERE data NOT LIKE 'ENC:%'"),
                       getDb().prepare('UPDATE media          SET data=? WHERE id=?')],
    ['network_events', getDb().prepare("SELECT id,data FROM network_events WHERE data NOT LIKE 'ENC:%'"),
                       getDb().prepare('UPDATE network_events SET data=? WHERE id=?')],
    ['call_logs',      getDb().prepare("SELECT id,data FROM call_logs      WHERE data NOT LIKE 'ENC:%'"),
                       getDb().prepare('UPDATE call_logs      SET data=? WHERE id=?')],
    ['sms_messages',   getDb().prepare("SELECT id,data FROM sms_messages   WHERE data NOT LIKE 'ENC:%'"),
                       getDb().prepare('UPDATE sms_messages   SET data=? WHERE id=?')],
    ['app_lists',      getDb().prepare("SELECT id,data FROM app_lists      WHERE data NOT LIKE 'ENC:%'"),
                       getDb().prepare('UPDATE app_lists      SET data=? WHERE id=?')],
    ['keylog_entries', getDb().prepare("SELECT id,data FROM keylog_entries WHERE data NOT LIKE 'ENC:%'"),
                       getDb().prepare('UPDATE keylog_entries SET data=? WHERE id=?')],
    ['screen_text_entries', getDb().prepare("SELECT id,data FROM screen_text_entries WHERE data NOT LIKE 'ENC:%'"),
                            getDb().prepare('UPDATE screen_text_entries SET data=? WHERE id=?')],
  ];
  let dbTotal = 0;
  for (const [name, sel, upd] of dbTargets) {
    const rows = sel.all();
    if (!rows.length) continue;
    (await getDb().transaction(async () => { for (const r of rows) (await upd.run(encryptText(r.data), r.id)); })());
    log('info', `Encrypted ${rows.length} existing row(s) in ${name}`);
    dbTotal += rows.length;
  }
  let filesMigrated = 0;
  try {
    for (const fname of fs.readdirSync(uploadsDir)) {
      const fPath = path.join(uploadsDir, fname);
      let buf; try { buf = fs.readFileSync(fPath); } catch { continue; }
      if (buf.length < 4 || !buf.slice(0, 4).equals(ENC_MAGIC)) {
        fs.writeFileSync(fPath, encryptBuffer(buf));
        filesMigrated++;
      }
    }
  } catch (e) { log('warn', 'Upload encryption migration error', { error: e.message }); }
  if (dbTotal || filesMigrated)
    log('info', 'Encryption migration complete', { dbRows: dbTotal, files: filesMigrated });

  // ── Devices: encrypt name, model, android_version ──
  {
    const devRows = (await getDb().prepare(`SELECT id,name,model,android_version FROM devices WHERE name IS NOT NULL AND name NOT LIKE 'ENC:%'`).all());
    if (devRows.length) {
      const upd = getDb().prepare(`UPDATE devices SET name=?,model=?,android_version=? WHERE id=?`);
      (await getDb().transaction(async () => {
        for (const d of devRows)
          (await upd.run(encryptText(d.name || ''), encryptText(d.model || ''), encryptText(d.android_version || ''), d.id));
      })());
      log('info', `Encrypted name/model/version for ${devRows.length} device(s)`);
    }
  }
  // ── Files: encrypt remote_path ──
  {
    const fileRows = (await getDb().prepare(`SELECT id,remote_path FROM files WHERE remote_path IS NOT NULL AND remote_path NOT LIKE 'ENC:%'`).all());
    if (fileRows.length) {
      const upd = getDb().prepare(`UPDATE files SET remote_path=? WHERE id=?`);
      (await getDb().transaction(async () => {
        for (const f of fileRows) (await upd.run(encryptText(f.remote_path), f.id));
      })());
      log('info', `Encrypted remote_path for ${fileRows.length} file(s)`);
    }
  }
  // ── Users: encrypt permissions JSON ──
  {
    const permRows = (await getDb().prepare(`SELECT id,permissions FROM users WHERE permissions NOT LIKE 'ENC:%'`).all());
    if (permRows.length) {
      const upd = getDb().prepare(`UPDATE users SET permissions=? WHERE id=?`);
      (await getDb().transaction(async () => {
        for (const r of permRows) (await upd.run(encryptText(r.permissions || '{}'), r.id));
      })());
      log('info', `Encrypted permissions for ${permRows.length} user(s)`);
    }
  }
  // ── Public users: ensure ALL features enabled for every active public user ──
  // Runs on every startup; skips only users who already have every feature set to true.
  // Catches users approved before the all-true default was introduced, or who only had
  // a partial backfill (e.g. audio/stream/files set but keylogs/schedules/timeline still false).
  {
    const ALL_FEATURE_KEYS = ['location','photos','audio','screenshots','stream','network',
      'files','calls','sms','apps','contacts','notifications','keylogs',
      'screentext','geofences','schedules','timeline','commands','connect','security',
      // ra_screenshots/edr/applocker/file_backup/s3_drive/bitlocker/boot_iso — see PUBLIC_USER_DEFAULT_FEATURES's
      // comment. Added here too so this startup backfill actually reaches already-active
      // accounts, not just future signups.
      'ra_screenshots','edr','applocker','file_backup','s3_drive','bitlocker','boot_iso'];
    const activePublic = (await getDb().prepare(
      `SELECT id, enabled_features FROM users WHERE account_type='public' AND status='active'`
    ).all());
    if (activePublic.length) {
      const upd = getDb().prepare('UPDATE users SET enabled_features=? WHERE id=?');
      let fixed = 0;
      (await getDb().transaction(async () => {
        for (const u of activePublic) {
          const existing = JSON.parse(decryptText(u.enabled_features || '{}') || '{}');
          if (ALL_FEATURE_KEYS.every(k => existing[k] === true)) continue;
          for (const k of ALL_FEATURE_KEYS) existing[k] = true;
          (await upd.run(encryptText(JSON.stringify(existing)), u.id));
          fixed++;
        }
      })());
      if (fixed) log('info', `Enabled all features for ${fixed} public user(s) (legacy default upgrade)`);
    }
  }
}

return { authenticateDeviceRequest, runMigration, verifyDeviceSignature, verifyWithPublicKey };

};
