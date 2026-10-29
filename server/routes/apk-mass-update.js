module.exports = ({ app, APK_UPDATE_PIN, APK_VARIANTS, APK_VARIANT_LABEL, SIGNER_TO_VARIANT, buildVariant, connectedSockets, db, decryptText, deviceVariant, emitToDevice, getActiveApkBuild, getActiveBuildForVariant, getApkBuildById, getApkBuilds, isDeviceOnline, kv, log, mintApkToken, redisEnabled, requireAdmin, requireUnlocked, selectBuildForDevice }) => {
// ── Mass device update ────────────────────────────────────────────────────

// Windows SentinelRemoteAssist devices have no APK/app_version concept at all — without this
// filter they leaked into this panel with meaningless "target APK version" arrows (their
// deviceVariant() falls through to 'stock' since apk_signer/model/os_build are all null), got
// counted toward pendingCount/totalDevices, and a bare "Update All" click would dispatch a bogus
// Android update_app command to them. Windows agent updates are a separate feature/panel — see
// GET /api/admin/remote-assist-updates. Same filter shape as the OS-status endpoint (~line 14988).
const ANDROID_ONLY_DEVICES = "(platform='android' OR platform IS NULL)";
app.get('/api/admin/mass-update', requireUnlocked, requireAdmin, async (req, res) => {
  const builds  = (await getApkBuilds());
  // Demo devices (is_demo=1) are synthetic sample data with no real APK to update — exclude them
  // everywhere in this panel, same as the is_demo admin-fleet-view exclusion in GET /api/devices.
  const pending = (await db.prepare(`SELECT COUNT(*) as c FROM devices WHERE pending_update=1 AND COALESCE(is_demo,0)=0 AND ${ANDROID_ONLY_DEVICES}`).get());
  const total   = (await db.prepare(`SELECT COUNT(*) as c FROM devices WHERE COALESCE(is_demo,0)=0 AND ${ANDROID_ONLY_DEVICES}`).get());
  const onlineSet = redisEnabled ? new Set(await kv.smembers('online_devices')) : new Set(connectedSockets.keys());
  // Active build per variant (what each variant's devices would receive).
  const activeByVariant = {};
  for (const v of APK_VARIANTS) {
    const b = (await getActiveBuildForVariant(v));
    activeByVariant[v] = b ? { id: b.id, name: b.name, version: b.version } : null;
  }
  const rows = (await db.prepare(`SELECT id, name, app_version, apk_signer, model, os_build, pending_update, online FROM devices WHERE COALESCE(is_demo,0)=0 AND ${ANDROID_ONLY_DEVICES} ORDER BY name`).all());
  const variantCounts = Object.fromEntries(APK_VARIANTS.map(v => [v, 0]));
  const devs = rows.map(d => {
    const variant = deviceVariant({ apk_signer: d.apk_signer, model: decryptText(d.model), os_build: d.os_build });
    variantCounts[variant] = (variantCounts[variant] || 0) + 1;
    const target = activeByVariant[variant];
    return {
      id:            d.id,
      name:          decryptText(d.name),
      appVersion:    d.app_version || null,
      variant,
      bySigner:      !!(d.apk_signer && SIGNER_TO_VARIANT[(d.apk_signer || '').toLowerCase()]),
      targetVersion: target?.version || null,
      hasBuild:      !!target,
      online:        onlineSet ? onlineSet.has(d.id) : d.online === 1,
      pending:       d.pending_update === 1,
    };
  });
  const legacyActive = (await getActiveApkBuild());
  res.json({
    apkAvailable:  APK_VARIANTS.some(v => activeByVariant[v]),
    builds,
    variants:      APK_VARIANTS,
    variantLabels: APK_VARIANT_LABEL,
    activeByVariant,
    variantCounts,
    // legacy fields (kept so an un-updated UI still renders)
    meta:         legacyActive ? { name: legacyActive.name, version: legacyActive.version, size: legacyActive.size } : null,
    apkVersion:   legacyActive?.version || null,
    activeId:     legacyActive?.id || null,
    pendingCount: pending.c,
    totalDevices: total.c,
    devices:      devs,
  });
});

app.post('/api/admin/mass-update', requireUnlocked, requireAdmin, async (req, res) => {
  const { pin, buildId } = req.body || {};
  if (!APK_UPDATE_PIN || pin !== APK_UPDATE_PIN) return res.status(403).json({ error: 'Invalid PIN' });
  // Optional: force a SPECIFIC build — then ONLY that build's-variant devices are eligible.
  // No buildId (the normal case) → each device gets ITS variant's active build.
  const forced = buildId ? (await getApkBuildById(buildId)) : null;
  if (buildId && !forced) return res.status(404).json({ error: 'Build not found' });
  const forcedVariant = forced ? buildVariant(forced) : null;

  // Demo devices (is_demo=1) are synthetic sample data — never queue/dispatch a real APK to them.
  // Windows RA devices are excluded too — see ANDROID_ONLY_DEVICES's doc comment above.
  const allDevices = (await db.prepare(`SELECT id, app_version, apk_signer, model, os_build FROM devices WHERE COALESCE(is_demo,0)=0 AND ${ANDROID_ONLY_DEVICES}`).all());
  let sent = 0, skipped = 0, noBuild = 0;
  const perVariant = Object.fromEntries(APK_VARIANTS.map(v => [v, 0]));

  // Mark eligible devices pending; dispatch the CORRECT variant build immediately to any online.
  for (const dev of allDevices) {
    const variant = deviceVariant({ apk_signer: dev.apk_signer, model: decryptText(dev.model), os_build: dev.os_build });
    if (forcedVariant && variant !== forcedVariant) { skipped++; continue; }      // forced build isn't for this variant
    const build = forced || (await getActiveBuildForVariant(variant));
    if (!build) { noBuild++; continue; }                                          // no hosted build for this variant
    if (build.version && dev.app_version === build.version) { skipped++; continue; }  // already on target
    perVariant[variant] = (perVariant[variant] || 0) + 1;
    if (await isDeviceOnline(dev.id)) {
      emitToDevice(dev.id, 'command', { command: 'update_app', token: mintApkToken(build, 10 * 60 * 1000) });
      (await db.prepare('UPDATE devices SET pending_update=0 WHERE id=?').run(dev.id));
      sent++;
    } else {
      // Queue — on reconnect, selectBuildForDevice() re-resolves the device's variant build.
      (await db.prepare('UPDATE devices SET pending_update=1 WHERE id=?').run(dev.id));
    }
  }

  const queued = (await db.prepare(`SELECT COUNT(*) as c FROM devices WHERE pending_update=1 AND COALESCE(is_demo,0)=0 AND ${ANDROID_ONLY_DEVICES}`).get()).c;
  log('info', 'Mass APK update triggered (per-variant)', { forced: forced?.name || null, sentNow: sent, queued, skipped, noBuild, perVariant });
  res.json({ ok: true, sentNow: sent, queued, skipped, noBuild, perVariant, forced: forced?.name || null });
});

app.delete('/api/admin/mass-update', requireUnlocked, requireAdmin, async (req, res) => {
  (await db.prepare('UPDATE devices SET pending_update=0').run());
  log('info', 'Mass APK update queue cleared');
  res.json({ ok: true });
});

// Single-device APK update (dispatches a hosted build to one device by ID).
app.post('/api/devices/:id/update-apk', requireUnlocked, requireAdmin, async (req, res) => {
  const { pin, buildId } = req.body || {};
  if (!APK_UPDATE_PIN || pin !== APK_UPDATE_PIN) return res.status(403).json({ error: 'Invalid PIN' });
  // Explicit buildId wins (admin override); otherwise pick this device's matching variant build.
  let build = buildId ? (await getApkBuildById(buildId)) : null;
  if (!build) {
    const d = (await db.prepare('SELECT apk_signer, model, os_build FROM devices WHERE id=?').get(req.params.id));
    build = d ? (await selectBuildForDevice({ apk_signer: d.apk_signer, model: decryptText(d.model), os_build: d.os_build })) : null;
  }
  if (!build) return res.status(400).json({ error: "No APK build available for this device's variant" });
  if (!(await isDeviceOnline(req.params.id))) {
    // Device offline — queue it (reconnect dispatches the then-active build).
    (await db.prepare('UPDATE devices SET pending_update=1 WHERE id=?').run(req.params.id));
    log('info', 'Single device APK update queued (offline)', { deviceId: req.params.id });
    return res.json({ ok: true, queued: true });
  }
  emitToDevice(req.params.id, 'command', { command: 'update_app', token: mintApkToken(build, 10 * 60 * 1000) });
  log('info', 'Single device APK update dispatched', { deviceId: req.params.id, build: build.name });
  res.json({ ok: true, queued: false });
});

};
