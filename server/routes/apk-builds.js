// routes/apk-builds.js - APK build management: list builds + active-build-per-variant,
// activate/scan/delete builds, legacy meta endpoint, and admin upload/delete of the
// public self-install APK + SentinelClient APK. Extracted VERBATIM from server.js
// L12890-L13013 (10 routes).

module.exports = ({ app, APK_VARIANTS, APK_VARIANT_LABEL, CLIENT_APK_R2_KEY, DeleteObjectCommand, PUBLIC_APK_R2_KEY, PutObjectCommand, R2_BUCKET, buildVariant, db, express, getActiveApkBuild, getActiveBuildForVariant, getActiveBuildId, getApkBuildById, getApkBuilds, log, r2, r2Del, requireAdmin, requireAuth, requireUnlocked, saveApkBuilds, saveClientApkMeta, savePublicApkMeta, scanIncomingApks, setActiveBuildForVariant, setActiveBuildId }) => {
// List all hosted builds + the active build PER variant (raven/stallion/tegu/stock).
app.get('/api/update/apks', requireUnlocked, requireAuth, async (req, res) => {
  const builds = (await getApkBuilds());
  const activeByVariant = {};
  for (const v of APK_VARIANTS) activeByVariant[v] = (await getActiveBuildForVariant(v))?.id || null;
  res.json({
    builds,
    activeId: (await getActiveApkBuild())?.id || null,   // legacy field (kept for older UI)
    activeByVariant,
    variants: APK_VARIANTS,
    variantLabels: APK_VARIANT_LABEL,
  });
});

// Set the active build FOR ITS VARIANT (the build that variant's devices get on a push).
app.post('/api/update/apk/active', requireUnlocked, requireAdmin, async (req, res) => {
  const { id } = req.body || {};
  const build = (await getApkBuildById(id));
  if (!build) return res.status(404).json({ error: 'Build not found' });
  const variant = buildVariant(build);
  (await setActiveBuildForVariant(variant, id));
  (await setActiveBuildId(id));   // keep legacy single-active in sync
  log('info', 'Active APK build set', { id, variant });
  res.json({ ok: true, activeId: id, variant });
});

// Manually trigger an R2-inbox scan (admin) — imports any APKs dropped into apk/incoming/ now,
// instead of waiting for the worker's 5-minute timer. Returns the builds it imported.
app.post('/api/update/apk/scan', requireUnlocked, requireAdmin, async (req, res) => {
  try {
    const r = (await scanIncomingApks({ trigger: 'manual' }));
    res.json({ ok: true, importedCount: r.imported.length, skipped: r.skipped || 0,
               reason: r.reason || null, imported: r.imported.map(b => ({ name: b.name, variant: b.variant, version: b.version })) });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Legacy metadata endpoint — returns the ACTIVE build so older UI calls keep working.
app.get('/api/update/apk/meta', requireUnlocked, requireAuth, async (req, res) => {
  const b = (await getActiveApkBuild());
  if (!b) return res.json({ available: false });
  res.json({ available: true, id: b.id, name: b.name, version: b.version,
             size: b.size, uploaded_at: b.uploaded_at, label: b.label });
});

// Delete a specific build by id (admin only).
app.delete('/api/update/apk/:id', requireUnlocked, requireAdmin, async (req, res) => {
  const build = (await getApkBuildById(req.params.id));
  if (!build) return res.status(404).json({ error: 'Build not found' });
  try {
    await r2Del(build.r2Key).catch(() => {});
    const remaining = (await getApkBuilds()).filter(b => b.id !== req.params.id);
    (await saveApkBuilds(remaining));
    if ((await getActiveBuildId()) === req.params.id) {
      if (remaining.length) (await setActiveBuildId(remaining[0].id));
      else (await db.prepare("DELETE FROM settings WHERE key='apk_active_build'").run());
    }
    log('info', 'APK build deleted', { id: req.params.id, name: build.name });
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// Back-compat: DELETE with no id removes the active build.
app.delete('/api/update/apk', requireUnlocked, requireAdmin, async (req, res) => {
  const b = (await getActiveApkBuild());
  if (!b) return res.json({ ok: true });
  try {
    await r2Del(b.r2Key).catch(() => {});
    const remaining = (await getApkBuilds()).filter(x => x.id !== b.id);
    (await saveApkBuilds(remaining));
    if (remaining.length) (await setActiveBuildId(remaining[0].id));
    else (await db.prepare("DELETE FROM settings WHERE key='apk_active_build'").run());
    res.json({ ok: true });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── Public (self-install) APK — admin upload / delete ────────────────────────
app.post('/api/admin/apk/public', requireUnlocked, requireAdmin,
  express.raw({ type: 'application/octet-stream', limit: '150mb' }),
  async (req, res) => {
    const name    = req.headers['x-apk-name']    || 'SentinelMDM-self-install.apk';
    const version = req.headers['x-apk-version'] || null;
    const size    = req.body.length;
    try {
      await r2.send(new PutObjectCommand({
        Bucket: R2_BUCKET, Key: PUBLIC_APK_R2_KEY,
        Body: req.body, ContentType: 'application/vnd.android.package-archive',
      }));
      const meta = { name, version, size, uploaded_at: Date.now() };
      (await savePublicApkMeta(meta));
      log('info', 'Public self-install APK uploaded', { name, version, size });
      res.json({ ok: true, meta });
    } catch (e) { res.status(500).json({ error: 'Upload failed: ' + e.message }); }
  }
);
app.delete('/api/admin/apk/public', requireUnlocked, requireAdmin, async (req, res) => {
  try { await r2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: PUBLIC_APK_R2_KEY })); } catch (_) {}
  (await db.prepare("DELETE FROM settings WHERE key='public_apk_meta'").run());
  res.json({ ok: true });
});

// ── SentinelClient APK — admin upload / delete ───────────────────────────────
app.post('/api/admin/apk/client', requireUnlocked, requireAdmin,
  express.raw({ type: 'application/octet-stream', limit: '150mb' }),
  async (req, res) => {
    const name    = req.headers['x-apk-name']    || 'SentinelClient.apk';
    const version = req.headers['x-apk-version'] || null;
    const size    = req.body.length;
    try {
      await r2.send(new PutObjectCommand({
        Bucket: R2_BUCKET, Key: CLIENT_APK_R2_KEY,
        Body: req.body, ContentType: 'application/vnd.android.package-archive',
      }));
      const meta = { name, version, size, uploaded_at: Date.now() };
      (await saveClientApkMeta(meta));
      log('info', 'SentinelClient APK uploaded', { name, version, size });
      res.json({ ok: true, meta });
    } catch (e) { res.status(500).json({ error: 'Upload failed: ' + e.message }); }
  }
);
app.delete('/api/admin/apk/client', requireUnlocked, requireAdmin, async (req, res) => {
  try { await r2.send(new DeleteObjectCommand({ Bucket: R2_BUCKET, Key: CLIENT_APK_R2_KEY })); } catch (_) {}
  (await db.prepare("DELETE FROM settings WHERE key='client_apk_meta'").run());
  res.json({ ok: true });
});
};
