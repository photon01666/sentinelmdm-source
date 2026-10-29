module.exports = ({ APK_VARIANTS, app, apkBuildR2Key, express, getApkBuilds, log, r2Put, randomUUID, requireAdmin, requireUnlocked, saveApkBuilds, setActiveBuildId, variantFromFilename }) => {
// Upload APK (admin only) — raw binary body, up to 150 MB. Appends a NEW build.
app.post('/api/update/apk', requireUnlocked, requireAdmin,
  express.raw({ type: 'application/octet-stream', limit: '150mb' }),
  async (req, res) => {
    if (!Buffer.isBuffer(req.body) || !req.body.length)
      return res.status(400).json({ error: 'No APK data received' });
    const name = String(req.headers['x-filename'] || 'sentinel.apk').replace(/[^a-zA-Z0-9._-]/g, '_');
    const size = req.body.length;
    const verMatch = name.match(/(\d+\.\d+\.\d+(?:\.\d+)?)/);
    const version  = verMatch ? verMatch[1] : null;
    const label    = String(req.headers['x-label'] || '').replace(/[^\w .\-]/g, '').slice(0, 40) || null;
    // Variant (raven/stallion/tegu/stock): explicit X-Variant header wins, else inferred from filename.
    const hdrVariant = String(req.headers['x-variant'] || '').toLowerCase();
    const variant    = APK_VARIANTS.includes(hdrVariant) ? hdrVariant : variantFromFilename(name);
    const id       = randomUUID();
    const r2Key    = apkBuildR2Key(id);
    try {
      await r2Put(r2Key, req.body);
      const builds = (await getApkBuilds());
      const build  = { id, name, version, size, label, variant, uploaded_at: Date.now(), r2Key };
      builds.push(build);
      (await saveApkBuilds(builds));
      if (builds.length === 1) (await setActiveBuildId(id));  // legacy single-active back-compat
      log('info', 'APK build uploaded', { id, name, size, version, label, variant });
      res.json({ ok: true, build });
    } catch (e) { res.status(500).json({ error: e.message }); }
  }
);
};
