module.exports = ({ app, GetObjectCommand, PUBLIC_APK_R2_KEY, R2_BUCKET, getPublicApkMeta, r2 }) => {
app.get('/api/update/apk/public/meta', async (req, res) => {
  const meta = (await getPublicApkMeta());
  if (!meta) return res.json({ available: false });
  res.json({ available: true, ...meta });
});
app.get('/api/update/apk/public', async (req, res) => {
  const meta = (await getPublicApkMeta());
  if (!meta) return res.status(404).json({ error: 'No public APK uploaded' });
  try {
    const obj = await r2.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: PUBLIC_APK_R2_KEY }));
    res.setHeader('Content-Disposition', `attachment; filename="${meta.name || 'SentinelMDM-self-install.apk'}"`);
    res.setHeader('Content-Type', 'application/vnd.android.package-archive');
    if (meta.size) res.setHeader('Content-Length', meta.size);
    (/** @type {any} */ (obj.Body)).pipe(res);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch APK from storage' }); }
});
};
