module.exports = ({ app, CLIENT_APK_R2_KEY, GetObjectCommand, R2_BUCKET, getClientApkMeta, r2 }) => {
app.get('/api/update/apk/client/meta', async (req, res) => {
  const meta = (await getClientApkMeta());
  if (!meta) return res.json({ available: false });
  res.json({ available: true, ...meta });
});
app.get('/api/update/apk/client', async (req, res) => {
  const meta = (await getClientApkMeta());
  if (!meta) return res.status(404).json({ error: 'No client APK uploaded' });
  try {
    const obj = await r2.send(new GetObjectCommand({ Bucket: R2_BUCKET, Key: CLIENT_APK_R2_KEY }));
    res.setHeader('Content-Disposition', `attachment; filename="${meta.name || 'SentinelClient.apk'}"`);
    res.setHeader('Content-Type', 'application/vnd.android.package-archive');
    if (meta.size) res.setHeader('Content-Length', meta.size);
    (/** @type {any} */ (obj.Body)).pipe(res);
  } catch (e) { res.status(500).json({ error: 'Failed to fetch APK from storage' }); }
});
};
