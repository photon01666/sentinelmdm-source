// helpers/apk-inbox-scan.js - the R2 incoming-APK inbox scan: find .apk files parked under
// `apk/incoming/`, dedupe by sha256, and import new ones into the apk-builds list.
//
// A HELPER module, not a route module: it registers nothing.
//
//   scanIncomingApks   export   one inbox pass: import new APKs into the builds list
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 10 of the 15 deps are `function` declarations and hoist (log L447, r2Get L60, r2Put L55,
// r2Del L76, r2List L81, getApkBuilds L6308, saveApkBuilds L6313, getActiveBuildId L6316,
// setActiveBuildId L6320, variantFromFilename L6357). The lowest non-hoisted binding is
// `randomUUID` (L16) but the LAST non-hoisted dep to initialise is `INCOMING_APK_PREFIX`
// at L6416 — so the call must sit at or after L6417; the earliest consumer of the export
// is L6512, so at or before L6511. L6417 satisfies both.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ INCOMING_APK_PREFIX, apkBuildR2Key, crypto, getActiveBuildId, getApkBuilds, kv, log, r2, r2Del, r2Get, r2List, r2Put, randomUUID, saveApkBuilds, setActiveBuildId, variantFromFilename }) => {
async function scanIncomingApks({ trigger = 'auto' } = {}) {
  if (!r2) return { imported: [], skipped: 0, reason: 'r2-unconfigured' };
  // One importer at a time across all replicas (lock auto-expires so a crash can't wedge it).
  if (!(await kv.setNX('apk:incoming:scan', 120))) return { imported: [], skipped: 0, reason: 'locked' };
  const imported = [];
  let skipped = 0;
  try {
    const keys = (await r2List(INCOMING_APK_PREFIX)).filter(k => /\.apk$/i.test(k));
    if (!keys.length) return { imported, skipped };
    const builds = (await getApkBuilds());
    const haveHashes = new Set(builds.map(b => b.sha256).filter(Boolean));
    for (const key of keys) {
      try {
        const name = key.slice(INCOMING_APK_PREFIX.length).replace(/[^a-zA-Z0-9._-]/g, '_');
        if (!name) continue;
        const buf = (await r2Get(key));
        if (!buf || !buf.length) { await r2Del(key).catch(() => {}); continue; }  // drop empties
        const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
        if (haveHashes.has(sha256)) { await r2Del(key).catch(() => {}); skipped++; continue; } // already hosted
        const verMatch = name.match(/(\d+\.\d+\.\d+(?:\.\d+)?)/);
        const version  = verMatch ? verMatch[1] : null;
        const variant  = variantFromFilename(name);
        const id       = randomUUID();
        const r2Key    = apkBuildR2Key(id);
        await r2Put(r2Key, buf);            // move: copy to the canonical builds key…
        await r2Del(key).catch(() => {});   // …then remove the inbox copy
        const build = { id, name, version, size: buf.length, label: null, variant,
                        sha256, source: 'incoming', uploaded_at: Date.now(), r2Key };
        builds.push(build);
        haveHashes.add(sha256);
        imported.push(build);
        log('info', 'APK auto-imported from R2 inbox', { id, name, version, variant, trigger });
      } catch (e) { log('error', 'APK inbox import failed', { key, err: e.message }); }
    }
    if (imported.length) {
      (await saveApkBuilds(builds));
      if (!(await getActiveBuildId())) (await setActiveBuildId(imported[0].id)); // legacy single-active seed
    }
    return { imported, skipped };
  } finally { await kv.del('apk:incoming:scan').catch(() => {}); }
}

  return {
    scanIncomingApks,
  };
};
