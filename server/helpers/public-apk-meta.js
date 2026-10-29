// helpers/public-apk-meta.js — public APK metadata storage.
//
// A HELPER module, not a route module: it registers nothing.
//
//   getPublicApkMeta, savePublicApkMeta   members
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: db (binding L646).  The call must sit at or after L647; the earliest consumer of
// the export is L3056, so at or before L3055.  L3047 satisfies both.
//
// relative requires: none

module.exports = ({ db }) => {
async function getPublicApkMeta() {
  const row = (await db.prepare("SELECT value FROM settings WHERE key='public_apk_meta'").get());
  if (!row) return null;
  try { return JSON.parse(row.value); } catch { return null; }
}
async function savePublicApkMeta(meta) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES ('public_apk_meta',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(JSON.stringify(meta)));
}

  return {
    getPublicApkMeta,
    savePublicApkMeta,
  };
};