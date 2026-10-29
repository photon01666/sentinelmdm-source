// helpers/client-apk-meta.js — client APK metadata storage.
//
// A HELPER module, not a route module: it registers nothing.
//
//   getClientApkMeta, saveClientApkMeta   members
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: db (binding L646).  The call must sit at or after L647; the earliest consumer of
// the export is L3062, so at or before L3061.  L3053 satisfies both.
//
// relative requires: none

module.exports = ({ db }) => {
async function getClientApkMeta() {
  const row = (await db.prepare("SELECT value FROM settings WHERE key='client_apk_meta'").get());
  if (!row) return null;
  try { return JSON.parse(row.value); } catch { return null; }
}
async function saveClientApkMeta(meta) {
  (await db.prepare("INSERT INTO settings (key,value) VALUES ('client_apk_meta',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(JSON.stringify(meta)));
}

  return {
    getClientApkMeta,
    saveClientApkMeta,
  };
};