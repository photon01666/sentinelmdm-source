// helpers/apk-build-store.js — multi-build APK hosting store + download-token mint.
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// apk-inbox-scan wiring, apk-build-upload / apk-builds / apk-mass-update route
// wirings, and the device-commands route wiring (getApkBuildById — eager, L2871).
//
//   apkBuildR2Key      export   id -> R2 object key
//   getApkBuilds       export   read the build list (settings JSON)
//   saveApkBuilds      export   persist the build list
//   getActiveBuildId   export   read the pinned active build id
//   setActiveBuildId   export   persist the pinned active build id
//   getApkBuildById    export   build by id (or null)
//   getActiveApkBuild  export   pinned-or-first active build
//   mintApkToken       export   one-time download token (Redis TTL)
//
// Wiring RELOCATED into [L440, L2086] (the run's own position L3481 is BELOW
// its earliest eager consumer — the getActiveApkBuild ctx capture at L2087).
// Placed just above L2087. Deps: db via the LIVE getter `getDb: () => db`
// (reads rewritten to `getDb().…`), kv (L21), randomUUID (L16) — all stable.
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ getDb, kv, randomUUID }) => {

// Multi-build APK hosting: any number of agent APKs can be hosted; one is marked
// "active" and that is what every push path (mass / per-device / offline-reconnect /
// update_app command) dispatches, unless a specific buildId is requested.
const apkBuildR2Key = (id) => `apk/builds/${id}.apk`;
async function getApkBuilds() {
  const row = (await getDb().prepare("SELECT value FROM settings WHERE key='apk_builds'").get());
  if (!row) return [];
  try { return JSON.parse(row.value) || []; } catch { return []; }
}
async function saveApkBuilds(arr) {
  (await getDb().prepare("INSERT INTO settings (key,value) VALUES ('apk_builds',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(JSON.stringify(arr)));
}
async function getActiveBuildId() {
  const row = (await getDb().prepare("SELECT value FROM settings WHERE key='apk_active_build'").get());
  return row ? row.value : null;
}
async function setActiveBuildId(id) {
  (await getDb().prepare("INSERT INTO settings (key,value) VALUES ('apk_active_build',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(id));
}
async function getApkBuildById(id) { return (await getApkBuilds()).find(b => b.id === id) || null; }
async function getActiveApkBuild() {
  const builds = (await getApkBuilds());
  if (!builds.length) return null;
  const activeId = (await getActiveBuildId());
  return builds.find(b => b.id === activeId) || builds[0];
}
// Mint a one-time download token bound to a specific build's R2 key.
function mintApkToken(build, ttlMs) {
  const token = randomUUID();
  // Fire-and-forget write to shared storage so any replica can validate the download.
  // The device can't redeem before this lands (it must receive the command first);
  // Redis TTL handles expiry. Returns synchronously so callers needn't await.
  kv.setJSON('apkdl:' + token, { r2Key: build.r2Key, name: build.name }, Math.ceil(ttlMs / 1000)).catch(() => {});
  return token;
}

return { apkBuildR2Key, getActiveApkBuild, getActiveBuildId, getApkBuildById, getApkBuilds, mintApkToken, saveApkBuilds, setActiveBuildId };

};
