// helpers/apk-build-variants.js — variant-aware OTA build resolution.
//
// A HELPER module, not a route module: it registers nothing. Consumers:
// buildVariant (L3817) calls variantFromFilename at request time; the
// selectBuildForDevice body (runtime) and the apk-* route wirings consume the
// rest from BELOW the block.
//
//   variantFromFilename        export   filename -> variant tag
//   getActiveBuildsMap         private  per-variant pinned build map
//   setActiveBuildsMap         export   persist the map
//   getActiveBuildForVariant   export   pinned-or-newest build for a variant
//   setActiveBuildForVariant   export   pin a build for a variant
//
// IN-PLACE splice at the block position (X = L4300, comment absorbed from
// L4299). Resolution (A): the only consumer above the block is a call inside
// buildVariant's arrow body (runtime, long after this wiring line) — no
// load-time ctx capture references any member above the block.
//
// Stable deps by value: buildVariant (const arrow L3817), getApkBuilds
// (hoisted function L4251). db travels as the LIVE getter `getDb: () => db`
// (LIVE_READS pair; reads are rewritten to `getDb().prepare`).
//
// No relative require to rebase: the block contains none (measured, not assumed).

module.exports = ({ buildVariant, getApkBuilds, getDb }) => {

// Filename → variant, for tagging uploads and back-filling older builds.
function variantFromFilename(name = '') {
  if (/-stallion-/i.test(name))  return 'stallion';
  if (/-tegu-/i.test(name))      return 'tegu';
  if (/-tangorpro-/i.test(name)) return 'tangorpro';
  if (/-stock-/i.test(name))     return 'stock';
  return 'raven';   // the plain SentinelMDM-<ver>.apk is the raven/GOS platform build
}

// Active build PER variant: { raven, stallion, tegu, stock } → buildId. Falls back to the NEWEST build of
// a variant when none is explicitly pinned, so a fresh upload is dispatch-ready immediately.
async function getActiveBuildsMap() {
  const row = (await getDb().prepare("SELECT value FROM settings WHERE key='apk_active_builds'").get());
  if (!row) return {};
  try { return JSON.parse(row.value) || {}; } catch { return {}; }
}
async function setActiveBuildsMap(map) {
  (await getDb().prepare("INSERT INTO settings (key,value) VALUES ('apk_active_builds',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(JSON.stringify(map)));
}
async function getActiveBuildForVariant(variant) {
  const ofVariant = (await getApkBuilds()).filter(b => buildVariant(b) === variant);
  if (!ofVariant.length) return null;
  const pinnedId = (await getActiveBuildsMap())[variant];
  return ofVariant.find(b => b.id === pinnedId)
      || ofVariant.sort((a, b) => (b.uploaded_at || 0) - (a.uploaded_at || 0))[0];
}
async function setActiveBuildForVariant(variant, id) {
  const map = (await getActiveBuildsMap());
  map[variant] = id;
  (await setActiveBuildsMap(map));
}

return { getActiveBuildForVariant, setActiveBuildForVariant, setActiveBuildsMap, variantFromFilename };

};
