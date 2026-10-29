// helpers/asset-ver.js — auto cache-bust asset version.
//
// A HELPER module, not a route module: it registers nothing.
//
//   assetVer   export   content-hash cache-bust for static assets
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 3 deps: crypto (binding L15), fs (binding L14), path (binding L13).  The call must sit at or after L15; the earliest consumer of
// the export is L3169, so at or before L3168.  L3158 satisfies both.
//
// relative requires: none

module.exports = ({ crypto, fs, path }) => {
// Auto cache-bust: stamp the app.js/style.css URLs with a content hash so every code change is
// delivered to browsers & PWAs without a manual ?v= bump (root cause of the recurring "dashboard
// still shows old UI after deploy" bug — a stale ?v never changed the URL, so SW/HTTP caches served
// old app.js forever). The hash changes iff the file content changes; stable for a given image.
const assetVer = (rel) => {
  try { return crypto.createHash('sha1').update(fs.readFileSync(path.join(__dirname, '..', 'public', rel))).digest('hex').slice(0, 10); }
  catch { return String(Date.now()); }
};

  return {
    assetVer,
  };
};