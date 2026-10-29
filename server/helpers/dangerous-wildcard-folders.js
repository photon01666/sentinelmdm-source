// helpers/dangerous-wildcard-folders.js — dangerous wildcard folder detection.
//
// A HELPER module, not a route module: it registers nothing.
//
//   isDangerousWildcardFolder, stripDangerousWildcardFolders   members
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: DANGEROUS_WILDCARD_FOLDER_BASENAMES (binding L4108).  The call must sit at or after L4109; the earliest consumer of
// the export is L4121, so at or before L4120.  L4109 satisfies both.
//
// relative requires: none

module.exports = ({ DANGEROUS_WILDCARD_FOLDER_BASENAMES }) => {
function isDangerousWildcardFolder(pathGlob) {
  const p = String(pathGlob || '').replace(/\\*$/, '').replace(/\\+$/, '');
  const basename = p.slice(p.lastIndexOf('\\') + 1).trim().toLowerCase();
  return DANGEROUS_WILDCARD_FOLDER_BASENAMES.has(basename);
}
function stripDangerousWildcardFolders(allowedPaths) {
  const paths = Array.isArray(allowedPaths) ? allowedPaths : [];
  const rejected = paths.filter(p => typeof p === 'string' && isDangerousWildcardFolder(p));
  const kept = paths.filter(p => !(typeof p === 'string' && isDangerousWildcardFolder(p)));
  return { kept, rejected };
}

  return {
    isDangerousWildcardFolder,
    stripDangerousWildcardFolders,
  };
};