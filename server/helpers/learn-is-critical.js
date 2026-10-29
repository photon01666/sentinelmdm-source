// helpers/learn-is-critical.js — check if a learn rule is critical.
//
// A HELPER module, not a route module: it registers nothing.
//
//   learnIsCritical   export   check if a category:rule pair is critical
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: LEARN_CRITICAL (binding L3761).  The call must sit at or after L3762; the earliest consumer of
// the export is L3829, so at or before L3828.  L3786 satisfies both.
//
// relative requires: none

module.exports = ({ LEARN_CRITICAL }) => {
function learnIsCritical(category, rule) {
  return !!rule && LEARN_CRITICAL.has(`${category}:${rule}`);
}

  return {
    learnIsCritical,
  };
};