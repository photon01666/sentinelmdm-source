// helpers/phish-never-domain.js — phish never-domain check.
//
// A HELPER module, not a route module: it registers nothing.
//
//   phishNeverDomain   export   check if a domain is in the phish never-list
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 1 dep: _phishNeverDomains (binding L6582).  The call must sit at or after L6583; the earliest consumer of
// the export is L6622, so at or before L6621.  L6588 satisfies both.
//
// relative requires: none

module.exports = ({ _phishNeverDomains }) => {
function phishNeverDomain(domain) {
  const d = String(domain || '').trim().toLowerCase().replace(/\.+$/, '');
  if (!d || !d.includes('.')) return false;
  let at = d;
  for (;;) {
    if (_phishNeverDomains.has(at)) return true;
    const i = at.indexOf('.');
    if (i < 0) break;
    at = at.slice(i + 1);
  }
  return false;
}

  return {
    phishNeverDomain,
  };
};