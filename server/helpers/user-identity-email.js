// helpers/user-identity-email.js — lineage identity for a public user row.
//
// A HELPER module, not a route module: it registers nothing. Consumers: the
// device-bind wiring (L2275) and the device-ownership-lifecycle route wiring
// (L2305) — both below the wiring line.
//
//   userIdentityEmail   export   normIdent(email) || normIdent(username) || null
//
// normIdent is a below-defined CALLED dep (const at L2264... — actually above
// this line after the leftover extraction, but it is passed via the sanctioned
// LIVE_CALLS wrapper form anyway so the call sites canonicalize):
//   getNormIdent: (s) => normIdent(s)
//
// No relative require to rebase.

module.exports = ({ getNormIdent }) => {

// Lineage identity for a public user = normalized email, falling back to username.
function userIdentityEmail(userRow) {
  if (!userRow) return null;
  return getNormIdent(userRow.email) || getNormIdent(userRow.username) || null;
}

return { userIdentityEmail };

};
