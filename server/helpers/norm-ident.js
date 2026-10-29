// helpers/norm-ident.js — canonical identity normalisation (trim + lower-case).
//
// A HELPER module, not a route module: it registers nothing and has NO ctx deps.
// Hand-built from the arrow-const at L2264 (the plan's scanner cannot see
// arrow-const clusters). Consumers: check-trial-lineage-abuse / device-lock-state
// / device-bind wirings, user-management + account-security routes — all BELOW
// the wiring line. The device-signature wiring's `getNormIdent` wrapper is lazy.
//
//   normIdent   export   (s || '').toString().trim().toLowerCase()
//
// No relative require to rebase.

module.exports = () => {

const normIdent = s => (s || '').toString().trim().toLowerCase();

return { normIdent };

};
