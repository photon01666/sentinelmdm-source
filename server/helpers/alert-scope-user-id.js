// helpers/alert-scope-user-id.js — resolve alert scope user ID.
//
// A HELPER module, not a route module: it registers nothing.
//
//   alertScopeUserId   export   resolve the effective user ID for alert scoping
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 0 deps.  The call must sit at or after L1; the earliest consumer of
// the export is L7006, so at or before L7005.  L4414 satisfies both.
//
// relative requires: none

module.exports = () => {
function alertScopeUserId(req) {
  return (req.session.account_type === 'business_sub' && req.session.parent_owner_id)
    ? req.session.parent_owner_id
    : req.session.userId;
}

  return {
    alertScopeUserId,
  };
};