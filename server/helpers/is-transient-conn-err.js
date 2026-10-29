// helpers/is-transient-conn-err.js — check if an error is a transient connection error.
//
// A HELPER module, not a route module: it registers nothing.
//
//   _isTransientConnErr   export   detect transient DB/network errors
//
// ctx is available at this module's own position in server.js -- nothing had to move.
// 0 deps.  The call must sit at or after L1; the earliest consumer of
// the export is L792, so at or before L791.  L781 satisfies both.
//
// relative requires: none

module.exports = () => {
const _isTransientConnErr = (e) => {
  if (!e) return false;
  const code = String(e.code || '');
  if (/^(ETIMEDOUT|ECONNRESET|ECONNREFUSED|EPIPE|EHOSTUNREACH|ENETUNREACH|EAI_AGAIN|ENOTFOUND)$/.test(code)) return true;
  if (/^08|^57P0/.test(code)) return true;   // Postgres SQLSTATE: class 08 = connection, 57P0x = admin shutdown/recovery
  return /Connection terminated|terminating connection|connection error|not queryable|server closed the connection|database system is (starting up|in recovery)|Connection ended unexpectedly/i.test(String(e.message || e));
};

  return {
    _isTransientConnErr,
  };
};